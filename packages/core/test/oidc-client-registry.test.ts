import { describe, expect, it, vi } from "vitest";
import { generateKeyPair, exportJWK } from "jose";
import type { AdapterFactory } from "oidc-provider";
import {
  OIDC_CLIENT_AUTH_SIGNING_ALGORITHMS,
  createDynamicOidcClientAdapter,
  normalizeOidcClaimPolicy,
  normalizeOidcJwksUri,
  projectOidcClientJwks,
  resolveOidcClaimPolicy,
  toDynamicOidcClientPayload,
} from "../src/index.js";

function baseAdapter(): AdapterFactory {
  return () => ({
    async find() {
      return undefined;
    },
    async upsert() {},
    async destroy() {},
  }) as never;
}

async function publicJwks(algorithm: "RS256" | "PS256" | "ES256" | "EdDSA", kid: string) {
  const { publicKey } = await generateKeyPair(algorithm);
  const jwk = await exportJWK(publicKey);
  return { keys: [{ ...jwk, kid, use: "sig" }] };
}

describe("dynamic OIDC client registry", () => {
  it("projects an active managed client for oidc-provider Client.find", async () => {
    const adapter = createDynamicOidcClientAdapter(baseAdapter(), {
      find: async (clientId) => clientId === "managed-client"
        ? {
            client_id: "managed-client",
            client_secret: "server-only-secret",
            redirect_uris: ["https://client.example.test/callback"],
            post_logout_redirect_uris: ["https://client.example.test/logout"],
            grant_types: ["authorization_code", "refresh_token"],
            response_types: ["code"],
            scope: "openid profile email offline_access",
            token_endpoint_auth_method: "client_secret_post",
            status: "active",
          }
        : undefined,
    });
    const payload = await adapter("Client").find("managed-client");
    expect(payload).toMatchObject({
      client_id: "managed-client",
      redirect_uris: ["https://client.example.test/callback"],
      grant_types: ["authorization_code", "refresh_token"],
      scope: "openid profile email offline_access",
    });
    expect(payload?.client_secret).toBe("server-only-secret");
    await expect(adapter("Client").find("missing")).resolves.toBeUndefined();
  });

  it("preserves prototype adapter methods for non-lookup operations", async () => {
    class PrototypeAdapter {
      readonly writes: string[] = [];
      async upsert(id: string) {
        this.writes.push(id);
      }
      async destroy() {}
    }
    const prototypeAdapter = new PrototypeAdapter();
    const adapter = createDynamicOidcClientAdapter(
      (() => prototypeAdapter) as unknown as AdapterFactory,
      { find: async () => undefined },
    );
    await adapter("Client").upsert("client-1", {}, 0);
    expect(prototypeAdapter.writes).toEqual(["client-1"]);
  });

  it("does not expose managed client store failures", async () => {
    const adapter = createDynamicOidcClientAdapter(baseAdapter(), {
      find: async () => {
        throw new Error("vault secret value");
      },
    });
    await expect(adapter("Client").find("client-1")).rejects.toThrow(/lookup failed/i);
    await expect(adapter("Client").find("client-1")).rejects.not.toThrow(/vault secret value/i);
  });

  it("projects all supported signing algorithms with matching key types", async () => {
    for (const algorithm of OIDC_CLIENT_AUTH_SIGNING_ALGORITHMS) {
      const jwks = projectOidcClientJwks(await publicJwks(algorithm, `key-${algorithm}`), algorithm);
      const payload = toDynamicOidcClientPayload({
        client_id: `client-${algorithm}`,
        application_type: "web",
        redirect_uris: ["https://client.example.test/callback"],
        grant_types: ["authorization_code"],
        response_types: ["code"],
        scope: "openid",
        token_endpoint_auth_method: "private_key_jwt",
        token_endpoint_auth_signing_alg: algorithm,
        jwks,
      });
      expect(payload).toMatchObject({
        token_endpoint_auth_signing_alg: algorithm,
        jwks: { keys: [{ alg: algorithm }] },
      });
    }
  });

  it("gives static clients priority over managed lookup", async () => {
    const find = vi.fn(async () => undefined);
    const adapter = createDynamicOidcClientAdapter(
      baseAdapter(),
      { find },
      { staticClientIds: ["static-client"] },
    );
    await expect(adapter("Client").find("static-client")).resolves.toBeUndefined();
    expect(find).not.toHaveBeenCalled();
  });

  it("validates managed metadata before resolving external keys", async () => {
    const resolveClientJwks = vi.fn(async () => ({ keys: [] }));
    const adapter = createDynamicOidcClientAdapter(baseAdapter(), {
      find: async () => ({
        client_id: "invalid-native",
        application_type: "native",
        redirect_uris: ["com.example.app:/oauth/callback"],
        grant_types: ["authorization_code"],
        response_types: ["code"],
        scope: "openid",
        token_endpoint_auth_method: "private_key_jwt",
      }),
    }, { resolveClientJwks });
    await expect(adapter("Client").find("invalid-native")).rejects.toThrow(/redirect URI/i);
    expect(resolveClientJwks).not.toHaveBeenCalled();
  });

  it("rejects unsupported managed application types, algorithms and native redirects", () => {
    expect(() => toDynamicOidcClientPayload({
      client_id: "bad-type",
      application_type: "mobile" as never,
      redirect_uris: ["https://client.example.test/callback"],
      grant_types: ["authorization_code"],
      response_types: ["code"],
      scope: "openid",
    })).toThrow(/application type/i);
    expect(() => toDynamicOidcClientPayload({
      client_id: "bad-alg",
      redirect_uris: ["https://client.example.test/callback"],
      grant_types: ["authorization_code"],
      response_types: ["code"],
      scope: "openid",
      token_endpoint_auth_method: "private_key_jwt",
      token_endpoint_auth_signing_alg: "HS256",
      jwks: { keys: [] },
    })).toThrow(/signing algorithm/i);
    expect(() => toDynamicOidcClientPayload({
      client_id: "bad-native",
      application_type: "native",
      redirect_uris: ["com.example.app:/oauth/callback"],
      grant_types: ["authorization_code"],
      response_types: ["code"],
      scope: "openid",
      token_endpoint_auth_method: "private_key_jwt",
      jwks_uri: "https://client.example.test/jwks.json",
    })).toThrow(/redirect URI/i);
  });

  it("resolves external JWKS for the default private_key_jwt method", async () => {
    const resolveClientJwks = vi.fn(async () => await publicJwks("ES256", "default-key"));
    const adapter = createDynamicOidcClientAdapter(baseAdapter(), {
      find: async (clientId) => clientId === "default-private"
        ? {
            client_id: "default-private",
            redirect_uris: ["https://client.example.test/callback"],
            grant_types: ["authorization_code"],
            response_types: ["code"],
            scope: "openid",
            token_endpoint_auth_signing_alg: "ES256",
          }
        : undefined,
    }, { resolveClientJwks });
    const payload = await adapter("Client").find("default-private");
    expect(payload).toMatchObject({
      token_endpoint_auth_method: "private_key_jwt",
      token_endpoint_auth_signing_alg: "ES256",
      jwks: { keys: [{ kid: "default-key", alg: "ES256" }] },
    });
    expect(resolveClientJwks).toHaveBeenCalledWith("default-private");
  });

  it("does not call a JWKS resolver when a validated jwks_uri is configured", async () => {
    const resolveClientJwks = vi.fn(async () => {
      throw new Error("resolver must not be called");
    });
    const adapter = createDynamicOidcClientAdapter(baseAdapter(), {
      find: async (clientId) => clientId === "uri-private"
        ? {
            client_id: "uri-private",
            redirect_uris: ["https://client.example.test/callback"],
            grant_types: ["authorization_code"],
            response_types: ["code"],
            scope: "openid",
            token_endpoint_auth_method: "private_key_jwt",
            jwks_uri: "https://client.example.test/jwks.json",
          }
        : undefined,
    }, { resolveClientJwks });
    await expect(adapter("Client").find("uri-private")).resolves.toMatchObject({
      jwks_uri: "https://client.example.test/jwks.json",
    });
    expect(resolveClientJwks).not.toHaveBeenCalled();
  });

  it("rejects production remote JWKS by default and blocks unsafe destinations", async () => {
    expect(() => normalizeOidcJwksUri("https://client.example.test/jwks", false, {
      profile: "production",
    })).toThrow(/production.*jwks_uri.*disabled/i);

    const adapter = createDynamicOidcClientAdapter(baseAdapter(), {
      find: async (clientId) => clientId === "remote-client"
        ? {
            client_id: "remote-client",
            redirect_uris: ["https://client.example.test/callback"],
            grant_types: ["authorization_code"],
            response_types: ["code"],
            scope: "openid",
            token_endpoint_auth_method: "private_key_jwt",
            jwks_uri: "https://client.example.test/jwks",
          }
        : undefined,
    }, { profile: "production" });
    await expect(adapter("Client").find("remote-client")).rejects.toThrow(/production.*jwks_uri.*disabled/i);

    const policy = {
      profile: "development" as const,
      allowRemoteJwksUri: true,
      trustedJwksOrigins: ["https://client.example.test"],
    };
    for (const uri of [
      "https://127.0.0.1/jwks",
      "https://10.0.0.1/jwks",
      "https://169.254.169.254/latest/meta-data",
      "https://[::1]/jwks",
      "https://[fc00::1]/jwks",
      "https://[::ffff:127.0.0.1]/jwks",
      "https://metadata.google.internal/jwks",
      "https://user:password@client.example.test/jwks",
      "https://client.example.test/userinfo",
      "http://client.example.test/jwks",
    ]) {
      expect(() => normalizeOidcJwksUri(uri, false, policy)).toThrow(/jwks_uri/i);
    }
  });

  it("allows an explicitly trusted development JWKS origin and canonicalizes the URI", () => {
    expect(normalizeOidcJwksUri("https://CLIENT.example.test:443/a/../jwks?version=2", false, {
      profile: "development",
      allowRemoteJwksUri: true,
      trustedJwksOrigins: ["https://client.example.test"],
    })).toBe("https://client.example.test/jwks?version=2");
    expect(() => normalizeOidcJwksUri("https://client.example.test/jwks", false, {
      profile: "development",
      allowRemoteJwksUri: true,
    })).toThrow(/trusted.*allowlist/i);
  });

  it("does not expose disabled static clients through a dynamic adapter", async () => {
    const find = vi.fn(async () => undefined);
    const adapter = createDynamicOidcClientAdapter(baseAdapter(), { find }, {
      staticClients: [{
        client_id: "disabled-static",
        status: "disabled",
        redirect_uris: ["https://client.example.test/callback"],
        grant_types: ["authorization_code"],
        response_types: ["code"],
        scope: "openid",
        token_endpoint_auth_method: "none",
      }],
    });
    await expect(adapter("Client").find("disabled-static")).resolves.toBeUndefined();
    expect(find).not.toHaveBeenCalled();
  });

  it("binds claim definitions to the registered client before exposing them", () => {
    const policy = normalizeOidcClaimPolicy({
      definitions: [{
        name: "tenant_role",
        scopes: ["profile"],
        clients: ["client-a"],
        source: "membership",
        required: false,
        sensitive: true,
        version: "1",
      }],
    });
    expect(resolveOidcClaimPolicy(policy, {
      requestedScopes: ["profile"],
      requestedClaims: ["tenant_role"],
      clientId: "client-a",
    }).allowedClaims).toEqual(["tenant_role"]);
    expect(resolveOidcClaimPolicy(policy, {
      requestedScopes: ["profile"],
      requestedClaims: ["tenant_role"],
      clientId: "client-b",
    }).allowedClaims).toEqual([]);
  });
});
