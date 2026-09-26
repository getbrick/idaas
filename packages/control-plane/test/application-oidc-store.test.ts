import { describe, expect, it, vi } from "vitest";
import {
  ApplicationOidcClientStore,
  InMemoryApplicationRepository,
  InMemorySecretBindingRepository,
} from "../src/index.js";

describe("ApplicationOidcClientStore", () => {
  it("projects managed clients and resolves secrets only at runtime", async () => {
    const repository = new InMemoryApplicationRepository({
      applications: [{ id: "app-1", name: "Alpha", slug: "alpha", status: "active" }],
      clients: [{
        id: "record-1",
        applicationId: "app-1",
        clientId: "managed-client",
        status: "active",
        redirectUris: ["https://client.example.test/callback"],
        postLogoutRedirectUris: [],
        grantTypes: ["authorization_code", "refresh_token"],
        responseTypes: ["code"],
        scopes: ["openid", "offline_access"],
        tokenEndpointAuthMethod: "client_secret_post",
        secretRef: "vault://managed-client",
      }],
    });
    const store = new ApplicationOidcClientStore(repository, {
      resolveSecret: (reference) => reference === "vault://managed-client" ? "runtime-secret" : "",
    });
    await expect(store.find("managed-client")).resolves.toMatchObject({
      client_id: "managed-client",
      client_secret: "runtime-secret",
      redirect_uris: ["https://client.example.test/callback"],
      grant_types: ["authorization_code", "refresh_token"],
      scope: "openid offline_access",
    });
    await expect(store.find("missing")).resolves.toBeUndefined();
  });

  it("projects private_key_jwt metadata without resolving a shared secret", async () => {
    const repository = new InMemoryApplicationRepository({
      applications: [{ id: "app-1", name: "Native", slug: "native", status: "active", applicationType: "native" }],
      clients: [{
        id: "record-2",
        applicationId: "app-1",
        clientId: "native-jwt",
        status: "active",
        redirectUris: ["com.example.app:/oauth/callback"],
        grantTypes: ["authorization_code"],
        responseTypes: ["code"],
        scopes: ["openid"],
        tokenEndpointAuthMethod: "private_key_jwt",
        tokenEndpointAuthSigningAlg: "ES256",
        requirePkce: true,
        privateKeyRef: "vault://clients/native-jwt/private-key",
      }],
    });
    const store = new ApplicationOidcClientStore(repository, {
      resolveClientJwks: () => ({ keys: [{ kid: "native-key", kty: "EC", crv: "P-256", x: "x", y: "y" }] }),
    });
    await expect(store.find("native-jwt")).resolves.toMatchObject({
      client_id: "native-jwt",
      application_type: "native",
      token_endpoint_auth_method: "private_key_jwt",
      token_endpoint_auth_signing_alg: "ES256",
      require_pkce: true,
      jwks: { keys: [{ kid: "native-key" }] },
    });
    await expect(store.find("native-jwt")).resolves.not.toHaveProperty("client_secret");
  });

  it("uses private_key_jwt by default and prefers a configured jwks_uri over resolution", async () => {
    const repository = new InMemoryApplicationRepository({
      applications: [{ id: "app-1", name: "Alpha", slug: "alpha", status: "active" }],
      clients: [{
        id: "record-1",
        applicationId: "app-1",
        clientId: "managed-private",
        status: "active",
        redirectUris: ["https://client.example.test/callback"],
        grantTypes: ["authorization_code"],
        responseTypes: ["code"],
        scopes: ["openid"],
        privateKeyRef: "vault://managed-private/key",
      }],
    });
    const resolveClientJwks = vi.fn(async () => ({ keys: [{ kid: "key-1" }] }));
    const store = new ApplicationOidcClientStore(repository, { resolveClientJwks });
    await expect(store.find("managed-private")).resolves.toMatchObject({
      token_endpoint_auth_method: "private_key_jwt",
      jwks: { keys: [{ kid: "key-1" }] },
    });
    expect(resolveClientJwks).toHaveBeenCalledOnce();

    const uriRepository = new InMemoryApplicationRepository({
      applications: [{ id: "app-1", name: "Alpha", slug: "alpha", status: "active" }],
      clients: [{
        id: "record-2",
        applicationId: "app-1",
        clientId: "managed-uri",
        status: "active",
        redirectUris: ["https://client.example.test/callback"],
        grantTypes: ["authorization_code"],
        responseTypes: ["code"],
        scopes: ["openid"],
        tokenEndpointAuthMethod: "private_key_jwt",
        jwksUri: "https://client.example.test/jwks.json",
      }],
    });
    const uriResolver = vi.fn(async () => {
      throw new Error("must not resolve");
    });
    const uriStore = new ApplicationOidcClientStore(uriRepository, { resolveClientJwks: uriResolver });
    await expect(uriStore.find("managed-uri")).resolves.toMatchObject({
      jwks_uri: "https://client.example.test/jwks.json",
    });
    expect(uriResolver).not.toHaveBeenCalled();
  });

  it("resolves the active secret and retains a retiring secret during grace", async () => {
    const repository = new InMemoryApplicationRepository({
      applications: [{ id: "app-1", name: "Alpha", slug: "alpha", status: "active" }],
      clients: [{
        id: "record-1",
        applicationId: "app-1",
        clientId: "managed-client",
        status: "active",
        redirectUris: ["https://client.example.test/callback"],
        grantTypes: ["authorization_code"],
        responseTypes: ["code"],
        scopes: ["openid"],
        tokenEndpointAuthMethod: "client_secret_basic",
        secretRef: "vault://old",
      }],
    });
    const bindings = new InMemorySecretBindingRepository();
    const first = await bindings.create({
      subjectType: "application-client",
      subjectId: "record-1",
      purpose: "oidc-client-secret",
      secretRef: "vault://old",
      gracePeriodSeconds: 60,
    });
    const second = await bindings.rotate("application-client", "record-1", "oidc-client-secret", {
      secretRef: "vault://new",
      gracePeriodSeconds: 60,
    });
    const resolveSecret = vi.fn(async (reference: string) => reference === "vault://new" ? "new-secret" : "old-secret");
    const store = new ApplicationOidcClientStore(repository, { secretBindings: bindings, resolveSecret });
    await expect(store.find("managed-client")).resolves.toMatchObject({ client_secret: "new-secret" });
    expect(resolveSecret).toHaveBeenLastCalledWith("vault://new");

    await bindings.revoke(second.id, second.version);
    await expect(store.find("managed-client")).resolves.toMatchObject({ client_secret: "old-secret" });
    expect(resolveSecret).toHaveBeenLastCalledWith("vault://old");

    await bindings.revoke(first.id, first.version);
    await expect(store.find("managed-client")).rejects.toThrow(/binding/i);
  });

  it("fails closed for revoked metadata even when a stale secret reference remains", async () => {
    const repository = new InMemoryApplicationRepository({
      applications: [{ id: "app-1", name: "Alpha", slug: "alpha", status: "active" }],
      clients: [{
        id: "record-1",
        applicationId: "app-1",
        clientId: "managed-client",
        status: "active",
        redirectUris: ["https://client.example.test/callback"],
        grantTypes: ["authorization_code"],
        responseTypes: ["code"],
        scopes: ["openid"],
        tokenEndpointAuthMethod: "client_secret_basic",
        secretRef: "vault://stale",
        hasSecret: false,
        secretStatus: "revoked",
      }],
    });
    const resolveSecret = vi.fn(async () => "stale-secret");
    const store = new ApplicationOidcClientStore(repository, { resolveSecret });
    await expect(store.find("managed-client")).rejects.toThrow(/binding/i);
    expect(resolveSecret).not.toHaveBeenCalled();
  });
});
