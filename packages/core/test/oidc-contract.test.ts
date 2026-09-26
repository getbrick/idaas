import { describe, expect, expectTypeOf, it } from "vitest";
import {
  OIDC_CONSENT_GRANT_STATUSES,
  OIDC_ENDPOINT_SOURCES,
  OIDC_LOGOUT_TARGETS,
  OIDC_PROVIDER_CLIENT_AUTH_METHODS,
  OIDC_PROVIDER_CLIENT_KINDS,
} from "@getbrick/idaas-contracts";
import type {
  OidcConsentDecision,
  OidcConsentResolverV2,
  OidcLogoutCoordinator,
  OidcLogoutOperation,
  OidcProviderClientMetadata,
  OidcProviderEndpointResolver,
  OidcResolvedProvider,
} from "../src/index.js";

describe("OIDC frozen contracts", () => {
  it("keeps endpoint sources explicit", () => {
    expect(OIDC_ENDPOINT_SOURCES).toEqual(["discovery", "explicit"]);
  });

  it("keeps client and auth method unions closed", () => {
    expect(OIDC_PROVIDER_CLIENT_KINDS).toEqual(["web", "native", "mp_weixin", "webview"]);
    expect(OIDC_PROVIDER_CLIENT_AUTH_METHODS).toEqual([
      "none",
      "client_secret_basic",
      "client_secret_post",
      "private_key_jwt",
    ]);
  });

  it("keeps consent and logout state machines finite", () => {
    expect(OIDC_CONSENT_GRANT_STATUSES).toEqual(["pending", "active", "denied", "revoked", "expired"]);
    expect(OIDC_LOGOUT_TARGETS).toEqual([
      "op_session",
      "offline_grant",
      "better_auth",
      "bff_cookie",
      "native_session",
      "webview_ticket",
    ]);
  });

  it("keeps strict PKCE and discriminated consent types", () => {
    expectTypeOf<OidcProviderClientMetadata["requirePkce"]>().toEqualTypeOf<true>();
    expectTypeOf<Extract<OidcConsentDecision, { decision: "approved" }>["userGesture"]>().toEqualTypeOf<true>();
  });

  it("exposes narrow endpoint, consent, and logout ports", () => {
    expectTypeOf<OidcProviderEndpointResolver["resolve"]>().toBeFunction();
    expectTypeOf<OidcConsentResolverV2>().toBeFunction();
    expectTypeOf<OidcLogoutCoordinator["prepare"]>().toBeFunction();
    expectTypeOf<OidcLogoutCoordinator["complete"]>().toBeFunction();
  });

  it("does not expose credential fields in frozen public contracts", () => {
    const provider: OidcResolvedProvider = {
      contractVersion: 1,
      issuer: "https://id.example.test/oidc",
      source: "explicit",
      endpoints: {
        authorization: "https://id.example.test/oidc/auth",
        token: "https://id.example.test/oidc/token",
        userInfo: "https://id.example.test/oidc/me",
        jwks: "https://id.example.test/oidc/jwks",
      },
      allowedIdTokenAlgorithms: ["RS256"],
    };
    const client: OidcProviderClientMetadata = {
      clientId: "client-01",
      applicationType: "web",
      clientKind: "web",
      redirectUris: ["https://client.example.test/callback"],
      postLogoutRedirectUris: [],
      grantTypes: ["authorization_code"],
      responseTypes: ["code"],
      scopes: ["openid"],
      tokenEndpointAuthMethod: "none",
      requirePkce: true,
    };
    const logout: OidcLogoutOperation = {
      contractVersion: 1,
      operationId: "logout-01",
      tenantId: "tenant-01",
      clientId: "client-01",
      status: "pending",
      idempotencyKey: "logout-key-01",
      targets: ["op_session"],
      createdAt: "2026-01-01T00:00:00.000Z",
      updatedAt: "2026-01-01T00:00:00.000Z",
    };
    expect("clientSecret" in client).toBe(false);
    expect("accessToken" in provider).toBe(false);
    expect("idTokenHint" in logout).toBe(false);
  });
});
