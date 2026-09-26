import { createServer } from "node:http";
import { describe, expect, it } from "vitest";
import { memoryAdapter } from "better-auth/adapters/memory";
import { buildTableMap, createIdaas, defineIdaasConfig, validateIdaasConfig } from "../src/index.js";

function memoryDb() {
  const tables = buildTableMap();
  const data: Record<string, unknown[]> = {};
  for (const name of Object.values(tables)) data[name] = [];
  return memoryAdapter(data as never);
}

describe("OIDC relying party", () => {
  it("registers strict generic OAuth providers and protects OAuth state", async () => {
    const server = createServer((req, res) => {
      if (req.url === "/.well-known/openid-configuration") {
        const origin = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
        res.setHeader("Content-Type", "application/json");
        res.end(JSON.stringify({
          issuer: origin,
          authorization_endpoint: `${origin}/authorize`,
          token_endpoint: `${origin}/token`,
          userinfo_endpoint: `${origin}/userinfo`,
          jwks_uri: `${origin}/jwks`,
        }));
        return;
      }
      res.statusCode = 404;
      res.end();
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const origin = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
    const config = defineIdaasConfig({
      appName: "RP Test",
      baseURL: "http://localhost:3000",
      trustedOrigins: ["http://localhost:3000"],
      oidc: {
        rp: {
          enabled: true,
          providers: [
            {
              providerId: "corp",
              issuer: origin,
              discoveryUrl: `${origin}/.well-known/openid-configuration`,
              clientId: "rp-client",
              redirectURI: "http://localhost:3000/api/auth/callback/corp",
              scopes: ["openid", "profile", "email"],
            },
          ],
        },
      },
    });
    const auth = createIdaas({
      config,
      database: memoryDb(),
      oidcRpClientSecrets: { corp: "rp-secret" },
      extraOptions: {
        account: {
          encryptOAuthTokens: false,
          skipStateCookieCheck: true,
        },
      },
    });
    expect(auth.options.account?.encryptOAuthTokens).toBe(true);
    expect(auth.options.account?.skipStateCookieCheck).toBe(false);
    expect(auth.options.account?.storeStateStrategy).toBe("database");
    expect(auth.options.account?.accountLinking?.disableImplicitLinking).toBe(true);
    expect(auth.options.plugins?.some((plugin) => plugin.id === "generic-oauth")).toBe(true);

    const result = await auth.api.signInSocial({
      body: {
        provider: "corp",
        callbackURL: "http://localhost:3000/callback",
      },
    });
    expect(result.url).toBeDefined();
    const authorizationUrl = new URL(result.url!);
    expect(authorizationUrl.pathname).toBe("/authorize");
    expect(authorizationUrl.searchParams.get("client_id")).toBe("rp-client");
    expect(authorizationUrl.searchParams.get("code_challenge_method")).toBe("S256");
    expect(authorizationUrl.searchParams.get("scope")).toBe("openid profile email");

    await new Promise<void>((resolve, reject) => {
      server.close((error) => (error ? reject(error) : resolve()));
    });
  });

  it("requires a pinned issuer and explicit userinfo endpoint for production RP", () => {
    const base = {
      profile: "production",
      appName: "RP Production",
      baseURL: "https://auth.example.test",
      secret: "s".repeat(32),
      trustedOrigins: ["https://app.example.test"],
      registration: { publicSignUp: false },
      email: { requireEmailVerification: true },
      oidc: {
        rp: {
          enabled: true,
          providers: [{
            providerId: "corp",
            discoveryUrl: "https://issuer.example.test/.well-known/openid-configuration",
            clientId: "client",
            redirectURI: "https://app.example.test/callback",
          }],
        },
      },
    } as Record<string, unknown>;
    expect(() => validateIdaasConfig(defineIdaasConfig(base as never))).toThrow(/issuer/i);
    const withIssuer = {
      ...base,
      oidc: {
        rp: {
          enabled: true,
          providers: [{
            providerId: "corp",
            issuer: "https://issuer.example.test",
            discoveryUrl: "https://issuer.example.test/.well-known/openid-configuration",
            clientId: "client",
            redirectURI: "https://app.example.test/callback",
          }],
        },
      },
    } as Record<string, unknown>;
    expect(() => validateIdaasConfig(defineIdaasConfig(withIssuer as never))).toThrow(/userInfoUrl/i);
    const withMismatchedDiscovery = {
      ...withIssuer,
      oidc: {
        rp: {
          enabled: true,
          providers: [{
            providerId: "corp",
            issuer: "https://issuer.example.test",
            discoveryUrl: "https://other.example.test/.well-known/openid-configuration",
            userInfoUrl: "https://issuer.example.test/userinfo",
            clientId: "client",
            redirectURI: "https://app.example.test/callback",
          }],
        },
      },
    } as Record<string, unknown>;
    expect(() => validateIdaasConfig(defineIdaasConfig(withMismatchedDiscovery as never))).toThrow(/issuer origin/i);
  });

  it("rejects duplicate OIDC providers and disabled PKCE", () => {
    expect(() =>
      createIdaas({
        config: {
          oidc: {
            rp: {
              enabled: true,
              providers: [
                {
                  providerId: "corp",
                  issuer: "https://issuer.example.com",
                  discoveryUrl: "https://issuer.example.com/.well-known/openid-configuration",
                  clientId: "one",
                  redirectURI: "https://app.example.com/callback",
                },
                {
                  providerId: "corp",
                  issuer: "https://issuer.example.com",
                  discoveryUrl: "https://issuer.example.com/.well-known/openid-configuration",
                  clientId: "two",
                  redirectURI: "https://app.example.com/callback",
                },
              ],
            },
          },
        },
        database: memoryDb(),
      }),
    ).toThrow(/duplicate.*providerId/i);
    expect(() =>
      defineIdaasConfig({
        oidc: {
          rp: {
            enabled: true,
            providers: [
              {
                providerId: "corp",
                issuer: "https://issuer.example.com",
                discoveryUrl: "https://issuer.example.com/.well-known/openid-configuration",
                clientId: "one",
                redirectURI: "https://app.example.com/callback",
                pkce: false as never,
              },
            ],
          },
        },
      }),
    ).toThrow();
  });

  it("rejects a client secret on a public RP provider", () => {
    expect(() => defineIdaasConfig({
      oidc: {
        rp: {
          enabled: true,
          providers: [{
            providerId: "public",
            issuer: "https://issuer.example.com",
            clientId: "public-client",
            clientSecret: "must-not-be-used",
            tokenEndpointAuth: "none",
            redirectURI: "https://app.example.com/callback",
          }],
        },
      },
    })).toThrow(/must not configure a client secret/i);
  });

  it("requires a client secret at runtime when the provider uses confidential auth", () => {
    expect(() =>
      createIdaas({
        config: {
          oidc: {
            rp: {
              enabled: true,
              providers: [
                {
                  providerId: "corp",
                  issuer: "https://issuer.example.com",
                  discoveryUrl: "https://issuer.example.com/.well-known/openid-configuration",
                  clientId: "client",
                  redirectURI: "https://app.example.com/api/auth/callback/corp",
                },
              ],
            },
          },
        },
        database: memoryDb(),
      }),
    ).toThrow(/client secret/i);
  });
});
