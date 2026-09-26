import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { createHash, randomBytes } from "node:crypto";
import { describe, expect, it } from "vitest";
import { memoryAdapter } from "better-auth/adapters/memory";
import { SignJWT, exportJWK, generateKeyPair } from "jose";
import { buildTableMap, createIdaas, createOidcProviderEndpointResolver } from "../src/index.js";

interface StoredCode {
  challenge: string;
  nonce?: string;
  redirectUri: string;
  scope: string;
  subject: string;
}

function memoryDb() {
  const tables = buildTableMap();
  const data: Record<string, unknown[]> = {};
  for (const name of Object.values(tables)) data[name] = [];
  return memoryAdapter(data as never);
}

function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve) => {
    let body = "";
    req.on("data", (chunk) => (body += chunk));
    req.on("end", () => resolve(body));
  });
}

function cookieHeader(response: Response): string {
  return response.headers.getSetCookie().map((value) => value.split(";")[0]).join("; ");
}

type ClaimFailure = "expired" | "missing-exp" | "future-iat" | "missing-iat" | "bad-aud" | "bad-azp" | "bad-nonce";

async function runClaimFailureFlow(mode: ClaimFailure): Promise<void> {
  const { privateKey, publicKey } = await generateKeyPair("RS256");
  const publicJwk = await exportJWK(publicKey);
  const keyId = "rp-claim-test-key";
  publicJwk.kid = keyId;
  publicJwk.alg = "RS256";
  publicJwk.use = "sig";
  const codes = new Map<string, { challenge: string; nonce: string; redirectUri: string }>();
  let origin = "";
  const server = createServer(async (req, res) => {
    const url = new URL(req.url ?? "/", origin || "http://127.0.0.1");
    if (url.pathname === "/.well-known/openid-configuration") {
      json(res, {
        issuer: origin,
        authorization_endpoint: `${origin}/authorize`,
        token_endpoint: `${origin}/token`,
        userinfo_endpoint: `${origin}/userinfo`,
        jwks_uri: `${origin}/jwks`,
        id_token_signing_alg_values_supported: ["RS256"],
      });
      return;
    }
    if (url.pathname === "/jwks") {
      json(res, { keys: [publicJwk] });
      return;
    }
    if (url.pathname === "/authorize") {
      const code = randomBytes(24).toString("base64url");
      const redirectUri = url.searchParams.get("redirect_uri")!;
      codes.set(code, {
        challenge: url.searchParams.get("code_challenge") ?? "",
        nonce: url.searchParams.get("nonce") ?? "",
        redirectUri,
      });
      const location = new URL(redirectUri);
      location.searchParams.set("code", code);
      location.searchParams.set("state", url.searchParams.get("state") ?? "");
      res.statusCode = 302;
      res.setHeader("Location", location.toString());
      res.end();
      return;
    }
    if (url.pathname === "/token" && req.method === "POST") {
      const body = new URLSearchParams(await readBody(req));
      const stored = codes.get(body.get("code") ?? "");
      const verifier = body.get("code_verifier") ?? "";
      const challenge = createHash("sha256").update(verifier).digest("base64url");
      if (!stored || body.get("redirect_uri") !== stored.redirectUri || challenge !== stored.challenge) {
        json(res, { error: "invalid_grant" }, 400);
        return;
      }
      codes.delete(body.get("code")!);
      const claims: Record<string, unknown> = {
        sub: "external-user-1",
        nonce: mode === "bad-nonce" ? "wrong-nonce" : stored.nonce,
        email: "external@example.com",
        email_verified: true,
      };
      if (mode === "bad-azp") claims.azp = "other-client";
      const tokenBuilder = new SignJWT(claims)
        .setProtectedHeader({ alg: "RS256", kid: keyId })
        .setIssuer(origin)
        .setAudience(mode === "bad-aud" ? "other-client" : mode === "bad-azp" ? ["rp-client", "other-client"] : "rp-client");
      if (mode === "future-iat") {
        tokenBuilder.setIssuedAt(Math.floor(Date.now() / 1000) + 3600);
      } else if (mode !== "missing-iat") {
        tokenBuilder.setIssuedAt();
      }
      if (mode !== "missing-exp") {
        tokenBuilder.setExpirationTime(mode === "expired" ? "-1m" : "5m");
      }
      const idToken = await tokenBuilder.sign(privateKey);
      json(res, {
        access_token: randomBytes(24).toString("base64url"),
        token_type: "Bearer",
        expires_in: 300,
        id_token: idToken,
      });
      return;
    }
    if (url.pathname === "/userinfo") {
      json(res, { sub: "external-user-1", email: "external@example.com", email_verified: true });
      return;
    }
    res.statusCode = 404;
    res.end();
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("test server did not bind");
  origin = `http://127.0.0.1:${address.port}`;
  try {
    const auth = createIdaas({
      config: {
        appName: "RP Claim Validation",
        baseURL: "http://localhost:3000",
        trustedOrigins: ["http://localhost:3000"],
        oidc: {
          rp: {
            enabled: true,
            providers: [{
              providerId: "corp",
              issuer: origin,
              discoveryUrl: `${origin}/.well-known/openid-configuration`,
              clientId: "rp-client",
              clientSecret: "rp-secret",
              redirectURI: "http://localhost:3000/api/auth/callback/corp",
              scopes: ["openid", "profile", "email"],
            }],
          },
        },
      },
      database: memoryDb(),
    });
    const signIn = await auth.handler(new Request("http://localhost:3000/api/auth/sign-in/social", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        origin: "http://localhost:3000",
      },
      body: JSON.stringify({
        provider: "corp",
        callbackURL: "http://localhost:3000/done",
      }),
    }));
    expect(signIn.status).toBe(200);
    const signInBody = await signIn.json() as { url: string };
    const authorization = await fetch(signInBody.url, { redirect: "manual" });
    expect(authorization.status).toBe(302);
    const callback = await auth.handler(new Request(new URL(authorization.headers.get("location")!), {
      headers: { cookie: cookieHeader(signIn) },
    }));
    expect(callback.status).toBe(302);
    expect(new URL(callback.headers.get("location")!).searchParams.get("error")).toBeTruthy();
    await expect(auth.api.getSession({ headers: new Headers({ cookie: cookieHeader(callback) }) })).resolves.toBeNull();
  } finally {
    await new Promise<void>((resolve, reject) => {
      server.close((error) => (error ? reject(error) : resolve()));
    });
  }
}

describe("OIDC relying party callback", () => {
  it("exchanges a verified code and creates a local session", async () => {
    const { privateKey, publicKey } = await generateKeyPair("RS256");
    const publicJwk = await exportJWK(publicKey);
    const keyId = "rp-test-key";
    publicJwk.kid = keyId;
    publicJwk.alg = "RS256";
    publicJwk.use = "sig";
    const codes = new Map<string, StoredCode>();
    const accessTokens = new Map<string, { subject: string; email: string }>();
    let origin = "";
    const server = createServer(async (req, res) => {
      const url = new URL(req.url ?? "/", origin || "http://127.0.0.1");
      if (url.pathname === "/.well-known/openid-configuration") {
        json(res, {
          issuer: origin,
          authorization_endpoint: `${origin}/authorize`,
          token_endpoint: `${origin}/token`,
          userinfo_endpoint: `${origin}/userinfo`,
          jwks_uri: `${origin}/jwks`,
          id_token_signing_alg_values_supported: ["RS256"],
        });
        return;
      }
      if (url.pathname === "/jwks") {
        json(res, { keys: [publicJwk] });
        return;
      }
      if (url.pathname === "/authorize") {
        const code = randomBytes(24).toString("base64url");
        const redirectUri = url.searchParams.get("redirect_uri")!;
        codes.set(code, {
          challenge: url.searchParams.get("code_challenge") ?? "",
          nonce: url.searchParams.get("nonce") ?? undefined,
          redirectUri,
          scope: url.searchParams.get("scope") ?? "",
          subject: "external-user-1",
        });
        const location = new URL(redirectUri);
        location.searchParams.set("code", code);
        location.searchParams.set("state", url.searchParams.get("state") ?? "");
        res.statusCode = 302;
        res.setHeader("Location", location.toString());
        res.end();
        return;
      }
      if (url.pathname === "/token" && req.method === "POST") {
        const body = new URLSearchParams(await readBody(req));
        const code = body.get("code") ?? "";
        const stored = codes.get(code);
        if (!stored || body.get("redirect_uri") !== stored.redirectUri) {
          json(res, { error: "invalid_grant" }, 400);
          return;
        }
        const verifier = body.get("code_verifier") ?? "";
        const challenge = createHash("sha256").update(verifier).digest("base64url");
        if (challenge !== stored.challenge) {
          json(res, { error: "invalid_grant" }, 400);
          return;
        }
        codes.delete(code);
        const accessToken = randomBytes(24).toString("base64url");
        accessTokens.set(accessToken, { subject: stored.subject, email: "external@example.com" });
        const idToken = await new SignJWT({
          sub: stored.subject,
          nonce: stored.nonce,
          email: "external@example.com",
          email_verified: true,
        })
          .setProtectedHeader({ alg: "RS256", kid: keyId })
          .setIssuer(origin)
          .setAudience("rp-client")
          .setIssuedAt()
          .setExpirationTime("5m")
          .sign(privateKey);
        json(res, {
          access_token: accessToken,
          token_type: "Bearer",
          expires_in: 300,
          id_token: idToken,
        });
        return;
      }
      if (url.pathname === "/userinfo") {
        const token = req.headers.authorization?.replace(/^Bearer\s+/u, "") ?? "";
        const user = accessTokens.get(token);
        if (!user) {
          json(res, { error: "invalid_token" }, 401);
          return;
        }
        json(res, { sub: user.subject, email: user.email, email_verified: true });
        return;
      }
      res.statusCode = 404;
      res.end();
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const address = server.address();
    if (!address || typeof address === "string") throw new Error("test server did not bind");
    origin = `http://127.0.0.1:${address.port}`;

    const auth = createIdaas({
      config: {
        appName: "RP Flow",
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
                clientSecret: "rp-secret",
                redirectURI: "http://localhost:3000/api/auth/callback/corp",
                scopes: ["openid", "profile", "email"],
              },
            ],
          },
        },
      },
      database: memoryDb(),
    });

    const signIn = await auth.handler(new Request("http://localhost:3000/api/auth/sign-in/social", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        origin: "http://localhost:3000",
      },
      body: JSON.stringify({
        provider: "corp",
        callbackURL: "http://localhost:3000/done",
      }),
    }));
    expect(signIn.status).toBe(200);
    const signInBody = await signIn.json() as { url: string };
    const authorization = await fetch(signInBody.url, { redirect: "manual" });
    expect(authorization.status).toBe(302);
    const callbackUrl = new URL(authorization.headers.get("location")!);
    const callback = await auth.handler(new Request(callbackUrl, {
      headers: { cookie: cookieHeader(signIn) },
    }));
    expect(callback.status).toBe(302);
    const cookies = cookieHeader(callback);
    expect(cookies).toContain("getbrick");
    const session = await auth.api.getSession({ headers: new Headers({ cookie: cookies }) });
    expect(session?.user.email).toBe("external@example.com");

    await new Promise<void>((resolve, reject) => {
      server.close((error) => (error ? reject(error) : resolve()));
    });
  });

  it("rejects invalid ID token lifecycle and authorized-party claims", async () => {
    for (const mode of ["expired", "missing-exp", "future-iat", "missing-iat", "bad-aud", "bad-azp", "bad-nonce"] as const) {
      await runClaimFailureFlow(mode);
    }
  });

  it("starts production discovery-only without an explicit userInfo endpoint", async () => {
    let resolverInput: { userInfoUrl?: string; discoveryUrl?: string } | undefined;
    const auth = createIdaas({
      config: {
        profile: "production",
        appName: "RP Production Discovery",
        baseURL: "https://app.example.test",
        secret: "s".repeat(32),
        trustedOrigins: ["https://app.example.test"],
        registration: { publicSignUp: false },
        email: { requireEmailVerification: true },
        oidc: {
          rp: {
            enabled: true,
            providers: [{
              providerId: "corp",
              issuer: "https://issuer.example.test",
              discoveryUrl: "https://issuer.example.test/.well-known/openid-configuration",
              clientId: "rp-client",
              clientSecret: "rp-secret",
              redirectURI: "https://app.example.test/api/auth/callback/corp",
            }],
          },
        },
      },
      database: memoryDb(),
      emailSender: async () => {},
      oidcProviderEndpointResolver: {
        resolve: async (input) => {
          resolverInput = input;
          return {
            contractVersion: 1,
            issuer: "https://issuer.example.test",
            source: "discovery",
            endpoints: {
              authorization: "https://issuer.example.test/authorize",
              token: "https://issuer.example.test/token",
              userInfo: "https://issuer.example.test/userinfo",
              jwks: "https://issuer.example.test/jwks",
            },
            allowedIdTokenAlgorithms: ["RS256"],
          };
        },
      },
    });
    await auth.api.signInSocial({
      body: {
        provider: "corp",
        callbackURL: "https://app.example.test/done",
      },
    });
    expect(auth.options.plugins?.some((plugin) => plugin.id === "generic-oauth")).toBe(true);
    expect(resolverInput?.discoveryUrl).toBe("https://issuer.example.test/.well-known/openid-configuration");
    expect(resolverInput?.userInfoUrl).toBeUndefined();
  });

  it("resolves explicit full endpoints with jwks and allowed algorithms", async () => {
    let resolverInput: {
      discoveryUrl?: string;
      jwksUri?: string;
      allowedIdTokenAlgorithms?: readonly string[];
    } | undefined;
    const defaultResolver = createOidcProviderEndpointResolver();
    const auth = createIdaas({
      config: {
        appName: "RP Explicit",
        baseURL: "http://localhost:3000",
        trustedOrigins: ["http://localhost:3000"],
        oidc: {
          rp: {
            enabled: true,
            providers: [{
              providerId: "corp",
              issuer: "https://issuer.example.test",
              authorizationUrl: "https://issuer.example.test/authorize",
              tokenUrl: "https://issuer.example.test/token",
              userInfoUrl: "https://issuer.example.test/userinfo",
              jwksUri: "https://issuer.example.test/jwks",
              allowedIdTokenAlgorithms: ["ES256"],
              endSessionEndpoint: "https://issuer.example.test/logout",
              clientId: "rp-client",
              clientSecret: "rp-secret",
              redirectURI: "http://localhost:3000/api/auth/callback/corp",
            }],
          },
        },
      },
      database: memoryDb(),
      oidcProviderEndpointResolver: {
        resolve: async (input) => {
          resolverInput = input;
          return defaultResolver.resolve(input);
        },
      },
    });
    await auth.api.signInSocial({
      body: {
        provider: "corp",
        callbackURL: "http://localhost:3000/done",
      },
    });
    expect(resolverInput).toMatchObject({
      jwksUri: "https://issuer.example.test/jwks",
      allowedIdTokenAlgorithms: ["ES256"],
    });
    expect(resolverInput?.discoveryUrl).toBeUndefined();
  });

  it("rejects direct social sign-in token replay", async () => {
    const auth = createIdaas({
      config: {
        appName: "RP Direct Token",
        baseURL: "http://localhost:3000",
        trustedOrigins: ["http://localhost:3000"],
        oidc: {
          rp: {
            enabled: true,
            providers: [{
              providerId: "corp",
              issuer: "https://issuer.example.test",
              discoveryUrl: "https://issuer.example.test/.well-known/openid-configuration",
              clientId: "rp-client",
              clientSecret: "rp-secret",
              redirectURI: "http://localhost:3000/api/auth/callback/corp",
            }],
          },
        },
      },
      database: memoryDb(),
      oidcProviderEndpointResolver: {
        resolve: async () => ({
          contractVersion: 1,
          issuer: "https://issuer.example.test",
          source: "discovery",
          endpoints: {
            authorization: "https://issuer.example.test/authorize",
            token: "https://issuer.example.test/token",
            userInfo: "https://issuer.example.test/userinfo",
            jwks: "https://issuer.example.test/jwks",
          },
          allowedIdTokenAlgorithms: ["RS256"],
        }),
      },
    });
    const directToken = {
      token: "eyJhbGciOiJSUzI1NiJ9.untrusted.signature",
      accessToken: "access-token",
    };
    for (let attempt = 0; attempt < 2; attempt += 1) {
      await expect(auth.api.signInSocial({
        body: {
          provider: "corp",
          callbackURL: "http://localhost:3000/done",
          idToken: directToken,
        },
      })).rejects.toThrow(/not supported/i);
    }
  });
});

function json(res: ServerResponse, value: unknown, status = 200): void {
  res.statusCode = status;
  res.setHeader("Content-Type", "application/json");
  res.end(JSON.stringify(value));
}
