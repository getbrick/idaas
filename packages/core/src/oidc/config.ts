import { z } from "zod";
import {
  assertOidcClientRedirectPolicy,
  parseOidcRedirectUri,
  type OidcApplicationType,
  type OidcRedirectPolicyOptions,
} from "./redirect-policy.js";
import { validateOidcClientJwks } from "./client-jwks.js";

const oidcScopeSchema = z.string().regex(/^[\u0021\u0023-\u005B\u005D-\u007E]+$/u);

const oidcClientIdSchema = z.string().min(1).max(512).regex(/^[^\u0000-\u001F\u007F]+$/u);

const oidcPathSchema = z
  .string()
  .min(1)
  .max(256)
  .regex(/^\/[A-Za-z0-9/_-]*$/u)
  .refine((value) => !value.includes("//") && !value.split("/").includes(".."), {
    message: "must be a safe absolute path",
  });

const oidcUrlSchema = z.string().url().superRefine((value, context) => {
  if (!isSafeOidcUrl(value, false)) {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      message: "must be an absolute HTTP(S) URL without credentials, query, or fragment",
    });
  }
});

const oidcJwksUriSchema = z.string().min(1).max(2048).superRefine((value, context) => {
  if (!isSafeOidcUrl(value, true)) {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      message: "must be an absolute HTTP(S) URL without credentials or fragment",
    });
  }
});

const oidcOpRedirectUriSchema = z.string().min(1).max(2048).superRefine((value, context) => {
  let parsed: URL | undefined;
  try {
    parsed = new URL(value);
  } catch {
    parsed = undefined;
  }
  if (
     parsed === undefined ||
     parseOidcRedirectUri(value) === undefined ||
     parsed.username !== "" ||
    parsed.password !== "" ||
    parsed.hash !== "" ||
     /[\u0000-\u001F\u007F\s]/u.test(value) ||
     value.includes("\\")
  ) {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      message: "must be an absolute redirect URI without credentials or fragment",
    });
  }
});

const oidcRpRedirectUriSchema = z.string().min(1).max(2048).superRefine((value, context) => {
  if (!isSafeOidcUrl(value, true) || /\s/u.test(value)) {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      message: "must be an absolute HTTP(S) URL without credentials or fragment",
    });
  }
});

const oidcClientJwksSchema = z.record(z.string(), z.unknown()).superRefine((value, context) => {
  try {
    validateOidcClientJwks(value);
  } catch {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      message: "must be a public-key JWKS with unique key IDs",
    });
  }
});

const oidcClientAuthSigningAlgorithmSchema = z.enum(["RS256", "PS256", "ES256", "EdDSA"]);

const oidcRpPkceSchema = z.union([
  z.literal(true),
  z.object({
    required: z.literal(true),
    method: z.literal("S256").default("S256"),
  }),
]);

const oidcRpRedirectPolicySchema = z.object({
  mode: z.literal("exact"),
  exact: z.literal(true).default(true),
});

const oidcRpConsentSchema = z.union([
  z.literal("explicit"),
  z.object({
    required: z.literal(true),
    mode: z.literal("explicit").default("explicit"),
    scopes: z.array(oidcScopeSchema).optional(),
    sensitiveScopes: z.array(oidcScopeSchema).optional(),
  }),
]);

export const oidcRpProviderSchema = z.object({
  providerId: z.string().regex(/^[a-z][a-z0-9_-]{1,63}$/u),
  clientType: z.literal("web").default("web"),
  clientKind: z.literal("web").default("web"),
  name: z.string().min(1).max(100).optional(),
  issuer: oidcUrlSchema.optional(),
  discoveryUrl: oidcUrlSchema.optional(),
  authorizationUrl: oidcUrlSchema.optional(),
  tokenUrl: oidcUrlSchema.optional(),
  userInfoUrl: oidcUrlSchema.optional(),
  endSessionEndpoint: oidcUrlSchema.optional(),
  clientId: oidcClientIdSchema,
  clientSecret: z.string().min(1).max(4096).optional(),
  redirectURI: oidcRpRedirectUriSchema,
  redirectUriPolicy: z.literal("exact").default("exact"),
  redirectPolicy: oidcRpRedirectPolicySchema.default({ mode: "exact", exact: true }),
  postLogoutRedirectURI: oidcRpRedirectUriSchema.optional(),
  scopes: z.array(oidcScopeSchema).min(1).default(["openid", "profile", "email"]),
  responseType: z.literal("code").default("code"),
  pkce: oidcRpPkceSchema.default(true),
  pkceMethod: z.literal("S256").default("S256"),
  consent: oidcRpConsentSchema.default("explicit"),
  consentRequired: z.literal(true).default(true),
  requireExplicitConsent: z.literal(true).default(true),
  requireIdTokenVerification: z.literal(true).default(true),
  tokenEndpointAuth: z
    .enum(["client_secret_basic", "client_secret_post", "none"])
    .default("client_secret_basic"),
  requireEmailVerification: z.boolean().default(false),
   disableImplicitSignUp: z.boolean().default(false),
   disableSignUp: z.boolean().default(false),
 }).superRefine((provider, context) => {
   if (provider.tokenEndpointAuth === "none" && provider.clientSecret !== undefined) {
     context.addIssue({
       code: z.ZodIssueCode.custom,
       message: "must not configure a client secret with tokenEndpointAuth=none",
     });
   }
   if (provider.clientSecret !== undefined && /[\u0000-\u001f\u007f]/u.test(provider.clientSecret)) {
     context.addIssue({
       code: z.ZodIssueCode.custom,
       message: "client secret is invalid",
     });
   }
 });

export const oidcOpClientSchema = z.object({
  clientId: oidcClientIdSchema,
  clientName: z.string().min(1).max(200).optional(),
  clientSecret: z.string().min(1).max(4096).optional(),
  applicationType: z.enum(["web", "native", "webview"]).default("web"),
  redirectUris: z.array(oidcOpRedirectUriSchema).min(1),
  postLogoutRedirectUris: z.array(oidcOpRedirectUriSchema).default([]),
  jwksUri: oidcJwksUriSchema.optional(),
  jwks: oidcClientJwksSchema.optional(),
  clientJwks: oidcClientJwksSchema.optional(),
  grantTypes: z
    .array(z.enum(["authorization_code", "refresh_token"]))
    .default(["authorization_code"]),
  responseTypes: z.array(z.literal("code")).default(["code"]),
  scopes: z.array(oidcScopeSchema).min(1).default(["openid", "profile", "email"]),
  tokenEndpointAuthMethod: z
    .enum(["client_secret_basic", "client_secret_post", "private_key_jwt", "none"])
    .default("client_secret_basic"),
  tokenEndpointAuthSigningAlg: oidcClientAuthSigningAlgorithmSchema.default("RS256"),
  requirePkce: z.literal(true).default(true),
 }).superRefine((client, context) => {
   if (client.clientSecret !== undefined && /[\u0000-\u001f\u007f]/u.test(client.clientSecret)) {
     context.addIssue({
       code: z.ZodIssueCode.custom,
       message: "client secret is invalid",
     });
   }
   if (client.tokenEndpointAuthMethod === "private_key_jwt" && client.clientSecret !== undefined) {
     context.addIssue({
       code: z.ZodIssueCode.custom,
       message: "private_key_jwt clients must not configure a client secret",
     });
   }
   if (client.tokenEndpointAuthMethod === "none" && client.clientSecret !== undefined) {
     context.addIssue({
       code: z.ZodIssueCode.custom,
       message: "public clients must not configure a client secret",
     });
   }
   try {
    assertOidcClientRedirectPolicy({
      applicationType: client.applicationType,
      tokenEndpointAuthMethod: client.tokenEndpointAuthMethod,
      requirePkce: client.requirePkce,
      redirectUris: client.redirectUris,
      postLogoutRedirectUris: client.postLogoutRedirectUris,
    }, { allowInsecureHttp: true });
  } catch {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      message: "redirect URIs violate the OIDC redirect policy",
    });
  }
});

const oidcConsentPolicySchema = z.object({
  sensitiveScopes: z.array(oidcScopeSchema).default(["offline_access"]),
  requireExplicitConsent: z.boolean().default(true),
});

export const oidcOpConfigSchema = z.object({
  enabled: z.boolean().default(false),
  issuer: oidcUrlSchema.optional(),
  basePath: oidcPathSchema.default("/oidc"),
  clients: z.array(oidcOpClientSchema).default([]),
  clientJwks: z.record(oidcClientIdSchema, oidcClientJwksSchema).optional(),
  dynamicClients: z.boolean().default(false),
  scopes: z.array(oidcScopeSchema).min(1).default(["openid", "profile", "email"]),
  signingAlgorithm: z.enum(["RS256", "PS256", "ES256", "EdDSA"]).default("RS256"),
  jwks: z.record(z.string(), z.unknown()).optional(),
  loginURL: oidcUrlSchema.optional(),
  refreshTokenEnabled: z.boolean().default(true),
  allowDynamicRegistration: z.literal(false).default(false),
  sensitiveScopes: z.array(oidcScopeSchema).default(["offline_access"]),
  requireExplicitConsent: z.boolean().default(true),
  consentPolicy: oidcConsentPolicySchema.optional(),
});

export const oidcConfigSchema = z
  .object({
    rp: z
      .object({
        enabled: z.boolean().default(false),
        providers: z.array(oidcRpProviderSchema).default([]),
      })
      .default({}),
    op: oidcOpConfigSchema.default({}),
  })
  .default({});

export type OidcRpProvider = z.output<typeof oidcRpProviderSchema>;
export type OidcOpClient = z.output<typeof oidcOpClientSchema>;
export type OidcOpConfig = z.output<typeof oidcOpConfigSchema>;
export type OidcConfig = z.output<typeof oidcConfigSchema>;
export type OidcClientAuthSigningAlgorithm = z.output<typeof oidcClientAuthSigningAlgorithmSchema>;
export type { OidcApplicationType } from "./redirect-policy.js";

export function validateOidcConfig(config: OidcConfig, profile: "development" | "test" | "staging" | "production"): void {
  if (config.rp.enabled) {
    if (config.rp.providers.length === 0) {
      throw new Error("[getbrick-idaas] oidc.rp.enabled requires at least one provider");
    }
    assertUnique(
      config.rp.providers.map((provider) => provider.providerId),
      "OIDC RP providerId",
    );
    for (const provider of config.rp.providers) {
        if (!provider.scopes.includes("openid")) {
          throw new Error(`[getbrick-idaas] OIDC RP provider ${provider.providerId} must include the openid scope`);
        }
        if (provider.redirectUriPolicy !== "exact" || provider.redirectPolicy.mode !== "exact" || !provider.redirectPolicy.exact) {
          throw new Error(`[getbrick-idaas] OIDC RP provider ${provider.providerId} requires exact redirect URI matching`);
        }
        const pkceRequired = provider.pkce === true || provider.pkce.required === true;
        const pkceMethod = provider.pkce === true ? provider.pkceMethod : provider.pkce.method;
        if (provider.consent !== "explicit" && (!provider.consent.required || provider.consent.mode !== "explicit")) {
          throw new Error(`[getbrick-idaas] OIDC RP provider ${provider.providerId} requires explicit consent`);
        }
        if (!provider.consentRequired || !provider.requireExplicitConsent) {
          throw new Error(`[getbrick-idaas] OIDC RP provider ${provider.providerId} requires explicit consent`);
        }
        if (!pkceRequired || pkceMethod !== "S256" || provider.responseType !== "code") {
          throw new Error(`[getbrick-idaas] OIDC RP provider ${provider.providerId} requires code flow with PKCE S256`);
        }
       if (provider.tokenEndpointAuth === "none" && provider.clientSecret !== undefined) {
         throw new Error(`[getbrick-idaas] OIDC RP provider ${provider.providerId} must not configure a client secret with tokenEndpointAuth=none`);
       }
       if (provider.clientSecret !== undefined && /[\u0000-\u001f\u007f]/u.test(provider.clientSecret)) {
         throw new Error(`[getbrick-idaas] OIDC RP provider ${provider.providerId} client secret is invalid`);
       }
        if (!provider.issuer && !provider.discoveryUrl) {
         throw new Error(
          `[getbrick-idaas] OIDC RP provider ${provider.providerId} requires issuer or discoveryUrl`,
        );
       }
       if (profile === "production") {
         if (!provider.issuer) throw new Error(`[getbrick-idaas] production OIDC RP provider ${provider.providerId} requires issuer`);
         if (!provider.userInfoUrl) throw new Error(`[getbrick-idaas] production OIDC RP provider ${provider.providerId} requires userInfoUrl`);
         if (provider.discoveryUrl !== undefined) assertOidcDiscoveryOrigin(provider.issuer, provider.discoveryUrl, provider.providerId);
       }
      if (profile === "production") {
        assertProductionUrls(profile, [
          provider.issuer,
          provider.discoveryUrl,
          provider.authorizationUrl,
          provider.tokenUrl,
          provider.userInfoUrl,
          provider.redirectURI,
          provider.postLogoutRedirectURI,
        ]);
      }
    }
  }

  if (config.op.enabled) {
    if (!config.op.issuer) {
      throw new Error("[getbrick-idaas] oidc.op.enabled requires issuer");
    }
    if (config.op.clients.length === 0 && !config.op.dynamicClients) {
      throw new Error("[getbrick-idaas] oidc.op.enabled requires at least one client or dynamicClients=true");
    }
    if (!config.op.scopes.includes("openid")) {
      throw new Error("[getbrick-idaas] oidc.op.scopes must include openid");
    }
    assertUnique(
      config.op.clients.map((client) => client.clientId),
      "OIDC OP clientId",
    );
    const redirectOptions: OidcRedirectPolicyOptions = { allowInsecureHttp: profile !== "production" };
    for (const [clientId, jwks] of Object.entries(config.op.clientJwks ?? {})) {
      try {
        validateOidcClientJwks(jwks);
      } catch {
        throw new Error(`[getbrick-idaas] OIDC OP client ${clientId} has invalid client JWKS`);
      }
    }
     for (const client of config.op.clients) {
       if (client.clientSecret !== undefined && /[\u0000-\u001f\u007f]/u.test(client.clientSecret)) {
         throw new Error(`[getbrick-idaas] OIDC OP client ${client.clientId} client secret is invalid`);
       }
       if (!client.scopes.includes("openid")) {
        throw new Error(`[getbrick-idaas] OIDC OP client ${client.clientId} must include the openid scope`);
      }
      if (!client.responseTypes.includes("code")) {
        throw new Error(`[getbrick-idaas] OIDC OP client ${client.clientId} must support the code response type`);
      }
       if (!client.requirePkce) {
         throw new Error(`[getbrick-idaas] OIDC OP client ${client.clientId} requires PKCE`);
       }
      if (client.tokenEndpointAuthMethod === "private_key_jwt") {
        if (client.clientSecret !== undefined) {
          throw new Error(`[getbrick-idaas] OIDC OP client ${client.clientId} must not configure a client secret with private_key_jwt`);
        }
        const clientJwks = client.jwks ?? client.clientJwks ?? config.op.clientJwks?.[client.clientId];
        if (!clientJwks && !client.jwksUri) {
          throw new Error(`[getbrick-idaas] OIDC OP client ${client.clientId} requires a client JWKS for private_key_jwt`);
        }
        if (clientJwks) validateOidcClientJwks(clientJwks, { algorithm: client.tokenEndpointAuthSigningAlg });
      }
      if (client.tokenEndpointAuthMethod === "none" && client.clientSecret !== undefined) {
        throw new Error(`[getbrick-idaas] OIDC OP client ${client.clientId} must not configure a client secret`);
      }
      if (profile === "production") {
        assertProductionUrls(profile, [client.jwksUri]);
      }
      assertOidcClientRedirectPolicy({
        applicationType: client.applicationType,
        tokenEndpointAuthMethod: client.tokenEndpointAuthMethod,
        requirePkce: client.requirePkce,
        redirectUris: client.redirectUris,
        postLogoutRedirectUris: client.postLogoutRedirectUris,
      }, redirectOptions);
    }
    const issuerPath = normalizeOidcPath(new URL(config.op.issuer).pathname);
    if (issuerPath !== "/" && issuerPath !== normalizeOidcPath(config.op.basePath)) {
      throw new Error(
        `[getbrick-idaas] oidc.op.basePath must match the issuer path (${issuerPath})`,
      );
    }
    if (normalizeOidcPath(config.op.basePath) === "/") {
      throw new Error("[getbrick-idaas] oidc.op.basePath must not be mounted at the application root");
    }
    if (profile === "production") {
      if (!config.op.requireExplicitConsent || config.op.consentPolicy?.requireExplicitConsent === false) {
        throw new Error("[getbrick-idaas] production OIDC consent must require explicit approval");
      }
      assertProductionUrls(profile, [config.op.issuer, config.op.loginURL]);
    }
  }
}

export function normalizeOidcPath(value: string): string {
  const path = value.trim().replace(/\/+$/u, "");
  return path || "/";
}

export function isSafeOidcUrl(value: string, allowQuery: boolean): boolean {
  try {
    const parsed = new URL(value);
    if (/%(?![0-9a-f]{2})/iu.test(value)) return false;
    let decoded = value;
    for (let depth = 0; depth <= value.length; depth += 1) {
      if (!/%[0-9a-f]{2}/iu.test(decoded)) break;
      const next = decodeURIComponent(decoded);
      if (next === decoded) break;
      decoded = next;
    }
    return (
      (parsed.protocol === "http:" || parsed.protocol === "https:") &&
      parsed.hostname !== "" &&
      parsed.username === "" &&
      parsed.password === "" &&
      !parsed.hash &&
      (allowQuery || parsed.search === "") &&
      !/[\u0000-\u001F\u007F]/u.test(value) &&
      !/[\u0000-\u001F\u007F]/u.test(decoded) &&
      !value.includes("\\") &&
      !decoded.includes("\\")
    );
  } catch {
    return false;
  }
}

function assertProductionUrls(
  profile: "development" | "test" | "staging" | "production",
  values: Array<string | undefined>,
): void {
  for (const value of values) {
    if (!value) continue;
    if (profile !== "production") continue;
    let parsed: URL;
    try {
      parsed = new URL(value);
    } catch {
      throw new Error(`[getbrick-idaas] OIDC production URL is invalid: ${value}`);
    }
    if (parsed.protocol !== "https:") {
      throw new Error("[getbrick-idaas] OIDC production endpoints must use HTTPS");
    }
  }
}

function assertOidcDiscoveryOrigin(issuer: string, discoveryUrl: string, providerId: string): void {
  let issuerOrigin: string;
  let discoveryOrigin: string;
  try {
    issuerOrigin = new URL(issuer).origin;
    discoveryOrigin = new URL(discoveryUrl).origin;
  } catch {
    throw new Error(`[getbrick-idaas] OIDC RP provider ${providerId} discovery URL is invalid`);
  }
  if (issuerOrigin !== discoveryOrigin) throw new Error(`[getbrick-idaas] OIDC RP provider ${providerId} discovery URL must use the issuer origin`);
}

function assertUnique(values: string[], label: string): void {
  const seen = new Set<string>();
  for (const value of values) {
    if (seen.has(value)) {
      throw new Error(`[getbrick-idaas] duplicate ${label}: ${value}`);
    }
    seen.add(value);
  }
}
