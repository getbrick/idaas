import { createPrivateKey, createPublicKey, randomBytes, type JsonWebKey as NodeJsonWebKey } from "node:crypto";
import Provider, { errors, interactionPolicy } from "oidc-provider";
import type {
  Account,
  AccountClaims,
  Adapter,
  AdapterFactory,
  AdapterPayload,
  ClientMetadata,
  Configuration,
  JWKS,
} from "oidc-provider";
import {
  OIDC_CLIENT_AUTH_SIGNING_ALGORITHMS,
  OIDC_CLIENT_KIND_METADATA,
  OIDC_DEFAULT_CLIENT_AUTH_METHOD,
  OIDC_DEFAULT_CLIENT_AUTH_SIGNING_ALGORITHM,
  OIDC_REDIRECT_POLICY_METADATA,
  OIDC_REQUIRE_PKCE_METADATA,
  normalizeOidcJwksUri,
  projectOidcClientJwks,
  type OidcDynamicClientSigningAlgorithm,
} from "./client-registry.js";
import {
  type OidcClientJwksInput,
} from "./client-jwks.js";
import {
  createOidcConsentResolverV2,
  normalizeOidcClaimPolicy,
  normalizeOidcConsentPolicy,
  isOidcBuiltinClaim,
  isValidOidcClaimName,
  projectOidcClaims,
  readOidcConsentClaims,
  readOidcConsentScopes,
  requiresExplicitOidcClaimConsent,
  resolveOidcClaimPolicy,
  requiresExplicitOidcConsent,
  resolveOidcConsentDecisionV2,
  snapshotOidcConsentContext,
  type OidcClaimPolicy,
  type OidcClaimPolicyInput,
  type OidcConsentPolicy,
  type OidcConsentResolver,
  type OidcHostGrantBoundary,
  type OidcLegacyConsentResolver,
} from "./consent-policy.js";
import type {
  OidcConsentContext,
  OidcConsentDecision,
  OidcConsentGrantStore,
  OidcConsentResolverV2,
} from "./contracts.js";
import type { OidcOpClient, OidcOpConfig } from "./config.js";
import { normalizeOidcPath } from "./config.js";
import {
  assertOidcClientRedirectPolicy,
  type OidcApplicationType,
  type OidcRedirectPolicyOptions,
} from "./redirect-policy.js";

export type { AdapterFactory, ClientMetadata, Configuration, JWKS } from "oidc-provider";

export interface OidcUser {
  id: string;
  name?: string;
  email?: string;
  emailVerified?: boolean;
  image?: string;
  claims?: Record<string, unknown>;
}

export type OidcUserResolver = (id: string) => Promise<OidcUser | null | undefined>;

export interface OidcClaimsResolverContext {
  user: OidcUser;
  userId: string;
  use: string;
  scope: string;
  requestedScopes: readonly string[];
  requestedClaims: readonly string[];
  allowedClaims: readonly string[];
  allowlist: readonly string[];
  policyVersion: string;
  clientId?: string;
  grantId?: string;
}

export type OidcClaimsResolver = (
  user: OidcUser,
  scope: string,
  context?: OidcClaimsResolverContext,
) => Record<string, unknown> | Promise<Record<string, unknown>>;

export type OidcClaimsResolverV2 = (
  context: OidcClaimsResolverContext,
) => Record<string, unknown> | Promise<Record<string, unknown>>;

export type OidcProviderClaimsResolverContext = OidcClaimsResolverContext;

export interface OidcProviderRuntime {
  provider: Provider;
  issuer: string;
  basePath: string;
  interactionPath: string;
  consentPolicy?: OidcConsentPolicy;
  consentResolver?: OidcConsentResolver;
  consentResolverMode: "v2" | "legacy";
  consentResolverV2?: OidcConsentResolverV2;
  legacyConsentResolver?: OidcLegacyConsentResolver;
  consentTenantId?: string;
  consentApplicationId?: string;
  hostGrantPort?: OidcHostGrantBoundary;
  consentGrantPort?: OidcHostGrantBoundary;
  consentGrantStore?: OidcConsentGrantStore;
  claimPolicy: OidcClaimPolicy;
  resolveConsentV2: (context: OidcConsentContext) => Promise<OidcConsentDecision>;
  resolveConsent: (context: OidcConsentContext) => Promise<OidcConsentDecision>;
}

export type OidcProviderClient = Omit<OidcOpClient, "tokenEndpointAuthSigningAlg"> & {
  tokenEndpointAuthSigningAlg?: OidcProviderSigningAlgorithm;
};

export type OidcProviderConfig = Omit<OidcOpConfig, "clients" | "signingAlgorithm"> & {
  clients: OidcProviderClient[];
  signingAlgorithm: OidcProviderSigningAlgorithm;
};

export interface CreateOidcProviderInput {
  config: OidcProviderConfig;
  findUser: OidcUserResolver;
  clientSecrets?: Record<string, string>;
  clientJwks?: Record<string, OidcClientJwksInput>;
  adapter?: AdapterFactory;
  jwks?: JWKS;
  cookieKeys?: string[];
  proxy?: boolean;
  mapClaims?: OidcClaimsResolver;
  claimsResolver?: OidcClaimsResolverV2;
  claimsAllowlist?: readonly string[];
  claimAllowlist?: readonly string[];
  allowedClaims?: readonly string[];
  profile?: "development" | "test" | "staging" | "production";
  dynamicClients?: boolean;
  consentPolicy?: Partial<OidcConsentPolicy>;
  consentResolver?: OidcConsentResolver;
  consentResolverV2?: OidcConsentResolverV2;
  oidcConsentResolverV2?: OidcConsentResolverV2;
  legacyConsentResolver?: OidcConsentResolver;
  consentTenantId?: string;
  consentApplicationId?: string;
  tenantId?: string;
  applicationId?: string;
  hostGrantPort?: OidcHostGrantBoundary;
  consentGrantPort?: OidcHostGrantBoundary;
  consentGrantStore?: OidcConsentGrantStore;
  claimPolicy?: OidcClaimPolicyInput;
  claimsPolicy?: OidcClaimPolicyInput;
  postLogoutSuccess?: (context: unknown) => void | Promise<void>;
  allowInsecureHttp?: boolean;
}

export type OidcProviderSigningAlgorithm = OidcDynamicClientSigningAlgorithm;

export function validateOidcSigningJwks(
  jwks: JWKS,
  algorithm: OidcProviderSigningAlgorithm,
): void {
  normalizeProviderSigningAlgorithm(algorithm);
  if (!Array.isArray(jwks.keys) || jwks.keys.length === 0 || jwks.keys.length > 16) {
    throw new Error("[getbrick-idaas] OIDC JWKS must contain at least one key");
  }
  const seen = new Set<string>();
  let privateKeyFound = false;
  for (const key of jwks.keys) {
    if (!key || typeof key !== "object") {
      throw new Error("[getbrick-idaas] OIDC JWKS contains an invalid key");
    }
    if (key.use !== undefined && key.use !== "sig") {
      throw new Error("[getbrick-idaas] OIDC JWKS keys must be signing keys");
    }
    if (key.alg !== undefined && key.alg !== algorithm) {
      throw new Error(`[getbrick-idaas] OIDC JWKS algorithm must be ${algorithm}`);
    }
    if (typeof key.kid !== "string" || key.kid.length === 0 || key.kid.length > 256 || /\s/u.test(key.kid) || /[\u0000-\u001f\u007f]/u.test(key.kid)) {
      throw new Error("[getbrick-idaas] OIDC JWKS keys require kid");
    }
    if (seen.has(key.kid)) {
      throw new Error(`[getbrick-idaas] duplicate OIDC JWKS kid: ${key.kid}`);
    }
    seen.add(key.kid);
    const keyRecord = key as unknown as Record<string, unknown>;
    if (keyRecord.key_ops !== undefined) {
      if (
        !Array.isArray(keyRecord.key_ops) ||
        !keyRecord.key_ops.every((operation) => typeof operation === "string") ||
        !keyRecord.key_ops.includes("sign") ||
        keyRecord.key_ops.includes("verify")
      ) {
        throw new Error("[getbrick-idaas] OIDC JWKS key operations are invalid");
      }
    }
    if (typeof keyRecord.d !== "string" || keyRecord.d.length === 0) {
      validateImportedJwk(keyRecord, algorithm, false);
      continue;
    }
    privateKeyFound = true;
    validateImportedJwk(keyRecord, algorithm, true);
  }
  if (!privateKeyFound) {
    throw new Error("[getbrick-idaas] OIDC JWKS must contain a private signing key");
  }
}

function validateImportedJwk(
  key: Record<string, unknown>,
  algorithm: OidcProviderSigningAlgorithm,
  privateKey: boolean,
): void {
  const jwk = key as unknown as NodeJsonWebKey;
  let imported;
  try {
    imported = privateKey
      ? createPrivateKey({ key: jwk, format: "jwk" })
      : createPublicKey({ key: jwk, format: "jwk" });
  } catch {
    throw new Error("[getbrick-idaas] OIDC JWKS key could not be imported");
  }
  if (algorithm === "RS256" || algorithm === "PS256") {
    if (imported.asymmetricKeyType !== "rsa") {
      throw new Error(`[getbrick-idaas] OIDC ${algorithm} JWKS key type is invalid`);
    }
    const modulusLength = imported.asymmetricKeyDetails?.modulusLength;
    if (modulusLength !== undefined && modulusLength < 2048) {
      throw new Error(`[getbrick-idaas] OIDC ${algorithm} JWKS keys must be at least 2048 bits`);
    }
  } else if (algorithm === "ES256") {
    if (
      imported.asymmetricKeyType !== "ec" ||
      imported.asymmetricKeyDetails?.namedCurve !== "prime256v1"
    ) {
      throw new Error("[getbrick-idaas] OIDC ES256 JWKS key must use P-256");
    }
  } else if (algorithm === "EdDSA") {
    if (
      typeof imported.asymmetricKeyType !== "string" ||
      !imported.asymmetricKeyType.startsWith("ed") ||
      (key.crv !== "Ed25519" && key.crv !== "Ed448")
    ) {
      throw new Error("[getbrick-idaas] OIDC EdDSA JWKS key is invalid");
    }
  }
}

export function validateOidcCookieKeys(
  keys: string[],
  minimumLength = 1,
): void {
  if (!Array.isArray(keys) || keys.length === 0) {
    throw new Error("[getbrick-idaas] OIDC cookie keys must not be empty");
  }
  for (const key of keys) {
    if (typeof key !== "string" || key.length < minimumLength) {
      throw new Error(`[getbrick-idaas] OIDC cookie keys must be at least ${minimumLength} characters`);
    }
  }
}

export function createOidcProvider(input: CreateOidcProviderInput): OidcProviderRuntime {
  const config = input.config;
  if (!config.enabled) {
    throw new Error("[getbrick-idaas] cannot create an OIDC provider while oidc.op.enabled is false");
  }
  if (!config.issuer) {
    throw new Error("[getbrick-idaas] cannot create an OIDC provider without an issuer");
  }
  if (input.profile === "production" && input.allowInsecureHttp === true) {
    throw new Error("[getbrick-idaas] production OIDC provider cannot allow insecure HTTP endpoints");
  }
  const dynamicClients = input.dynamicClients ?? config.dynamicClients;
  if (config.clients.length === 0 && dynamicClients !== true) {
    throw new Error("[getbrick-idaas] cannot create an OIDC provider without clients");
  }
  if (input.profile === "production" && !input.adapter) {
    throw new Error("[getbrick-idaas] production OIDC provider requires a persistent adapter");
  }
  if (input.profile === "production" && typeof (input.adapter as { ready?: unknown } | undefined)?.ready !== "function") {
    throw new Error("[getbrick-idaas] production OIDC provider requires an adapter readiness check");
  }
  if (input.profile === "production" && !input.jwks && !config.jwks) {
    throw new Error("[getbrick-idaas] production OIDC provider requires a configured JWKS");
  }
  if (input.profile === "production") {
    if (!input.cookieKeys || input.cookieKeys.length === 0) {
      throw new Error("[getbrick-idaas] production OIDC provider requires explicit cookie keys");
    }
    validateOidcCookieKeys(input.cookieKeys, 32);
  }
  if (input.profile === "production" && input.consentPolicy?.requireExplicitConsent === false) {
    throw new Error("[getbrick-idaas] production OIDC provider requires explicit consent");
  }
  if (!config.refreshTokenEnabled && config.clients.some((client) => client.grantTypes.includes("refresh_token"))) {
    throw new Error("[getbrick-idaas] OIDC refresh_token grant requires refreshTokenEnabled=true");
  }
  const redirectOptions: OidcRedirectPolicyOptions = {
    allowInsecureHttp: input.profile === "production"
      ? false
      : input.allowInsecureHttp ?? true,
  };
  const clientJwks = {
    ...(config.clientJwks ?? {}),
    ...(input.clientJwks ?? {}),
  } as Record<string, OidcClientJwksInput>;
  const staticClientIds = new Set<string>();
  for (const client of config.clients) {
    const clientId = typeof client.clientId === "string" ? client.clientId : "";
    if (!isProviderClientId(clientId) || staticClientIds.has(clientId)) {
      throw new Error("[getbrick-idaas] static OIDC clientId must be valid and unique");
    }
    staticClientIds.add(clientId);
  }
  for (const [clientId, jwks] of Object.entries(clientJwks)) {
    const client = config.clients.find((item) => item.clientId === clientId);
    const algorithm = client?.tokenEndpointAuthSigningAlg as OidcProviderSigningAlgorithm | undefined;
    try {
      projectOidcClientJwks(jwks, algorithm);
    } catch {
      throw new Error(`[getbrick-idaas] OIDC OP client ${clientId} has invalid client JWKS`);
    }
  }
  const basePath = normalizeOidcPath(config.basePath);
  const clients = config.clients.map((client) =>
    toClientMetadata(
      client,
      input.clientSecrets?.[client.clientId] ?? client.clientSecret,
      config.signingAlgorithm as OidcProviderSigningAlgorithm,
      clientJwks[client.clientId],
      redirectOptions,
    ),
  );
  const adapter = prioritizeStaticOidcClients(input.adapter, staticClientIds);
  const scopes = unique([
    ...config.scopes,
    ...config.clients.flatMap((client) => client.scopes),
  ]);
  const cookieKeys = input.cookieKeys?.length
    ? input.cookieKeys
    : [randomBytes(32).toString("base64url")];
  assertCookieKeys(cookieKeys);
  const configuredJwks = input.jwks ?? (config.jwks as JWKS | undefined);
  const signingAlgorithm = config.signingAlgorithm as OidcProviderSigningAlgorithm;
  if (configuredJwks) {
    validateOidcSigningJwks(configuredJwks, signingAlgorithm);
  }
  if (!configuredJwks && signingAlgorithm !== "RS256") {
    throw new Error(`[getbrick-idaas] ${signingAlgorithm} OIDC signing requires a configured JWKS`);
  }
  const consentPolicy = normalizeOidcConsentPolicy({
    sensitiveScopes: [
      ...(config.sensitiveScopes ?? []),
      ...(config.consentPolicy?.sensitiveScopes ?? []),
    ],
    requireExplicitConsent: config.consentPolicy?.requireExplicitConsent ?? config.requireExplicitConsent ?? true,
    ...input.consentPolicy,
  });
  const configuredClaimPolicy = input.claimPolicy ?? input.claimsPolicy ?? {};
  const configuredClaimsAllowlist = input.claimsAllowlist ?? input.claimAllowlist ?? input.allowedClaims;
  const claimPolicy = normalizeOidcClaimPolicy({
    ...configuredClaimPolicy,
    policyVersion: configuredClaimPolicy.policyVersion ?? consentPolicy.policyVersion,
    ...(configuredClaimsAllowlist === undefined ? {} : { allowlist: configuredClaimsAllowlist }),
  });
  const configuredConsentResolverV2 = input.consentResolverV2 ?? input.oidcConsentResolverV2;
  const legacyConsentResolver = input.consentResolver ?? input.legacyConsentResolver;
  const hostGrantPort = input.hostGrantPort ?? input.consentGrantPort ?? input.consentGrantStore;
  if (legacyConsentResolver !== undefined && (configuredConsentResolverV2 !== undefined || hostGrantPort !== undefined)) {
    throw new Error("[getbrick-idaas] legacy and V2 OIDC consent resolvers cannot be mixed");
  }
  const consentTenantId = normalizeConsentIdentifier(input.consentTenantId ?? input.tenantId);
  const consentApplicationId = normalizeConsentIdentifier(input.consentApplicationId ?? input.applicationId);
  const hostConsentResolver = hostGrantPort === undefined
    ? undefined
    : createOidcConsentResolverV2(hostGrantPort, claimPolicy);
  const resolveConsentV2 = async (context: OidcConsentContext): Promise<OidcConsentDecision> => {
    try {
      const request = snapshotOidcConsentContext(context);
      if (configuredConsentResolverV2 !== undefined) {
        return resolveOidcConsentDecisionV2(request, await configuredConsentResolverV2(request), claimPolicy);
      }
      if (hostConsentResolver !== undefined) {
        return await hostConsentResolver(request);
      }
    } catch {
      return { decision: "denied", reason: "policy_denied" };
    }
    return { decision: "denied", reason: "policy_denied" };
  };
  const interactionPolicyConfig = createInteractionPolicy(consentPolicy, claimPolicy);
  const findAccount = async (
    context: unknown,
    accountId: string,
  ): Promise<Account | undefined> => {
    const user = await input.findUser(accountId);
    if (!user || typeof user.id !== "string" || user.id.length === 0) return undefined;
    const providerContext = readProviderContext(context);
    return {
      accountId: user.id,
      claims: async (use: string, scope: string, claimMask?: Record<string, unknown>) => {
        const requestedScopes = scope.split(/\s+/u).filter((entry) => entry.length > 0);
        const requestedScopeSet = new Set(requestedScopes);
        const requestedClaims = readProviderRequestedClaims(claimMask);
        const resolvedClaimPolicy = resolveOidcClaimPolicy(claimPolicy, {
          requestedScopes,
          requestedClaims,
          ...(providerContext.clientId === undefined ? {} : { clientId: providerContext.clientId }),
        });
        const allowedClaims = unique([
          ...resolvedClaimPolicy.allowedClaims,
          ...requestedClaims.filter((claim) => isOidcBuiltinClaim(claim)),
        ]);
        const resolverContext: OidcClaimsResolverContext = {
          user,
          userId: user.id,
          use,
          scope,
          requestedScopes,
          requestedClaims,
          allowedClaims,
          allowlist: allowedClaims,
          policyVersion: claimPolicy.policyVersion,
          ...(providerContext.clientId === undefined ? {} : { clientId: providerContext.clientId }),
          ...(providerContext.grantId === undefined ? {} : { grantId: providerContext.grantId }),
        };
        const claims: AccountClaims = { sub: user.id };
        const profileClaims = new Set(["name", "preferred_username", "picture"]);
        const emailClaims = new Set(["email", "email_verified"]);
        const wantsProfile = requestedScopeSet.has("profile") || requestedClaims.some((claim) => profileClaims.has(claim));
        const wantsEmail = requestedScopeSet.has("email") || requestedClaims.some((claim) => emailClaims.has(claim));
        if (wantsProfile) {
          if (user.name !== undefined) claims.name = user.name;
          if (user.email !== undefined) claims.preferred_username = user.email;
          if (user.image !== undefined) claims.picture = user.image;
        }
        if (wantsEmail) {
          if (user.email !== undefined) claims.email = user.email;
          if (user.emailVerified !== undefined) claims.email_verified = user.emailVerified;
        }
        const customClaims = input.claimsResolver !== undefined
          ? await input.claimsResolver(resolverContext)
          : input.mapClaims !== undefined
            ? await input.mapClaims(user, scope, resolverContext)
            : user.claims ?? {};
        return {
          ...claims,
          ...projectOidcClaims(customClaims, {
            requestedClaims,
            allowlist: allowedClaims,
            protectedClaims: Object.keys(claims),
          }),
        };
      },
    };
  };

  const providerClaims: Record<string, string[]> = {
    openid: ["sub"],
    profile: ["name", "preferred_username", "picture"],
    email: ["email", "email_verified"],
  };
  for (const definition of claimPolicy.definitions) {
    providerClaims[definition.name] = unique([
      ...(providerClaims[definition.name] ?? []),
      definition.name,
    ]);
    for (const scope of definition.scopes) {
      providerClaims[scope] = unique([
        ...(providerClaims[scope] ?? []),
        definition.name,
      ]);
    }
  }

  const configuration: Configuration = {
    clients,
    adapter,
    findAccount,
    claims: providerClaims,
    scopes,
    responseTypes: ["code"],
    pkce: {
      methods: ["S256"],
       required: () => true,
    },
    clientAuthMethods: ["client_secret_basic", "client_secret_post", "none", "private_key_jwt"],
    extraClientMetadata: {
       properties: [OIDC_REDIRECT_POLICY_METADATA, OIDC_REQUIRE_PKCE_METADATA, OIDC_CLIENT_KIND_METADATA],
      validator: (_context, _key, _value, metadata) => {
        validateProviderClientMetadata(metadata, redirectOptions);
      },
    },
    features: {
       devInteractions: { enabled: false },
       resourceIndicators: { enabled: false },
       claimsParameter: { enabled: true },
       userinfo: { enabled: true },
      introspection: { enabled: true },
      revocation: { enabled: true },
      registration: { enabled: false },
      clientCredentials: { enabled: false },
      rpInitiatedLogout: {
        enabled: true,
        ...(input.postLogoutSuccess === undefined ? {} : { postLogoutSuccessSource: input.postLogoutSuccess }),
      },
    },
    interactions: {
      policy: interactionPolicyConfig,
      url: (_context, interaction) =>
        `${basePath}/interaction/${encodeURIComponent(interaction.uid)}`,
    },
     issueRefreshToken: (_context, client, code) =>
       config.refreshTokenEnabled &&
       client.grantTypeAllowed("refresh_token") &&
       (code.scope ?? "").split(" ").includes("offline_access"),
    rotateRefreshToken: config.refreshTokenEnabled,
    revokeGrantPolicy: () => true,
    ttl: {
      AccessToken: 300,
      AuthorizationCode: 600,
      IdToken: 300,
      RefreshToken: config.refreshTokenEnabled ? 2_592_000 : 300,
      Interaction: 600,
      Session: 86_400,
      Grant: 2_592_000,
    },
    cookies: {
      keys: cookieKeys,
      names: {
        session: "getbrick_oidc_session",
        interaction: "getbrick_oidc_interaction",
        resume: "getbrick_oidc_resume",
        state: "getbrick_oidc_state",
      },
    },
    enabledJWA: {
      idTokenSigningAlgValues: [signingAlgorithm],
      userinfoSigningAlgValues: [signingAlgorithm],
      introspectionSigningAlgValues: [signingAlgorithm],
      clientAuthSigningAlgValues: [...OIDC_CLIENT_AUTH_SIGNING_ALGORITHMS],
    },
    jwks: configuredJwks,
  };

  const provider = new Provider(config.issuer, configuration);
  provider.proxy = input.proxy === true;
  return {
    provider,
    issuer: config.issuer,
    basePath,
    interactionPath: `${basePath}/interaction`,
    consentPolicy,
    consentResolver: legacyConsentResolver,
    consentResolverMode: configuredConsentResolverV2 !== undefined || hostGrantPort !== undefined
      ? "v2"
      : legacyConsentResolver !== undefined
        ? "legacy"
        : "v2",
    consentResolverV2: configuredConsentResolverV2 === undefined && hostGrantPort === undefined
      ? undefined
      : resolveConsentV2,
    legacyConsentResolver,
    consentTenantId,
    consentApplicationId,
    hostGrantPort,
    consentGrantPort: hostGrantPort,
    consentGrantStore: input.consentGrantStore,
    claimPolicy,
    resolveConsentV2,
    resolveConsent: resolveConsentV2,
  };
}

function toClientMetadata(
  client: OidcProviderClient,
  secret: string | undefined,
  signingAlgorithm: OidcProviderSigningAlgorithm,
  configuredClientJwks: OidcClientJwksInput | undefined,
  redirectOptions: OidcRedirectPolicyOptions,
): ClientMetadata {
  const authMethod = client.tokenEndpointAuthMethod ?? OIDC_DEFAULT_CLIENT_AUTH_METHOD;
  if (!new Set(["none", "client_secret_basic", "client_secret_post", "private_key_jwt"]).has(authMethod)) {
    throw new Error(`[getbrick-idaas] OIDC OP client ${client.clientId} auth method is invalid`);
  }
  const applicationType = client.applicationType ?? "web";
  if (applicationType !== "web" && applicationType !== "native" && applicationType !== "webview") {
    throw new Error(`[getbrick-idaas] OIDC OP client ${client.clientId} application type is invalid`);
  }
  const providerApplicationType = applicationType === "webview" ? "web" : applicationType;
  const requirePkce = client.requirePkce ?? true;
  if (!requirePkce) {
    throw new Error(`[getbrick-idaas] OIDC OP client ${client.clientId} requires PKCE`);
  }
  const tokenEndpointAuthSigningAlg = normalizeProviderSigningAlgorithm(
    client.tokenEndpointAuthSigningAlg ?? OIDC_DEFAULT_CLIENT_AUTH_SIGNING_ALGORITHM,
  );
  if (authMethod !== "none" && authMethod !== "private_key_jwt" && (typeof secret !== "string" || secret.length === 0)) {
    throw new Error(`[getbrick-idaas] OIDC OP client ${client.clientId} requires a client secret`);
  }
  if (secret !== undefined && (authMethod === "private_key_jwt" || authMethod === "none")) {
    throw new Error(`[getbrick-idaas] OIDC OP client ${client.clientId} must not configure a client secret`);
  }
  if (secret !== undefined && /[\u0000-\u001f\u007f]/u.test(secret)) {
    throw new Error(`[getbrick-idaas] OIDC OP client ${client.clientId} client secret is invalid`);
  }
  const jwksUri = client.jwksUri === undefined
    ? undefined
    : normalizeOidcJwksUri(client.jwksUri, redirectOptions.allowInsecureHttp);
  if (client.jwks !== undefined && client.clientJwks !== undefined && client.jwks !== client.clientJwks) {
    throw new Error(`[getbrick-idaas] OIDC OP client ${client.clientId} has conflicting JWKS aliases`);
  }
  const jwksSource = client.jwks ?? client.clientJwks ?? configuredClientJwks;
  if (jwksSource !== undefined && jwksUri !== undefined) {
    throw new Error(`[getbrick-idaas] OIDC OP client ${client.clientId} cannot configure both JWKS and jwks_uri`);
  }
  if (authMethod !== "private_key_jwt" && (jwksSource !== undefined || jwksUri !== undefined)) {
    throw new Error(`[getbrick-idaas] OIDC OP client ${client.clientId} asymmetric fields require private_key_jwt`);
  }
  if (authMethod === "private_key_jwt" && jwksSource === undefined && jwksUri === undefined) {
    throw new Error(`[getbrick-idaas] OIDC OP client ${client.clientId} requires a client JWKS for private_key_jwt`);
  }
  const jwks = jwksSource === undefined
    ? undefined
    : projectOidcClientJwks(jwksSource, tokenEndpointAuthSigningAlg);
  if (
    !Array.isArray(client.redirectUris) ||
    !Array.isArray(client.postLogoutRedirectUris ?? []) ||
    client.redirectUris.length > 100 ||
    (client.postLogoutRedirectUris?.length ?? 0) > 100 ||
    !Array.isArray(client.grantTypes) ||
    !Array.isArray(client.responseTypes) ||
    !Array.isArray(client.scopes)
  ) {
    throw new Error(`[getbrick-idaas] OIDC OP client ${client.clientId} metadata is invalid`);
  }
  if (
    new Set(client.grantTypes).size !== client.grantTypes.length ||
    new Set(client.responseTypes).size !== client.responseTypes.length ||
    new Set(client.scopes).size !== client.scopes.length ||
    !client.grantTypes.includes("authorization_code") ||
    client.grantTypes.some((grantType) => grantType !== "authorization_code" && grantType !== "refresh_token") ||
    !client.responseTypes.includes("code") ||
    client.responseTypes.some((responseType) => responseType !== "code") ||
    !client.scopes.includes("openid")
  ) {
    throw new Error(`[getbrick-idaas] OIDC OP client ${client.clientId} metadata is invalid`);
  }
  assertOidcClientRedirectPolicy({
    applicationType,
    tokenEndpointAuthMethod: authMethod,
    requirePkce,
    redirectUris: client.redirectUris,
    postLogoutRedirectUris: client.postLogoutRedirectUris,
  }, redirectOptions);
  return {
    client_id: client.clientId,
    client_name: client.clientName,
    application_type: providerApplicationType,
    ...(applicationType === "webview" ? { [OIDC_CLIENT_KIND_METADATA]: applicationType } : {}),
    redirect_uris: [...client.redirectUris],
    post_logout_redirect_uris: [...(client.postLogoutRedirectUris ?? [])],
    ...(jwksUri === undefined ? {} : { jwks_uri: jwksUri }),
    grant_types: [...client.grantTypes],
    response_types: [...client.responseTypes],
    scope: client.scopes.join(" "),
    id_token_signed_response_alg: signingAlgorithm,
    token_endpoint_auth_method: authMethod,
    ...(authMethod === "private_key_jwt"
      ? {
          token_endpoint_auth_signing_alg: tokenEndpointAuthSigningAlg,
          ...(jwks === undefined ? {} : { jwks }),
        }
      : {}),
    ...(secret !== undefined && authMethod !== "private_key_jwt" ? { client_secret: secret } : {}),
    [OIDC_REDIRECT_POLICY_METADATA]: "rfc8252-v1",
    [OIDC_REQUIRE_PKCE_METADATA]: requirePkce,
  } as ClientMetadata;
}

function createInteractionPolicy(
  consentPolicy: OidcConsentPolicy,
  claimPolicy: OidcClaimPolicy,
): interactionPolicy.Prompt[] {
  const policy = interactionPolicy.base();
  const consent = policy.get("consent");
  if (!consent) throw new Error("[getbrick-idaas] OIDC provider consent policy is unavailable");
  consent.checks.add(new interactionPolicy.Check(
    "getbrick_explicit_consent",
    "explicit consent is required for sensitive scopes and claims",
    "consent_required",
    (context) => {
      const oidc = (context as unknown as { oidc?: Record<string, unknown> }).oidc;
      const client = oidc?.client as {
        clientId?: unknown;
        client_id?: unknown;
        applicationType?: unknown;
        application_type?: unknown;
        [OIDC_CLIENT_KIND_METADATA]?: unknown;
      } | undefined;
      const params = (oidc?.params ?? {}) as Record<string, unknown>;
      const scopes = readOidcConsentScopes(params);
      const claims = readOidcConsentClaims(params);
      const clientId = typeof client?.clientId === "string"
        ? client.clientId
        : typeof client?.client_id === "string"
          ? client.client_id
          : undefined;
      const nativeInteraction = client?.applicationType === "native" ||
        client?.application_type === "native" ||
        client?.applicationType === "webview" ||
        client?.application_type === "webview" ||
        client?.[OIDC_CLIENT_KIND_METADATA] === "webview";
      const requiresClaims = requiresExplicitOidcClaimConsent(
        claims,
        claimPolicy,
        scopes,
        clientId,
      );
      return (requiresExplicitOidcConsent(scopes, consentPolicy, nativeInteraction) || requiresClaims) &&
        !hasConsentResult(oidc?.result);
    },
    () => ({
      sensitiveScopes: [...consentPolicy.sensitiveScopes],
      claimPolicyVersion: claimPolicy.policyVersion,
    }),
  ));
  return policy;
}

function validateProviderClientMetadata(
  metadata: ClientMetadata,
  redirectOptions: OidcRedirectPolicyOptions,
): void {
  const rawApplicationValue = metadata.application_type ?? metadata.applicationType;
  const applicationValue = rawApplicationValue === "webview" ? "web" : rawApplicationValue;
  const clientKind = readClientMarker(metadata, OIDC_CLIENT_KIND_METADATA);
  if (clientKind !== undefined && (typeof clientKind !== "string" || !["web", "native", "mp_weixin", "webview"].includes(clientKind))) {
    throw new errors.InvalidClientMetadata("client kind is invalid");
  }
  if (rawApplicationValue !== undefined && rawApplicationValue !== "web" && rawApplicationValue !== "native" && rawApplicationValue !== "webview") {
    throw new errors.InvalidClientMetadata("client application type is invalid");
  }
  const kindApplicationType = clientKind === "native" || clientKind === "mp_weixin"
    ? "native"
    : clientKind === "webview"
      ? "webview"
      : clientKind === "web"
        ? "web"
        : undefined;
  if (applicationValue !== undefined && kindApplicationType !== undefined && applicationValue !== kindApplicationType && !(clientKind === "webview" && applicationValue === "web")) {
    throw new errors.InvalidClientMetadata("client kind does not match application type");
  }
  const applicationType = (kindApplicationType ?? (rawApplicationValue === "webview" ? "webview" : applicationValue) ?? "web") as OidcApplicationType;
  const authValue = metadata.token_endpoint_auth_method ?? metadata.tokenEndpointAuthMethod;
  if (
    authValue !== undefined &&
    authValue !== "none" &&
    authValue !== "client_secret_basic" &&
    authValue !== "client_secret_post" &&
    authValue !== "private_key_jwt"
  ) {
    throw new errors.InvalidClientMetadata("client auth method is invalid");
  }
  const authMethod = authValue ?? OIDC_DEFAULT_CLIENT_AUTH_METHOD;
  const pkceMarker = readClientMarker(metadata, OIDC_REQUIRE_PKCE_METADATA);
  if (pkceMarker !== undefined && typeof pkceMarker !== "boolean") {
    throw new errors.InvalidClientMetadata("client PKCE policy is invalid");
  }
  const requirePkce = pkceMarker !== false;
  if (!requirePkce) {
    throw new errors.InvalidClientMetadata("OIDC clients require PKCE");
  }
  const redirectUris = Array.isArray(metadata.redirect_uris) ? metadata.redirect_uris : [];
  const postLogoutRedirectUris = Array.isArray(metadata.post_logout_redirect_uris)
    ? metadata.post_logout_redirect_uris
    : [];
  if (redirectUris.length > 100 || postLogoutRedirectUris.length > 100) {
    throw new errors.InvalidClientMetadata("client redirect URI list is too large");
  }
  try {
    assertOidcClientRedirectPolicy({
      applicationType,
      tokenEndpointAuthMethod: authMethod,
      requirePkce,
      redirectUris,
      postLogoutRedirectUris,
    }, redirectOptions);
    const signingValue = metadata.token_endpoint_auth_signing_alg ?? metadata.tokenEndpointAuthSigningAlg;
    const idTokenSigningValue = metadata.id_token_signed_response_alg ?? metadata.idTokenSignedResponseAlg;
    if (idTokenSigningValue !== undefined) normalizeProviderSigningAlgorithm(idTokenSigningValue);
    if (authMethod === "private_key_jwt") {
      if (metadata.client_secret !== undefined) {
        throw new Error("private_key_jwt clients must not have a client secret");
      }
      if (signingValue === undefined) {
        throw new Error("private_key_jwt clients require an explicit signing algorithm");
      }
      const algorithm = normalizeProviderSigningAlgorithm(signingValue);
      if (metadata.jwks && metadata.jwks_uri) {
        throw new Error("private_key_jwt clients cannot configure both JWKS and jwks_uri");
      }
      if (!metadata.jwks && !metadata.jwks_uri) {
        throw new Error("private_key_jwt clients require a JWKS");
      }
      if (metadata.jwks) projectOidcClientJwks(metadata.jwks, algorithm);
      if (metadata.jwks_uri) normalizeOidcJwksUri(metadata.jwks_uri, redirectOptions.allowInsecureHttp);
    } else {
      if (signingValue !== undefined || metadata.jwks !== undefined || metadata.jwks_uri !== undefined) {
        throw new Error("asymmetric client authentication fields require private_key_jwt");
      }
      if (metadata.client_secret !== undefined && (
        typeof metadata.client_secret !== "string" ||
        metadata.client_secret.length === 0 ||
        metadata.client_secret.length > 4096 ||
        /[\u0000-\u001f\u007f]/u.test(metadata.client_secret)
      )) {
        throw new Error("client secret is invalid");
      }
      if (authMethod === "none" && metadata.client_secret !== undefined) {
        throw new Error("public clients must not have a client secret");
      }
      if (authMethod !== "none" && (typeof metadata.client_secret !== "string" || metadata.client_secret.length === 0)) {
        throw new Error("confidential clients require a client secret");
      }
    }
  } catch (error) {
    if (error instanceof errors.InvalidClientMetadata) throw error;
    throw new errors.InvalidClientMetadata(error instanceof Error ? error.message : "client metadata violates policy");
  }
}

function normalizeProviderSigningAlgorithm(value: unknown): OidcProviderSigningAlgorithm {
  if (typeof value !== "string" || !OIDC_CLIENT_AUTH_SIGNING_ALGORITHMS.includes(value as OidcProviderSigningAlgorithm)) {
    throw new Error("[getbrick-idaas] OIDC signing algorithm is invalid");
  }
  return value as OidcProviderSigningAlgorithm;
}

function prioritizeStaticOidcClients(
  adapter: AdapterFactory | undefined,
  staticClientIds: ReadonlySet<string>,
): AdapterFactory | undefined {
  if (adapter === undefined || staticClientIds.size === 0) return adapter;
  const wrapped = ((model: string): Adapter => {
    const base = adapter(model);
    if (model !== "Client") return base;
    const delegated = Object.create(base) as Adapter;
    Object.defineProperty(delegated, "find", {
      configurable: true,
      enumerable: true,
      value: async (id: string): Promise<AdapterPayload | undefined> => {
        if (typeof id === "string" && staticClientIds.has(id)) return undefined;
        const result = await base.find(id);
        return result ?? undefined;
      },
      writable: true,
    });
    return delegated;
  }) as AdapterFactory;
  const readiness = (adapter as AdapterFactory & { ready?: () => boolean | Promise<boolean> }).ready;
  if (typeof readiness === "function") {
    Object.defineProperty(wrapped, "ready", {
      configurable: true,
      enumerable: true,
      value: () => readiness.call(adapter),
      writable: false,
    });
  }
  return wrapped;
}

function isProviderClientId(value: string): boolean {
  return value.length > 0 && value.length <= 512 && value === value.trim() && !/\s/u.test(value) && !/[\u0000-\u001f\u007f]/u.test(value);
}

function readClientMarker(value: unknown, key: string): unknown {
  if (typeof value !== "object" || value === null) return undefined;
  return (value as Record<string, unknown>)[key];
}

interface ProviderContextSummary {
  clientId?: string;
  grantId?: string;
}

function readProviderContext(value: unknown): ProviderContextSummary {
  const root = isRecord(value) ? value : {};
  const oidc = isRecord(root.oidc) ? root.oidc : root;
  const client = isRecord(oidc.client) ? oidc.client : undefined;
  const clientId = firstString(client?.clientId, client?.client_id, oidc.clientId, oidc.client_id);
  const entities = isRecord(oidc.entities) ? oidc.entities : undefined;
  const grant = entities && isRecord(entities.Grant) ? entities.Grant : undefined;
  const interaction = isRecord(oidc.interaction) ? oidc.interaction : undefined;
  const grantId = firstString(oidc.grantId, oidc.grant_id, interaction?.grantId, grant?.grantId, grant?.id);
  return {
    ...(clientId === undefined ? {} : { clientId }),
    ...(grantId === undefined ? {} : { grantId }),
  };
}

function readProviderRequestedClaims(value: unknown): string[] {
  if (!isRecord(value)) return [];
  return [...new Set(Object.keys(value).filter((claim) => isValidOidcClaimName(claim)))].slice(0, 256);
}

function firstString(...values: unknown[]): string | undefined {
  for (const value of values) {
    if (typeof value === "string" && value.length > 0 && value.length <= 512 && !/[\u0000-\u001f\u007f\s]/u.test(value)) return value;
  }
  return undefined;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function normalizeConsentIdentifier(value: string | undefined): string | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== "string" || value.length === 0 || value.length > 512 || value !== value.trim() || /[\u0000-\u001f\u007f\s]/u.test(value)) {
    throw new Error("[getbrick-idaas] OIDC consent binding identifier is invalid");
  }
  return value;
}

function hasConsentResult(value: unknown): boolean {
  return typeof value === "object" && value !== null && Object.prototype.hasOwnProperty.call(value, "consent");
}

function assertCookieKeys(keys: string[]): void {
  validateOidcCookieKeys(keys);
}

function unique(values: string[]): string[] {
  return [...new Set(values)];
}
