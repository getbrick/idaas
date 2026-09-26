import { betterAuth, type BetterAuthOptions, type BetterAuthPlugin } from "better-auth";
import {
  createAuthorizationURL,
  refreshAccessToken,
  validateAuthorizationCode,
  type OAuthIdTokenConfig,
  type OAuthProvider,
} from "better-auth/oauth2";
import { admin, organization, twoFactor } from "better-auth/plugins";
import { phoneNumber } from "better-auth/plugins/phone-number";
import { createLocalJWKSet, jwtVerify, type JSONWebKeySet, type JWTPayload } from "jose";
import {
  OIDC_ID_TOKEN_SIGNING_ALGORITHMS,
  type OidcDiscoveryMetadata,
  type OidcIdTokenSigningAlgorithm,
  type OidcResolvedProvider,
} from "@getbrick/idaas-contracts";
import type {
  OidcProviderEndpointResolver,
  OidcProviderEndpointResolverInput,
} from "./oidc/contracts.js";
import type { IdaasConfig, IdaasConfigInput } from "./config.js";
import { defineIdaasConfig, validateIdaasConfig } from "./config.js";
import { buildTableMap } from "./tables.js";
import { createAuditDatabaseHooks, type DatabaseHooks } from "./audit.js";

export type EmailSenderType = "verification" | "password-reset";

export interface EmailSenderPayload {
  to: string;
  type: EmailSenderType;
  url: string;
  expiresAt: Date;
}

export type EmailSender = (payload: EmailSenderPayload) => void | Promise<void>;

type AuthBeforeHook = NonNullable<NonNullable<BetterAuthOptions["hooks"]>["before"]>;

const EMAIL_VERIFICATION_EXPIRES_IN_SECONDS = 3600;
const PASSWORD_RESET_EXPIRES_IN_SECONDS = 3600;
const MAX_AUTH_URL_LENGTH = 4096;
const UNSAFE_URL_CHARACTERS = /[\s\u0000-\u001f\u007f-\u009f]/u;
const CALLBACK_URL_ERROR = "[getbrick-idaas] callback URL is not trusted";
const EMAIL_DELIVERY_ERROR = "[getbrick-idaas] email delivery failed";
const OIDC_FETCH_TIMEOUT_MS = 5_000;
const OIDC_MAX_RESPONSE_BYTES = 1_048_576;
const OIDC_JWKS_CACHE_TTL_MS = 300_000;
const OIDC_MAX_ID_TOKEN_LENGTH = 1_048_576;
const OIDC_MAX_ACCESS_TOKEN_LENGTH = 16_384;
const OIDC_CLOCK_SKEW_SECONDS = 60;
const OIDC_REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);

type OidcEndpointResolverRequest = OidcProviderEndpointResolverInput & {
  allowedIdTokenAlgorithms?: readonly OidcIdTokenSigningAlgorithm[];
  requireHttps?: boolean;
};

export interface OidcProviderEndpointResolverOptions {
  fetch?: typeof globalThis.fetch;
  timeoutMs?: number;
  maxResponseBytes?: number;
}

export interface OidcProviderEndpointResolverPort extends OidcProviderEndpointResolver {
  resolve(input: OidcEndpointResolverRequest): Promise<OidcResolvedProvider>;
}

type OidcFailureKind =
  | "configuration"
  | "timeout"
  | "network"
  | "redirect"
  | "content_type"
  | "response_too_large"
  | "provider_error"
  | "invalid_response"
  | "invalid_token"
  | "subject_mismatch";

type OidcTransportFailure = Exclude<OidcFailureKind, "configuration" | "invalid_token" | "subject_mismatch">;

class OidcProviderError extends Error {
  readonly code: OidcFailureKind;
  readonly retryable: boolean;

  constructor(providerId: string, operation: string, kind: OidcFailureKind, retryable = false) {
    super(formatOidcProviderError(providerId, operation, kind));
    this.name = "OidcProviderError";
    this.code = kind;
    this.retryable = retryable;
  }
}

class OidcTransportError extends Error {
  readonly kind: OidcTransportFailure;
  readonly retryable: boolean;

  constructor(kind: OidcTransportFailure, retryable = false) {
    super(kind);
    this.name = "OidcTransportError";
    this.kind = kind;
    this.retryable = retryable;
  }
}

type RawOidcProviderOptions = {
  jwksUri?: string;
  allowedIdTokenAlgorithms?: readonly OidcIdTokenSigningAlgorithm[];
};

type IdaasConfigInputWithOidcFields = IdaasConfigInput & {
  oidc?: IdaasConfigInput["oidc"] & {
    rp?: NonNullable<IdaasConfigInput["oidc"]>["rp"] & {
      providers?: Array<NonNullable<NonNullable<NonNullable<IdaasConfigInput["oidc"]>["rp"]>["providers"]>[number] & RawOidcProviderOptions>;
    };
  };
};

export interface CreateIdaasInput {
  config: IdaasConfigInputWithOidcFields;
  database: BetterAuthOptions["database"];
  auditSink?: (event: { event: string; userId?: string; detail?: Record<string, unknown>; occurredAt: string }) => void | Promise<void>;
  emailSender?: EmailSender;
  extraOptions?: Partial<BetterAuthOptions>;
  oidcRpClientSecrets?: Record<string, string>;
  oidcProviderEndpointResolver?: OidcProviderEndpointResolver;
  oidcEndpointResolver?: OidcProviderEndpointResolver;
  smsSender?: (payload: { phone: string; code: string }) => Promise<void>;
  phoneValidator?: (phone: string) => boolean | Promise<boolean>;
}

type HookFunction = (...args: any[]) => any;

export function createIdaas(input: CreateIdaasInput) {
  const rawOidcProviderOptions = readRawOidcProviderOptions(input.config);
  const config: IdaasConfig = defineIdaasConfig(input.config);
  validateIdaasConfig(configForPresetValidation(config));
  validateEmailRuntime(config, input.emailSender);
  const emailSender = input.emailSender;
  const emailVerification = {
    sendOnSignUp: config.email.sendOnSignUp,
    sendOnSignIn: false,
    expiresIn: EMAIL_VERIFICATION_EXPIRES_IN_SECONDS,
    ...(emailSender
      ? {
          sendVerificationEmail: createEmailSenderCallback(
            emailSender,
            "verification",
            EMAIL_VERIFICATION_EXPIRES_IN_SECONDS,
          ),
        }
      : {}),
  };
  const emailAndPassword = {
    enabled: true,
    minPasswordLength: config.password.minLength,
    disableSignUp: !config.registration.publicSignUp,
    requireEmailVerification: config.email.requireEmailVerification,
    resetPasswordTokenExpiresIn: PASSWORD_RESET_EXPIRES_IN_SECONDS,
    ...(config.email.resetPasswordEnabled && emailSender
      ? {
          sendResetPassword: createEmailSenderCallback(
            emailSender,
            "password-reset",
            PASSWORD_RESET_EXPIRES_IN_SECONDS,
          ),
        }
      : {}),
  };
  const tables = buildTableMap({
    prefix: config.tables.prefix,
    overrides: config.tables.overrides,
  });

  const auditHooks: DatabaseHooks = config.audit.enabled
    ? createAuditDatabaseHooks(
        input.auditSink ?? config.audit.sink ?? defaultAuditSink,
        undefined,
        { redactPersonalData: config.audit.redactPersonalData },
      )
    : {};

  const corePlugins: BetterAuthPlugin[] = [];
  if (config.features.admin) {
    corePlugins.push(admin());
  }
  if (config.features.twoFactor) {
    corePlugins.push(twoFactor({ twoFactorTable: tables.twoFactor }));
  }
  if (config.features.phoneNumber) {
    if (!input.smsSender) {
      throw new Error(
        "[getbrick-idaas] features.phoneNumber requires an smsSender callback: ({ phone, code }) => Promise<void>",
      );
    }
    corePlugins.push(
      phoneNumber({
        otpLength: config.phoneNumber.otpLength,
        expiresIn: config.phoneNumber.otpExpiresInSeconds,
        requireVerification: config.phoneNumber.requireVerification,
        sendOTP: ({ phoneNumber: phone, code }) => input.smsSender!({ phone, code }),
        sendPasswordResetOTP: ({ phoneNumber: phone, code }) => input.smsSender!({ phone, code }),
        phoneNumberValidator: input.phoneValidator,
        ...(config.phoneNumber.signUpOnVerification
          ? { signUpOnVerification: { getTempEmail: (phone: string) => `phone-${phone}@users.getbrick.local` } }
          : {}),
      }),
    );
  }
  if (config.features.organization) {
    corePlugins.push(
      organization({
        schema: {
          organization: { modelName: tables.organization },
          member: { modelName: tables.member },
          invitation: { modelName: tables.invitation },
        },
      }),
    );
  }
  const oidcPlugins = createOidcRpPlugins(
    config,
    input.oidcRpClientSecrets,
    input.oidcProviderEndpointResolver ?? input.oidcEndpointResolver,
    rawOidcProviderOptions,
  );

  const options: Partial<BetterAuthOptions> = {
    appName: config.appName,
    baseURL: config.baseURL,
    secret: config.secret,
    trustedOrigins: config.trustedOrigins,
    database: input.database,
    emailAndPassword,
    emailVerification,
    session: {
      modelName: tables.session,
      expiresIn: config.session.expiresInDays * 86400,
      updateAge: config.session.refreshIntervalDays * 86400,
      storeSessionInDatabase: config.session.storeInDatabase,
    },
    user: {
      modelName: tables.user,
      additionalFields: config.features.phoneNumber
        ? {
            phoneNumber: { type: "string", required: false, unique: true, returned: true },
            phoneNumberVerified: { type: "boolean", required: false, returned: true, input: false },
          }
        : undefined,
    },
    account: {
      modelName: tables.account,
      encryptOAuthTokens: true,
      skipStateCookieCheck: false,
      storeStateStrategy: "database",
      accountLinking: {
        disableImplicitLinking: true,
        requireLocalEmailVerified: true,
        allowDifferentEmails: false,
        allowUnlinkingAll: false,
      },
    },
    verification: {
      modelName: tables.verification,
    },
    advanced: {
      cookiePrefix: "getbrick",
    },
    hooks: {
      before: createCallbackGuard(config),
    },
    databaseHooks: auditHooks as BetterAuthOptions["databaseHooks"],
    rateLimit: {
      enabled: true,
      window: config.lockout.windowSeconds,
      max: config.lockout.maxAttempts,
      customRules: {
        "/sign-up/*": { window: config.lockout.windowSeconds, max: config.lockout.maxAttempts },
        "/sign-in/*": { window: config.lockout.windowSeconds, max: config.lockout.maxAttempts },
        "/change-password": { window: config.lockout.windowSeconds, max: config.lockout.maxAttempts },
        "/change-email": { window: config.lockout.windowSeconds, max: config.lockout.maxAttempts },
      },
    },
  };

  const {
    plugins: extraPlugins,
    databaseHooks: extraDatabaseHooks,
    hooks: extraHooks,
    ...safeExtraOptions
  } = (input.extraOptions ?? {}) as Partial<BetterAuthOptions> & Record<string, unknown>;
  const merged = deepMerge(options, safeExtraOptions) as BetterAuthOptions;
  protectCoreOptions(merged, options);
  const mergedHooks = mergeAuthHooks(options.hooks, extraHooks);
  if (mergedHooks) {
    setEntry(merged as Record<string, unknown>, "hooks", mergedHooks);
  }
  merged.plugins = [
    ...corePlugins,
    ...oidcPlugins,
    ...(Array.isArray(extraPlugins) ? extraPlugins : []),
  ];
  merged.databaseHooks = mergeDatabaseHooks(
    options.databaseHooks,
    extraDatabaseHooks,
  ) as BetterAuthOptions["databaseHooks"];
  setEntry(merged as Record<string, unknown>, "logger", createSafeLogger(merged.logger));

  return betterAuth(merged);
}

function configForPresetValidation(config: IdaasConfig): IdaasConfig {
  if (config.profile !== "production" || !config.oidc.rp.enabled) return config;
  let changed = false;
  const providers = config.oidc.rp.providers.map((provider) => {
    if (provider.discoveryUrl === undefined || provider.userInfoUrl !== undefined) return provider;
    changed = true;
    return { ...provider, userInfoUrl: provider.discoveryUrl };
  });
  if (!changed) return config;
  return {
    ...config,
    oidc: {
      ...config.oidc,
      rp: {
        ...config.oidc.rp,
        providers,
      },
    },
  };
}

function readRawOidcProviderOptions(
  config: IdaasConfigInputWithOidcFields,
): ReadonlyMap<string, RawOidcProviderOptions> {
  const output = new Map<string, RawOidcProviderOptions>();
  const oidc = isRecord(config) ? config.oidc : undefined;
  const rp = isRecord(oidc) ? oidc.rp : undefined;
  const providers = isRecord(rp) ? rp.providers : undefined;
  if (!Array.isArray(providers)) return output;
  for (const provider of providers) {
    if (!isRecord(provider) || typeof provider.providerId !== "string") continue;
    const jwksUri = typeof provider.jwksUri === "string" ? provider.jwksUri : undefined;
    const rawAlgorithms = provider.allowedIdTokenAlgorithms;
    const allowedIdTokenAlgorithms = Array.isArray(rawAlgorithms)
      ? [...rawAlgorithms] as OidcIdTokenSigningAlgorithm[]
      : undefined;
    if (jwksUri !== undefined || allowedIdTokenAlgorithms !== undefined) {
      output.set(provider.providerId, { jwksUri, allowedIdTokenAlgorithms });
    }
  }
  return output;
}

function createOidcRpPlugins(
  config: IdaasConfig,
  clientSecrets: Record<string, string> | undefined,
  endpointResolver: OidcProviderEndpointResolver | undefined,
  rawProviderOptions: ReadonlyMap<string, RawOidcProviderOptions>,
): BetterAuthPlugin[] {
  if (!config.oidc.rp.enabled) return [];
  const providerInputs = config.oidc.rp.providers.map((provider) => {
    const clientSecret = clientSecrets?.[provider.providerId] ?? provider.clientSecret;
    if (provider.tokenEndpointAuth !== "none" && !clientSecret) {
      throw new Error(
        `[getbrick-idaas] OIDC RP provider ${provider.providerId} requires a client secret`,
      );
    }
    if (provider.tokenEndpointAuth === "none" && clientSecret) {
      throw new Error(
        `[getbrick-idaas] OIDC RP provider ${provider.providerId} must not configure a client secret with tokenEndpointAuth=none`,
      );
    }
    return { provider, clientSecret };
  });
  const resolver = endpointResolver ?? createOidcProviderEndpointResolver();
  return [{
    id: "generic-oauth",
    init: async (ctx) => {
      const resolvedProviders = await Promise.all(providerInputs.map(async ({ provider, clientSecret }) => {
        const request = createOidcResolverRequest(provider, config, rawProviderOptions.get(provider.providerId));
        let resolved: OidcResolvedProvider;
        try {
          resolved = await resolver.resolve(request);
        } catch (error) {
          if (error instanceof OidcProviderError) throw error;
          throw new OidcProviderError(provider.providerId, "endpoint resolution", "configuration");
        }
        return {
          clientSecret,
          provider,
          resolved: normalizeResolvedOidcProvider(resolved, request),
        };
      }));
      const socialProviders = resolvedProviders.map(({ provider, clientSecret, resolved }) =>
        createResolvedOidcProvider(provider, clientSecret, resolved, config),
      );
      return {
        context: {
          socialProviders: [...socialProviders, ...ctx.socialProviders],
        },
      };
    },
  }];
}

function createOidcResolverRequest(
  provider: IdaasConfig["oidc"]["rp"]["providers"][number],
  config: IdaasConfig,
  rawOptions: RawOidcProviderOptions | undefined,
): OidcEndpointResolverRequest {
  if (typeof provider.issuer !== "string" || provider.issuer.length === 0) {
    throw new OidcProviderError(provider.providerId, "issuer", "configuration");
  }
  const jwksUri = rawOptions?.jwksUri ?? readOptionalProviderField(provider, "jwksUri");
  const allowedIdTokenAlgorithms = rawOptions?.allowedIdTokenAlgorithms ?? readOptionalProviderAlgorithms(provider);
  const explicitValues = [
    provider.authorizationUrl,
    provider.tokenUrl,
    provider.userInfoUrl,
    jwksUri,
    provider.endSessionEndpoint,
  ];
  const hasExplicitEndpoint = explicitValues.some((value) => value !== undefined);
  const discoveryUrl = provider.discoveryUrl ?? (
    hasExplicitEndpoint
      ? undefined
      : `${provider.issuer.replace(/\/+$/u, "")}/.well-known/openid-configuration`
  );
  const trustedEndpointOrigins = [
    getExactOrigin(provider.issuer),
    ...config.trustedOrigins.map((origin) => getExactOrigin(origin)),
  ].filter((value): value is string => value !== undefined);
  return {
    providerId: provider.providerId,
    issuer: provider.issuer,
    discoveryUrl,
    authorizationUrl: provider.authorizationUrl,
    tokenUrl: provider.tokenUrl,
    userInfoUrl: provider.userInfoUrl,
    jwksUri,
    endSessionEndpoint: provider.endSessionEndpoint,
    trustedEndpointOrigins,
    allowInsecureHttp: config.profile !== "production",
    requireHttps: config.profile === "production",
    allowedIdTokenAlgorithms,
  };
}

function createResolvedOidcProvider(
  provider: IdaasConfig["oidc"]["rp"]["providers"][number],
  clientSecret: string | undefined,
  resolved: OidcResolvedProvider,
  config: IdaasConfig,
): OAuthProvider<Record<string, unknown>> {
  const jwks = createOidcJwksCache(resolved.endpoints.jwks, provider.providerId);
  const tokenEndpointAuth = { method: provider.tokenEndpointAuth } as const;
  const verifyIdToken = async (token: string, nonce?: string): Promise<boolean> => {
    try {
      await verifyOidcIdToken(resolved, token, provider.clientId, nonce, jwks, provider.providerId);
      return true;
    } catch {
      return false;
    }
  };
  const idToken: OAuthIdTokenConfig = { verify: verifyIdToken };
  const oauthProvider: OAuthProvider<Record<string, unknown>> = {
    id: provider.providerId,
    name: provider.name ?? provider.providerId,
    issuer: resolved.issuer,
    accountSubject: ({ profile }) => {
      const subject = profile.sub;
      if (typeof subject !== "string" || subject.length === 0 || subject.length > 512 || /[\u0000-\u001f\u007f]/u.test(subject)) {
        throw new OidcProviderError(provider.providerId, "subject", "subject_mismatch");
      }
      return subject;
    },
    requiresIdTokenNonce: true,
    idToken,
    createAuthorizationURL: async (data) => createAuthorizationURL({
      id: provider.providerId,
      options: {
        clientId: provider.clientId,
        clientSecret,
        redirectURI: provider.redirectURI,
      },
      authorizationEndpoint: resolved.endpoints.authorization,
      state: data.state,
      codeVerifier: data.codeVerifier,
      scopes: uniqueStrings([...(data.scopes ?? []), ...provider.scopes]),
      redirectURI: data.redirectURI,
      nonce: data.idTokenNonce,
      responseType: "code",
    }),
    validateAuthorizationCode: async (data) => validateAuthorizationCode({
      code: data.code,
      codeVerifier: data.codeVerifier,
      deviceId: data.deviceId,
      redirectURI: data.redirectURI,
      options: {
        clientId: provider.clientId,
        clientSecret,
        redirectURI: provider.redirectURI,
      },
      tokenEndpoint: resolved.endpoints.token,
      authentication: provider.tokenEndpointAuth === "client_secret_basic" ? "basic" : "post",
      tokenEndpointAuth,
    }),
    getUserInfo: async (tokens) => {
      try {
        const idTokenValue = tokens.idToken;
        const accessToken = tokens.accessToken;
        if (!isSafeOidcToken(idTokenValue, OIDC_MAX_ID_TOKEN_LENGTH) || !isSafeOidcToken(accessToken, OIDC_MAX_ACCESS_TOKEN_LENGTH)) {
          throw new OidcProviderError(provider.providerId, "ID token", "invalid_token");
        }
        const verifiedClaims = await verifyOidcIdToken(
          resolved,
          idTokenValue,
          provider.clientId,
          tokens.expectedIdTokenNonce,
          jwks,
          provider.providerId,
        );
        const userInfo = await fetchOidcUserInfo(resolved.endpoints.userInfo, accessToken, provider.providerId);
        if (userInfo.sub !== verifiedClaims.sub) {
          throw new OidcProviderError(provider.providerId, "userinfo", "subject_mismatch");
        }
        const normalized: Record<string, unknown> = {
          ...userInfo,
          sub: verifiedClaims.sub,
          emailVerified: userInfo.emailVerified === true || userInfo.email_verified === true,
        };
        if (typeof userInfo.image !== "string" && typeof userInfo.picture === "string") {
          normalized.image = userInfo.picture;
        }
        if (typeof normalized.name !== "string" && typeof userInfo.preferred_username === "string") {
          normalized.name = userInfo.preferred_username;
        }
        return {
          user: {
            email: typeof normalized.email === "string" ? normalized.email : undefined,
            emailVerified: normalized.emailVerified === true,
            image: typeof normalized.image === "string" ? normalized.image : undefined,
            name: typeof normalized.name === "string" ? normalized.name : undefined,
          },
          data: normalized,
        };
      } catch (error) {
        if (error instanceof OidcProviderError) return null;
        throw error;
      }
    },
    refreshAccessToken: async (refreshToken) => refreshAccessToken({
      refreshToken,
      options: {
        clientId: provider.clientId,
        clientSecret,
      },
      tokenEndpoint: resolved.endpoints.token,
      authentication: provider.tokenEndpointAuth === "client_secret_basic" ? "basic" : "post",
      tokenEndpointAuth,
    }),
    createEndSessionURL: async (data) => {
      if (!resolved.endpoints.endSession) return null;
      const url = new URL(resolved.endpoints.endSession);
      if (data.idToken) url.searchParams.set("id_token_hint", data.idToken);
      const postLogoutRedirectURI = data.postLogoutRedirectURI ?? provider.postLogoutRedirectURI;
      if (postLogoutRedirectURI) {
        url.searchParams.set("post_logout_redirect_uri", postLogoutRedirectURI);
        url.searchParams.set("client_id", provider.clientId);
        if (data.state) url.searchParams.set("state", data.state);
      } else if (!data.idToken) {
        url.searchParams.set("client_id", provider.clientId);
      }
      return url;
    },
    disableImplicitSignUp: provider.disableImplicitSignUp,
    disableSignUp: provider.disableSignUp || !config.registration.publicSignUp,
     options: {
       disableIdTokenSignIn: true,
       disableSignUp: provider.disableSignUp || !config.registration.publicSignUp,
       requireEmailVerification: provider.requireEmailVerification,
     },

  };
  return oauthProvider;
}

export function createOidcProviderEndpointResolver(
  options: OidcProviderEndpointResolverOptions = {},
): OidcProviderEndpointResolverPort {
  const timeoutMs = normalizeOidcLimit(options.timeoutMs, OIDC_FETCH_TIMEOUT_MS, 1, 120_000);
  const maxResponseBytes = normalizeOidcLimit(options.maxResponseBytes, OIDC_MAX_RESPONSE_BYTES, 1, 16 * 1_048_576);
  const fetcher = options.fetch;
  return {
    async resolve(input) {
      try {
        return await resolveOidcProvider(input, { fetcher, maxResponseBytes, timeoutMs });
      } catch (error) {
        if (error instanceof OidcProviderError) throw error;
        if (error instanceof OidcTransportError) {
          throw new OidcProviderError(readProviderId(input), "endpoint resolution", error.kind, error.retryable);
        }
        throw new OidcProviderError(readProviderId(input), "endpoint resolution", "configuration");
      }
    },
  };
}

async function resolveOidcProvider(
  input: OidcProviderEndpointResolverInput,
  transport: OidcResolverTransport,
): Promise<OidcResolvedProvider> {
  const providerId = readProviderId(input);
  const request = input as OidcEndpointResolverRequest;
  const issuer = validateOidcIssuer(request.issuer, providerId, request);
  const explicitValues = [
    request.authorizationUrl,
    request.tokenUrl,
    request.userInfoUrl,
    request.jwksUri,
    request.endSessionEndpoint,
  ];
  const hasExplicitEndpoint = explicitValues.some((value) => value !== undefined);
  if (request.discoveryUrl !== undefined && hasExplicitEndpoint) {
    throw new OidcProviderError(providerId, "discovery and explicit endpoints", "configuration");
  }
  if (request.discoveryUrl === undefined && !hasExplicitEndpoint) {
    throw new OidcProviderError(providerId, "endpoints", "configuration");
  }
  if (request.discoveryUrl !== undefined) {
    const discoveryUrl = validateOidcEndpoint(
      request.discoveryUrl,
      providerId,
      "discovery endpoint",
      request,
      false,
    );
    let metadata: unknown;
    try {
      metadata = await fetchOidcJson(
        discoveryUrl,
        { headers: { Accept: "application/json" } },
        providerId,
        "discovery",
        transport,
      );
    } catch (error) {
      throw mapOidcTransportError(providerId, "discovery", error);
    }
    if (!isRecord(metadata) || metadata.issuer !== issuer) {
      throw new OidcProviderError(providerId, "discovery issuer", "invalid_response");
    }
    const resolvedMetadata = metadata as unknown as OidcDiscoveryMetadata;
    const algorithms = readDiscoveryAlgorithms(resolvedMetadata, providerId, request);
    return normalizeResolvedOidcProvider({
      contractVersion: 1,
      issuer,
      source: "discovery",
      endpoints: {
        authorization: requiredMetadataEndpoint(resolvedMetadata.authorization_endpoint, providerId, "authorization"),
        token: requiredMetadataEndpoint(resolvedMetadata.token_endpoint, providerId, "token"),
        userInfo: requiredMetadataEndpoint(resolvedMetadata.userinfo_endpoint, providerId, "userinfo"),
        jwks: requiredMetadataEndpoint(resolvedMetadata.jwks_uri, providerId, "jwks"),
        ...(resolvedMetadata.end_session_endpoint === undefined
          ? {}
          : { endSession: requiredMetadataEndpoint(resolvedMetadata.end_session_endpoint, providerId, "end session") }),
      },
      allowedIdTokenAlgorithms: algorithms,
    }, { ...request, issuer, discoveryUrl });
  }
  if (
    typeof request.authorizationUrl !== "string" ||
    typeof request.tokenUrl !== "string" ||
    typeof request.userInfoUrl !== "string" ||
    typeof request.jwksUri !== "string"
  ) {
    throw new OidcProviderError(providerId, "explicit endpoints", "configuration");
  }
  return normalizeResolvedOidcProvider({
    contractVersion: 1,
    issuer,
    source: "explicit",
    endpoints: {
      authorization: request.authorizationUrl,
      token: request.tokenUrl,
      userInfo: request.userInfoUrl,
      jwks: request.jwksUri,
      ...(request.endSessionEndpoint === undefined ? {} : { endSession: request.endSessionEndpoint }),
    },
    allowedIdTokenAlgorithms: request.allowedIdTokenAlgorithms ?? ["RS256"],
  }, { ...request, issuer });
}

function normalizeResolvedOidcProvider(
  value: OidcResolvedProvider,
  request: OidcEndpointResolverRequest,
): OidcResolvedProvider {
  const providerId = request.providerId;
  if (!isRecord(value) || value.contractVersion !== 1 || value.issuer !== request.issuer) {
    throw new OidcProviderError(providerId, "resolved provider", "configuration");
  }
  if (value.source !== "discovery" && value.source !== "explicit") {
    throw new OidcProviderError(providerId, "resolved provider source", "configuration");
  }
  const expectedSource: "discovery" | "explicit" = request.discoveryUrl === undefined ? "explicit" : "discovery";
  if (value.source !== expectedSource) {
    throw new OidcProviderError(providerId, "resolved provider source", "configuration");
  }
  if (!isRecord(value.endpoints)) {
    throw new OidcProviderError(providerId, "resolved provider endpoints", "configuration");
  }
  const endpoints = value.endpoints as Record<string, unknown>;
  const authorization = validateOidcEndpoint(endpoints.authorization, providerId, "authorization endpoint", request, false);
  const token = validateOidcEndpoint(endpoints.token, providerId, "token endpoint", request, false);
  const userInfo = validateOidcEndpoint(endpoints.userInfo, providerId, "userinfo endpoint", request, false);
  const jwks = validateOidcEndpoint(endpoints.jwks, providerId, "jwks endpoint", request, true);
  const endSession = endpoints.endSession === undefined
    ? undefined
    : validateOidcEndpoint(endpoints.endSession, providerId, "end session endpoint", request, false);
  const algorithms = normalizeOidcAlgorithms(value.allowedIdTokenAlgorithms, providerId);
  return Object.freeze({
    contractVersion: 1,
    issuer: request.issuer,
    source: value.source,
    endpoints: Object.freeze({
      authorization,
      token,
      userInfo,
      jwks,
      ...(endSession === undefined ? {} : { endSession }),
    }),
    allowedIdTokenAlgorithms: Object.freeze(algorithms),
  });
}

function validateOidcIssuer(
  value: unknown,
  providerId: string,
  request: OidcEndpointResolverRequest,
): string {
  if (typeof value !== "string" || value.length === 0) {
    throw new OidcProviderError(providerId, "issuer", "configuration");
  }
  validateOidcEndpoint(value, providerId, "issuer", request, false, true);
  return value;
}

function validateOidcEndpoint(
  value: unknown,
  providerId: string,
  label: string,
  request: OidcEndpointResolverRequest,
  allowQuery: boolean,
  skipTrustedOrigin = false,
): string {
  if (typeof value !== "string" || value.length === 0 || value.length > 4096 || hasUnsafeURLText(value)) {
    throw new OidcProviderError(providerId, label, "configuration");
  }
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new OidcProviderError(providerId, label, "configuration");
  }
  if (
    (parsed.protocol !== "https:" && parsed.protocol !== "http:") ||
    parsed.origin === "null" ||
    parsed.hostname === "" ||
    parsed.username !== "" ||
    parsed.password !== "" ||
    parsed.hash !== "" ||
    (!allowQuery && parsed.search !== "")
  ) {
    throw new OidcProviderError(providerId, label, "configuration");
  }
  if ((request.requireHttps || !request.allowInsecureHttp) && parsed.protocol !== "https:") {
    throw new OidcProviderError(providerId, label, "configuration");
  }
  if (!skipTrustedOrigin && !getTrustedEndpointOrigins(request).has(parsed.origin)) {
    throw new OidcProviderError(providerId, `${label} origin`, "configuration");
  }
  return value;
}

function getTrustedEndpointOrigins(request: OidcEndpointResolverRequest): Set<string> {
  const origins = new Set<string>();
  for (const value of request.trustedEndpointOrigins) {
    if (
      typeof value !== "string" ||
      value.length === 0 ||
      value.includes("*") ||
      value.includes("?") ||
      hasUnsafeURLText(value)
    ) {
      throw new OidcProviderError(request.providerId, "trusted endpoint origins", "configuration");
    }
    let parsed: URL;
    try {
      parsed = new URL(value);
    } catch {
      throw new OidcProviderError(request.providerId, "trusted endpoint origins", "configuration");
    }
    if (
      (parsed.protocol !== "https:" && parsed.protocol !== "http:") ||
      parsed.origin === "null" ||
      parsed.username !== "" ||
      parsed.password !== "" ||
      parsed.search !== "" ||
      parsed.pathname !== "/" ||
      parsed.hash !== ""
    ) {
      throw new OidcProviderError(request.providerId, "trusted endpoint origins", "configuration");
    }
    origins.add(parsed.origin);
  }
  return origins;
}

function requiredMetadataEndpoint(value: unknown, providerId: string, label: string): string {
  if (typeof value !== "string" || value.length === 0) {
    throw new OidcProviderError(providerId, `${label} endpoint`, "invalid_response");
  }
  return value;
}

function readDiscoveryAlgorithms(
  metadata: OidcDiscoveryMetadata,
  providerId: string,
  request: OidcEndpointResolverRequest,
): readonly OidcIdTokenSigningAlgorithm[] {
  if (metadata.id_token_signing_alg_values_supported === undefined) {
    if (request.requireHttps || !request.allowInsecureHttp) {
      throw new OidcProviderError(providerId, "discovery algorithms", "invalid_response");
    }
    return ["RS256"];
  }
  return normalizeOidcAlgorithms(metadata.id_token_signing_alg_values_supported, providerId);
}

function normalizeOidcAlgorithms(
  value: unknown,
  providerId: string,
): readonly OidcIdTokenSigningAlgorithm[] {
  if (!Array.isArray(value) || value.length === 0) {
    throw new OidcProviderError(providerId, "ID token algorithms", "configuration");
  }
  const algorithms: OidcIdTokenSigningAlgorithm[] = [];
  for (const algorithm of value) {
    if (typeof algorithm !== "string" || !OIDC_ID_TOKEN_SIGNING_ALGORITHMS.includes(algorithm as OidcIdTokenSigningAlgorithm)) {
      throw new OidcProviderError(providerId, "ID token algorithms", "configuration");
    }
    if (!algorithms.includes(algorithm as OidcIdTokenSigningAlgorithm)) {
      algorithms.push(algorithm as OidcIdTokenSigningAlgorithm);
    }
  }
  return Object.freeze(algorithms);
}

type OidcResolverTransport = {
  fetcher?: typeof globalThis.fetch;
  timeoutMs: number;
  maxResponseBytes: number;
};

async function fetchOidcJson(
  url: string,
  init: RequestInit,
  providerId: string,
  operation: string,
  transport: OidcResolverTransport,
): Promise<unknown> {
  const controller = new AbortController();
  let timeout: ReturnType<typeof setTimeout> | undefined;
  try {
    const fetcher = transport.fetcher ?? globalThis.fetch;
    const operationPromise = Promise.resolve().then(async () => {
      const response = await fetcher(url, {
        ...init,
        redirect: "manual",
        signal: controller.signal,
      });
      if (response.redirected || response.type === "opaqueredirect" || OIDC_REDIRECT_STATUSES.has(response.status) || (response.status >= 300 && response.status < 400)) {
        throw new OidcTransportError("redirect");
      }
      if (response.status < 200 || response.status >= 300) {
        throw new OidcTransportError("provider_error", response.status === 408 || response.status === 429 || response.status >= 500);
      }
      if (!isJsonContentType(response.headers.get("content-type"))) {
        throw new OidcTransportError("content_type");
      }
      const text = await readBoundedResponseText(response, transport.maxResponseBytes);
      try {
        return JSON.parse(text);
      } catch {
        throw new OidcTransportError("invalid_response");
      }
    }).catch((error) => {
      if (error instanceof OidcTransportError) throw error;
      throw new OidcTransportError(controller.signal.aborted ? "timeout" : "network", true);
    });
    const timeoutPromise = new Promise<never>((_, reject) => {
      timeout = setTimeout(() => {
        controller.abort();
        reject(new OidcTransportError("timeout", true));
      }, transport.timeoutMs);
    });
    return await Promise.race([operationPromise, timeoutPromise]);
  } catch (error) {
    if (error instanceof OidcProviderError) throw error;
    if (error instanceof OidcTransportError) {
      throw mapOidcTransportError(providerId, operation, error);
    }
    throw new OidcProviderError(providerId, operation, controller.signal.aborted ? "timeout" : "invalid_response");
  } finally {
    if (timeout !== undefined) clearTimeout(timeout);
  }
}

async function readBoundedResponseText(response: Response, maxBytes: number): Promise<string> {
  const contentLength = response.headers.get("content-length");
  if (contentLength !== null) {
    if (!/^\d+$/u.test(contentLength)) throw new OidcTransportError("invalid_response");
    if (Number(contentLength) > maxBytes) throw new OidcTransportError("response_too_large");
  }
  const body = response.body;
  if (body && typeof body.getReader === "function") {
    const reader = body.getReader();
    const chunks: Uint8Array[] = [];
    let size = 0;
    try {
      while (true) {
        const chunk = await reader.read();
        if (chunk.done) break;
        const value = chunk.value instanceof Uint8Array ? chunk.value : new Uint8Array(chunk.value);
        size += value.byteLength;
        if (size > maxBytes) {
          await reader.cancel();
          throw new OidcTransportError("response_too_large");
        }
        chunks.push(value);
      }
    } catch (error) {
      if (error instanceof OidcTransportError) throw error;
      throw new OidcTransportError("network");
    } finally {
      reader.releaseLock();
    }
    const bytes = new Uint8Array(size);
    let offset = 0;
    for (const chunk of chunks) {
      bytes.set(chunk, offset);
      offset += chunk.byteLength;
    }
    try {
      return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    } catch {
      throw new OidcTransportError("invalid_response");
    }
  }
  let buffer: ArrayBuffer;
  try {
    buffer = await response.arrayBuffer();
  } catch {
    throw new OidcTransportError("network");
  }
  if (buffer.byteLength > maxBytes) throw new OidcTransportError("response_too_large");
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(buffer);
  } catch {
    throw new OidcTransportError("invalid_response");
  }
}

function isJsonContentType(value: string | null): boolean {
  if (!value) return false;
  const mediaType = value.split(";", 1)[0]?.trim().toLowerCase();
  return mediaType === "application/json" || Boolean(mediaType?.endsWith("+json"));
}

function createOidcJwksCache(endpoint: string, providerId: string): () => Promise<JSONWebKeySet> {
  let cached: { expiresAt: number; value: JSONWebKeySet } | undefined;
  let pending: Promise<JSONWebKeySet> | undefined;
  return async () => {
    if (cached && cached.expiresAt > Date.now()) return cached.value;
    if (pending) return pending;
    pending = fetchOidcJson(
      endpoint,
      { headers: { Accept: "application/json" } },
      providerId,
      "jwks",
      { maxResponseBytes: OIDC_MAX_RESPONSE_BYTES, timeoutMs: OIDC_FETCH_TIMEOUT_MS },
    ).then((value) => {
      if (!isRecord(value) || !Array.isArray(value.keys) || value.keys.length === 0 || value.keys.length > 32) {
        throw new OidcProviderError(providerId, "jwks response", "invalid_response");
      }
      const result = value as unknown as JSONWebKeySet;
      cached = { expiresAt: Date.now() + OIDC_JWKS_CACHE_TTL_MS, value: result };
      return result;
    }).catch((error) => {
      pending = undefined;
      if (error instanceof OidcProviderError) throw error;
      if (error instanceof OidcTransportError) {
        throw new OidcProviderError(providerId, "jwks", error.kind, error.retryable);
      }
      throw new OidcProviderError(providerId, "jwks", "invalid_response");
    });
    const result = await pending;
    pending = undefined;
    return result;
  };
}

async function verifyOidcIdToken(
  resolved: OidcResolvedProvider,
  token: string,
  clientId: string,
  expectedNonce: string | undefined,
  getJwks: () => Promise<JSONWebKeySet>,
  providerId: string,
): Promise<JWTPayload> {
  let jwks: JSONWebKeySet;
  try {
    jwks = await getJwks();
  } catch (error) {
    if (error instanceof OidcProviderError) throw error;
    throw new OidcProviderError(providerId, "ID token", "invalid_token");
  }
  let verified: { payload: JWTPayload };
  try {
    verified = await jwtVerify(token, createLocalJWKSet(jwks), {
      issuer: resolved.issuer,
      audience: clientId,
      algorithms: [...resolved.allowedIdTokenAlgorithms],
    });
  } catch {
    throw new OidcProviderError(providerId, "ID token", "invalid_token");
  }
  const subject = verified.payload.sub;
  const now = Math.floor(Date.now() / 1000);
  const expiresAt = verified.payload.exp;
  const issuedAt = verified.payload.iat;
  const audiences = typeof verified.payload.aud === "string"
    ? [verified.payload.aud]
    : Array.isArray(verified.payload.aud)
      ? verified.payload.aud
      : [];
  const authorizedParty = verified.payload.azp;
  if (
    typeof subject !== "string" ||
    subject.length === 0 ||
    subject.length > 512 ||
    /[\u0000-\u001f\u007f]/u.test(subject) ||
    typeof expiresAt !== "number" ||
    !Number.isFinite(expiresAt) ||
    expiresAt <= now ||
    typeof issuedAt !== "number" ||
    !Number.isFinite(issuedAt) ||
    issuedAt < 0 ||
    issuedAt > now + OIDC_CLOCK_SKEW_SECONDS ||
    issuedAt >= expiresAt ||
    !audiences.includes(clientId) ||
    (authorizedParty !== undefined && (typeof authorizedParty !== "string" || authorizedParty !== clientId)) ||
    (audiences.length > 1 && authorizedParty === undefined) ||
    typeof expectedNonce !== "string" ||
    expectedNonce.length === 0 ||
    verified.payload.nonce !== expectedNonce
  ) {
    throw new OidcProviderError(providerId, "ID token", "invalid_token");
  }
  return verified.payload;
}

async function fetchOidcUserInfo(
  endpoint: string,
  accessToken: string,
  providerId: string,
): Promise<Record<string, unknown>> {
  if (!isSafeOidcToken(accessToken, OIDC_MAX_ACCESS_TOKEN_LENGTH)) {
    throw new OidcProviderError(providerId, "userinfo", "invalid_token");
  }
  let value: unknown;
  try {
    value = await fetchOidcJson(
      endpoint,
      {
        method: "GET",
        headers: {
          Accept: "application/json",
          Authorization: `Bearer ${accessToken}`,
        },
      },
      providerId,
      "userinfo",
      { maxResponseBytes: OIDC_MAX_RESPONSE_BYTES, timeoutMs: OIDC_FETCH_TIMEOUT_MS },
    );
  } catch (error) {
    if (error instanceof OidcProviderError) throw error;
    if (error instanceof OidcTransportError) {
      throw new OidcProviderError(providerId, "userinfo", error.kind, error.retryable);
    }
    throw new OidcProviderError(providerId, "userinfo", "invalid_response");
  }
  if (!isRecord(value)) throw new OidcProviderError(providerId, "userinfo", "invalid_response");
  return value;
}

function isSafeOidcToken(value: unknown, maxLength: number): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= maxLength && !/[\u0000-\u0020\u007f]/u.test(value);
}

function normalizeOidcLimit(value: number | undefined, fallback: number, minimum: number, maximum: number): number {
  if (value === undefined) return fallback;
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new Error("[getbrick-idaas] OIDC resolver limit is invalid");
  }
  return value;
}

function readProviderId(input: unknown): string {
  if (!isRecord(input) || typeof input.providerId !== "string" || input.providerId.length === 0) return "unknown";
  return input.providerId;
}

function readOptionalProviderField(provider: object, key: string): string | undefined {
  const value = (provider as Record<string, unknown>)[key];
  return typeof value === "string" ? value : undefined;
}

function readOptionalProviderAlgorithms(
  provider: object,
): readonly OidcIdTokenSigningAlgorithm[] | undefined {
  const value = (provider as Record<string, unknown>).allowedIdTokenAlgorithms;
  if (!Array.isArray(value)) return undefined;
  return value as readonly OidcIdTokenSigningAlgorithm[];
}

function getExactOrigin(value: string): string | undefined {
  if (value.includes("*") || value.includes("?") || hasUnsafeURLText(value)) return undefined;
  try {
    const parsed = new URL(value);
    if (parsed.origin === "null" || parsed.username !== "" || parsed.password !== "" || parsed.hash !== "" || parsed.search !== "") return undefined;
    return parsed.origin;
  } catch {
    return undefined;
  }
}

function uniqueStrings(values: readonly string[]): string[] {
  return [...new Set(values)];
}

function mapOidcTransportError(providerId: string, operation: string, error: unknown): OidcProviderError {
  if (error instanceof OidcProviderError) return error;
  if (error instanceof OidcTransportError) {
    return new OidcProviderError(providerId, operation, error.kind, error.retryable);
  }
  return new OidcProviderError(providerId, operation, "invalid_response");
}

function formatOidcProviderError(providerId: string, operation: string, kind: OidcFailureKind): string {
  const suffix: Record<OidcFailureKind, string> = {
    configuration: "configuration is invalid",
    timeout: "request timed out",
    network: "request failed",
    redirect: "response redirected",
    content_type: "response has an invalid content type",
    response_too_large: "response is too large",
    provider_error: "request failed",
    invalid_response: "response is invalid",
    invalid_token: "ID token is invalid",
    subject_mismatch: "subject is invalid",
  };
  return `[getbrick-idaas] OIDC RP provider ${providerId} ${operation} ${suffix[kind]}`;
}

function createSafeLogger(input: unknown): Record<string, unknown> {
  const source = isRecord(input) ? input : undefined;
  const output = source ? copyRecord(source) : {};
  const originalLog = typeof source?.log === "function"
    ? source.log as (...args: any[]) => void
    : undefined;
  setEntry(output, "log", (level: unknown, message: unknown) => {
    const safeMessage = typeof message === "string"
      ? redactLogText(message)
      : "[non-string log message]";
    if (originalLog) {
      try {
        originalLog(String(level), safeMessage);
      } catch {
        return;
      }
      return;
    }
    const method = level === "error" ? "error" : level === "warn" ? "warn" : "log";
    const logger = console[method] as (...args: any[]) => void;
    logger(`[getbrick-idaas] ${safeMessage}`);
  });
  return output;
}

function redactLogText(value: string): string {
  return value
    .replace(
      /((?:callbackURL|redirectTo|redirectURL|errorCallbackURL|newUserCallbackURL)\s*:\s*)[^\s,;]+/giu,
      "$1[redacted]",
    )
    .replace(
      /([?&](?:callbackURL|redirectTo|redirectURL|errorCallbackURL|newUserCallbackURL)=)[^&#\s]*/giu,
      "$1[redacted]",
    )
    .replace(
      /([?&](?:access[_-]?token|refresh[_-]?token|id[_-]?token|session[_-]?token|verification[_-]?token|reset[_-]?token|token|password|passwd|secret|code|code[_-]?verifier|nonce|state)=)[^&#\s]*/giu,
      "$1[redacted]",
    )
    .replace(
      /((?:access[_-]?token|refresh[_-]?token|id[_-]?token|session[_-]?token|verification[_-]?token|reset[_-]?token|token|password|passwd|secret|code|code[_-]?verifier|nonce|state)\s*[:=]\s*)(?:"[^"]*"|'[^']*'|[^\s,;]+)/giu,
      "$1[redacted]",
    )
    .replace(/\bBearer\s+[A-Za-z0-9._~+/=-]+/giu, "Bearer [redacted]")
    .replace(/(\/(?:verify-email|reset-password)\/)[^\s/?#]+/giu, "$1[redacted]");
}

function validateEmailRuntime(config: IdaasConfig, emailSender: EmailSender | undefined): void {
  if (emailSender !== undefined && typeof emailSender !== "function") {
    throw new Error("[getbrick-idaas] emailSender must be a function");
  }
  if (config.email.requireEmailVerification && !emailSender) {
    throw new Error(
      "[getbrick-idaas] email.requireEmailVerification requires an emailSender callback",
    );
  }
  if (config.profile === "production" && !emailSender) {
    throw new Error("[getbrick-idaas] production requires an emailSender callback");
  }
  if (config.email.resetPasswordEnabled && !emailSender) {
    throw new Error(
      "[getbrick-idaas] email.resetPasswordEnabled requires an emailSender callback",
    );
  }
  if (config.email.sendOnSignUp && !emailSender) {
    throw new Error("[getbrick-idaas] email.sendOnSignUp requires an emailSender callback");
  }
}

function createEmailSenderCallback(
  sender: EmailSender,
  type: EmailSenderType,
  expiresInSeconds: number,
): (data: { user: { email: string }; url: string }) => Promise<void> {
  return async (data) => {
    try {
      const email = data?.user?.email;
      const url = data?.url;
      if (typeof email !== "string" || email.length === 0 || !isSafeEmailActionURL(url)) {
        throw new Error(EMAIL_DELIVERY_ERROR);
      }
      const payload: EmailSenderPayload = {
        to: email,
        type,
        url,
        expiresAt: new Date(Date.now() + expiresInSeconds * 1000),
      };
      await sender(payload);
    } catch {
      throw new Error(EMAIL_DELIVERY_ERROR);
    }
  };
}

function isSafeEmailActionURL(value: unknown): value is string {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > MAX_AUTH_URL_LENGTH ||
    value.includes("#") ||
    hasUnsafeURLText(value)
  ) {
    return false;
  }
  const authority = value.match(/^https?:\/\/([^/?#]*)/iu)?.[1];
  if (!authority || authority.includes("@")) return false;
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    return false;
  }
  return (
    (parsed.protocol === "http:" || parsed.protocol === "https:") &&
    parsed.origin !== "null" &&
    parsed.hostname !== "" &&
    parsed.username === "" &&
    parsed.password === "" &&
    parsed.hash === "" &&
    parsed.href.length <= MAX_AUTH_URL_LENGTH
  );
}

function hasUnsafeURLText(value: string): boolean {
  if (/%(?![0-9a-f]{2})/iu.test(value)) return true;
  let decoded = value;
  for (let depth = 0; depth <= value.length; depth += 1) {
    if (UNSAFE_URL_CHARACTERS.test(decoded) || decoded.includes("\\")) return true;
    const next = decoded.replace(/%([0-9a-f]{2})/giu, (_, hex: string) =>
      String.fromCharCode(Number.parseInt(hex, 16)),
    );
    if (next === decoded) return false;
    decoded = next;
  }
  return true;
}

function createCallbackGuard(config: IdaasConfig): AuthBeforeHook {
  return async (ctx) => {
    const body = isRecord(ctx.body) ? ctx.body : undefined;
    const query = isRecord(ctx.query) ? ctx.query : undefined;
    const values: unknown[] = [];
    values.push(
      readField(body, "callbackURL"),
      readField(body, "redirectTo"),
      readField(body, "newUserCallbackURL"),
      readField(body, "errorCallbackURL"),
    );
    values.push(
      readField(query, "callbackURL"),
      readField(query, "redirectTo"),
      readField(query, "newUserCallbackURL"),
      readField(query, "errorCallbackURL"),
    );
    const request = ctx.request;
    if (isRequestLike(request)) {
      let requestURL: URL;
      try {
        requestURL = new URL(request.url);
      } catch {
        throw new Error(CALLBACK_URL_ERROR);
      }
      for (const key of [
        "callbackURL",
        "redirectTo",
        "newUserCallbackURL",
        "errorCallbackURL",
      ]) {
        const entries = requestURL.searchParams.getAll(key);
        if (entries.length > 1) throw new Error(CALLBACK_URL_ERROR);
        values.push(entries[0]);
      }
    }
    for (const value of values) {
      if (value !== undefined) assertSafeCallbackURL(value, config);
    }
  };
}

function assertSafeCallbackURL(value: unknown, config: IdaasConfig): void {
  if (typeof value !== "string" || value.length === 0 || value.length > MAX_AUTH_URL_LENGTH) {
    throw new Error(CALLBACK_URL_ERROR);
  }
  if (value !== value.trim() || hasUnsafeURLText(value)) {
    throw new Error(CALLBACK_URL_ERROR);
  }
  if (value.startsWith("/") && !value.startsWith("//")) {
    const path = value.split(/[?#]/u, 1)[0];
    let decodedPath: string;
    try {
      decodedPath = decodeURIComponent(path);
    } catch {
      throw new Error(CALLBACK_URL_ERROR);
    }
    if (/%2f|%5c/iu.test(path) || decodedPath.includes("\\") || decodedPath.split("/").includes("..")) {
      throw new Error(CALLBACK_URL_ERROR);
    }
    return;
  }
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error(CALLBACK_URL_ERROR);
  }
  if (
    (parsed.protocol !== "http:" && parsed.protocol !== "https:") ||
    parsed.origin === "null" ||
    parsed.username !== "" ||
    parsed.password !== ""
  ) {
    throw new Error(CALLBACK_URL_ERROR);
  }
  if (config.profile === "production" && parsed.protocol !== "https:") {
    throw new Error(CALLBACK_URL_ERROR);
  }
  if (!isAllowedOrigin(parsed.origin, config)) {
    throw new Error(CALLBACK_URL_ERROR);
  }
}

function isAllowedOrigin(origin: string, config: IdaasConfig): boolean {
  const patterns = [...config.trustedOrigins];
  if (config.baseURL) patterns.push(config.baseURL);
  return patterns.some((pattern) => matchesOriginPattern(origin, pattern, config.profile === "production"));
}

function matchesOriginPattern(origin: string, pattern: string, requireHttps: boolean): boolean {
  const normalizedPattern = pattern.trim();
  if (!normalizedPattern || /[\u0000-\u001f\u007f]/u.test(normalizedPattern)) return false;
  let parsedOrigin: URL;
  try {
    parsedOrigin = new URL(origin);
  } catch {
    return false;
  }
  if (normalizedPattern.includes("*") || normalizedPattern.includes("?")) {
    const wildcard = normalizedPattern.match(/^([a-z][a-z\d+.-]*:)?\/\/([^/]+)(?:\/.*)?$/iu);
    if (wildcard) {
      const scheme = wildcard[1]?.toLowerCase();
      if (requireHttps && parsedOrigin.protocol !== "https:") return false;
      if (scheme && parsedOrigin.protocol !== scheme) return false;
      return wildcardMatches(parsedOrigin.host, wildcard[2]);
    }
    if (normalizedPattern.includes("/") || requireHttps && parsedOrigin.protocol !== "https:") {
      return false;
    }
    return wildcardMatches(parsedOrigin.host, normalizedPattern);
  }
  try {
    const parsedPattern = new URL(
      normalizedPattern.includes("://") ? normalizedPattern : `https://${normalizedPattern}`,
    );
    if (requireHttps && parsedOrigin.protocol !== "https:") return false;
    return parsedPattern.origin === parsedOrigin.origin;
  } catch {
    return false;
  }
}

function wildcardMatches(value: string, pattern: string): boolean {
  let expression = "^";
  for (const character of pattern) {
    if (character === "*") expression += ".*";
    else if (character === "?") expression += ".";
    else expression += character.replace(/[\\^$+?.()|[\]{}]/gu, "\\$&");
  }
  try {
    return new RegExp(`${expression}$`, "iu").test(value);
  } catch {
    return false;
  }
}

function readField(record: Record<string, unknown> | undefined, key: string): unknown {
  if (!record || !Object.prototype.hasOwnProperty.call(record, key)) return undefined;
  try {
    return record[key];
  } catch {
    throw new Error(CALLBACK_URL_ERROR);
  }
}

function isRequestLike(value: unknown): value is { url: string } {
  return isRecord(value) && typeof value.url === "string";
}

function mergeAuthHooks(core: unknown, extra: unknown): Record<string, unknown> | undefined {
  const coreRecord = isRecord(core) ? core : undefined;
  const extraRecord = isRecord(extra) ? extra : undefined;
  if (!coreRecord && !extraRecord) return undefined;
  const out: Record<string, unknown> = {};
  if (coreRecord) for (const [key, value] of Object.entries(coreRecord)) setEntry(out, key, value);
  if (extraRecord) for (const [key, value] of Object.entries(extraRecord)) setEntry(out, key, value);
  const coreBefore = typeof coreRecord?.before === "function" ? coreRecord.before as HookFunction : undefined;
  const extraBefore = typeof extraRecord?.before === "function" ? extraRecord.before as HookFunction : undefined;
  const coreAfter = typeof coreRecord?.after === "function" ? coreRecord.after as HookFunction : undefined;
  const extraAfter = typeof extraRecord?.after === "function" ? extraRecord.after as HookFunction : undefined;
  if (coreBefore && extraBefore) setEntry(out, "before", composeHooks(coreBefore, extraBefore));
  else if (coreBefore) setEntry(out, "before", coreBefore);
  else if (extraBefore) setEntry(out, "before", extraBefore);
  if (coreAfter && extraAfter) setEntry(out, "after", composeHooks(coreAfter, extraAfter));
  else if (coreAfter) setEntry(out, "after", coreAfter);
  else if (extraAfter) setEntry(out, "after", extraAfter);
  return out;
}

function protectCoreOptions(
  merged: BetterAuthOptions,
  core: Partial<BetterAuthOptions>,
): void {
  const target = merged as Record<string, unknown>;
  const source = core as Record<string, unknown>;
  if (Object.prototype.hasOwnProperty.call(source, "database")) {
    setEntry(target, "database", source.database);
  }
  if (source.secret !== undefined) setEntry(target, "secret", source.secret);
  if (Object.prototype.hasOwnProperty.call(source, "baseURL")) {
    setEntry(target, "baseURL", source.baseURL);
  }
  if (Object.prototype.hasOwnProperty.call(source, "trustedOrigins")) {
    setEntry(target, "trustedOrigins", source.trustedOrigins);
  }
  protectObjectFields(target, "emailAndPassword", source.emailAndPassword, [
    "enabled",
    "minPasswordLength",
    "disableSignUp",
    "requireEmailVerification",
    "sendResetPassword",
    "resetPasswordTokenExpiresIn",
  ]);
  protectObjectFields(target, "emailVerification", source.emailVerification, [
    "sendVerificationEmail",
    "sendOnSignUp",
    "sendOnSignIn",
    "expiresIn",
  ]);
  const emailAndPassword = getObjectField(target, "emailAndPassword");
  if (
    emailAndPassword &&
    isRecord(source.emailAndPassword) &&
    !Object.prototype.hasOwnProperty.call(source.emailAndPassword, "sendResetPassword")
  ) {
    setEntry(emailAndPassword, "sendResetPassword", undefined);
  }
  const emailVerification = getObjectField(target, "emailVerification");
  if (
    emailVerification &&
    isRecord(source.emailVerification) &&
    !Object.prototype.hasOwnProperty.call(source.emailVerification, "sendVerificationEmail")
  ) {
    setEntry(emailVerification, "sendVerificationEmail", undefined);
  }
  protectObjectFields(target, "session", source.session, ["modelName", "expiresIn", "updateAge", "storeSessionInDatabase"]);
  protectObjectFields(target, "user", source.user, ["modelName"]);
  protectObjectFields(target, "account", source.account, [
    "modelName",
    "encryptOAuthTokens",
    "skipStateCookieCheck",
    "storeStateStrategy",
    "accountLinking",
  ]);
  protectObjectFields(target, "verification", source.verification, ["modelName"]);
  protectObjectFields(target, "advanced", source.advanced, ["cookiePrefix"]);

  const advanced = getObjectField(target, "advanced");
  if (advanced) {
    setEntry(advanced, "disableCSRFCheck", false);
    setEntry(advanced, "disableOriginCheck", false);
    const ipAddress = getObjectField(advanced, "ipAddress");
    if (ipAddress) setEntry(ipAddress, "disableIpTracking", false);
  }

  const coreRateLimit = isRecord(source.rateLimit) ? source.rateLimit : undefined;
  const rateLimit = getObjectField(target, "rateLimit") ?? (coreRateLimit ? copyRecord(coreRateLimit) : undefined);
  if (rateLimit && !getObjectField(target, "rateLimit")) setEntry(target, "rateLimit", rateLimit);
  if (rateLimit && coreRateLimit) {
    for (const key of ["enabled", "window", "max"]) {
      if (Object.prototype.hasOwnProperty.call(coreRateLimit, key)) {
        setEntry(rateLimit, key, coreRateLimit[key]);
      }
    }
    const extraRules = isRecord(rateLimit.customRules) ? rateLimit.customRules : undefined;
    const coreRules = isRecord(coreRateLimit.customRules) ? coreRateLimit.customRules : undefined;
    if (coreRules) {
      const rules = extraRules ? copyRecord(extraRules) : {};
      for (const [key, value] of Object.entries(coreRules)) setEntry(rules, key, value);
      setEntry(rateLimit, "customRules", rules);
    }
  }
}

function protectObjectFields(
  target: Record<string, unknown>,
  key: string,
  coreValue: unknown,
  protectedKeys: string[],
): void {
  if (!isRecord(coreValue)) return;
  const current = isRecord(target[key]) ? target[key] : copyRecord(coreValue);
  if (!isRecord(target[key])) setEntry(target, key, current);
  for (const protectedKey of protectedKeys) {
    if (Object.prototype.hasOwnProperty.call(coreValue, protectedKey)) {
      setEntry(current, protectedKey, coreValue[protectedKey]);
    }
  }
}

function mergeDatabaseHooks(core: unknown, extra: unknown): unknown {
  if (!isRecord(extra)) return core;
  if (!isRecord(core)) return extra;
  return mergeHookRecords(core, extra);
}

function mergeHookRecords(core: Record<string, unknown>, extra: Record<string, unknown>): Record<string, unknown> {
  const out = copyRecord(core);
  for (const [key, value] of Object.entries(extra)) {
    if (value === undefined || value === null) continue;
    const current = out[key];
    if (typeof current === "function" && typeof value === "function") {
      setEntry(out, key, composeHooks(current as HookFunction, value as HookFunction));
    } else if (isRecord(current) && isRecord(value)) {
      setEntry(out, key, mergeHookRecords(current, value));
    } else if (current === undefined && isHookValue(value)) {
      setEntry(out, key, value);
    }
  }
  return out;
}

function isHookValue(value: unknown): boolean {
  return typeof value === "function" || isRecord(value);
}

function composeHooks(first: HookFunction, second: HookFunction): HookFunction {
  return async function (this: unknown, ...args: any[]) {
    const firstResult = await first.apply(this, args);
    if (firstResult === false) return false;
    let nextArgs = args;
    if (isRecord(firstResult) && Object.prototype.hasOwnProperty.call(firstResult, "data") && isRecord(args[0])) {
      nextArgs = [{ ...args[0], ...(firstResult.data as Record<string, unknown>) }, ...args.slice(1)];
    }
    const secondResult = await second.apply(this, nextArgs);
    return secondResult === undefined ? firstResult : secondResult;
  };
}

function getObjectField(target: Record<string, unknown>, key: string): Record<string, unknown> | undefined {
  if (!isRecord(target[key])) return undefined;
  return target[key];
}

function copyRecord(value: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [key, entry] of Object.entries(value)) setEntry(out, key, entry);
  return out;
}

function setEntry(target: Record<string, unknown>, key: string, value: unknown): void {
  Object.defineProperty(target, key, {
    configurable: true,
    enumerable: true,
    value,
    writable: true,
  });
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function defaultAuditSink(event: { event: string; userId?: string; detail?: Record<string, unknown> }): void {
  console.info(`[getbrick-idaas] ${event.event}`, event);
}

function deepMerge<T>(base: T, override: Record<string, unknown>): T {
  const out: Record<string, unknown> = { ...(base as Record<string, unknown>) };
  for (const [key, value] of Object.entries(override)) {
    const current = out[key];
    if (
      value !== null &&
      typeof value === "object" &&
      !Array.isArray(value) &&
      current !== null &&
      typeof current === "object" &&
      !Array.isArray(current)
    ) {
      setEntry(out, key, deepMerge(current as Record<string, unknown>, value as Record<string, unknown>));
    } else {
      setEntry(out, key, value);
    }
  }
  return out as T;
}
