import type {
  OpenPlatformServiceClientVerifierPort,
} from "../../types.js";
import {
  OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES,
  isOpenPlatformOidcAdapterError,
  oidcAdapterError,
} from "./errors.js";
import {
  OidcVerificationCache,
  assertNotRevoked,
  cacheKey,
  defaultRevocation,
  dependencyReady,
  makeRevocationLookup,
  makeRevokeLookup,
  normalizeAllowedAlgorithms,
  normalizeAudience,
  normalizeCacheTtl,
  normalizeClaimNames,
  normalizeClockSkew,
  normalizeIdentifier,
  normalizeIssuer,
  normalizeMaxCacheEntries,
  normalizeMaxTokenLength,
  normalizeOidcHash,
  normalizeOidcMode,
  normalizeScopeList,
  resolveIdentity,
  validateCryptoPort,
  validateRevocationPort,
  validateSecretInput,
  validateVerifiedClaims,
  type VerifiedOidcClaims,
} from "./shared.js";
import { oidcTokenFingerprint } from "./revocation.js";
import type {
  OidcAdapterCredentialIdentity,
  OidcCacheInvalidationInput,
  OidcIdentityResolverPort,
  OidcRevokeInput,
  OidcServiceClientAdapterVerifierInput,
  OidcServiceClientAuthenticationMethod,
  OidcServiceClientJwtVerifierPort,
  OidcServiceClientVerifierAdapterOptions,
  OidcServiceClientVerifierAdapterPort,
} from "./contracts.js";

export class OpenPlatformOidcServiceClientVerifierAdapter
  implements OidcServiceClientVerifierAdapterPort {
  readonly productionReady: boolean;
  readonly readiness = (): Promise<boolean> => this.isReady();
  readonly authenticationMethod: OidcServiceClientAuthenticationMethod;
  private readonly mode: ReturnType<typeof normalizeOidcMode>;
  private readonly issuer: string;
  private readonly tenantId: string;
  private readonly applicationId: string;
  private readonly clientId: string;
  private readonly assertionAudience: string | undefined;
  private readonly requiredScopes: readonly string[];
  private readonly allowedScopes: readonly string[] | undefined;
  private readonly allowedAlgorithms: ReturnType<typeof normalizeAllowedAlgorithms>;
  private readonly jwtVerifier: OidcServiceClientJwtVerifierPort;
  private readonly identityResolver: OidcIdentityResolverPort | undefined;
  private readonly revocation: ReturnType<typeof validateRevocationPort>;
  private readonly clock: () => Date;
  private readonly cacheTtlMs: number;
  private readonly maxCacheEntries: number;
  private readonly maxTokenLength: number;
  private readonly clockSkewSeconds: number;
  private readonly requireNbf: boolean;
  private readonly claimNames: ReturnType<typeof normalizeClaimNames>;
  private readonly cache: OidcVerificationCache;

  constructor(options: OidcServiceClientVerifierAdapterOptions) {
    if (options === null || typeof options !== "object") {
      throw oidcAdapterError(OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.CONFIGURATION);
    }
    this.mode = normalizeOidcMode(options.mode);
    this.issuer = normalizeIssuer(options.issuer, this.mode);
    this.tenantId = normalizeIdentifier(options.tenantId, "tenantId");
    this.applicationId = normalizeIdentifier(options.applicationId, "applicationId");
    this.clientId = normalizeIdentifier(options.clientId, "clientId");
    this.authenticationMethod = normalizeAuthenticationMethod(
      options.authenticationMethod,
    );
    this.assertionAudience = this.authenticationMethod === "private_key_jwt"
      ? normalizeAudience(options.assertionAudience, "assertionAudience")
      : undefined;
    if (
      this.mode === "production" &&
      this.assertionAudience !== undefined &&
      /^http:/iu.test(this.assertionAudience)
    ) {
      throw oidcAdapterError(OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.CONFIGURATION);
    }
    this.requiredScopes = Object.freeze(
      normalizeScopeList(options.requiredScopes ?? [], "requiredScopes", false),
    );
    this.allowedScopes = options.allowedScopes === undefined
      ? undefined
      : Object.freeze(normalizeScopeList(options.allowedScopes, "allowedScopes", false));
    this.allowedAlgorithms = normalizeAllowedAlgorithms(options.allowedAlgorithms);
    this.jwtVerifier = validateCryptoPort<OidcServiceClientJwtVerifierPort>(
      options.jwtVerifier,
      "serviceClient",
    );
    this.identityResolver = validateIdentityResolver(options.identityResolver);
    this.revocation = validateRevocationPort(
      defaultRevocation(options.revocation),
    );
    if (options.clock !== undefined && typeof options.clock !== "function") {
      throw oidcAdapterError(OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.CONFIGURATION);
    }
    this.clock = options.clock ?? (() => new Date());
    this.cacheTtlMs = normalizeCacheTtl(options.cacheTtlMs);
    this.maxCacheEntries = normalizeMaxCacheEntries(options.maxCacheEntries);
    this.cache = new OidcVerificationCache(this.maxCacheEntries);
    this.maxTokenLength = normalizeMaxTokenLength(options.maxTokenLength);
    this.clockSkewSeconds = normalizeClockSkew(options.clockSkewSeconds);
    this.requireNbf = options.requireNbf ?? true;
    if (typeof this.requireNbf !== "boolean") {
      throw oidcAdapterError(OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.CONFIGURATION);
    }
    this.claimNames = normalizeClaimNames(options.claimNames);
    const identityProductionReady =
      this.identityResolver === undefined
        ? this.mode !== "production"
        : this.identityResolver.productionReady === true;
    const readinessConfigured =
      typeof this.jwtVerifier.readiness === "function" &&
      typeof this.revocation.readiness === "function" &&
      (this.identityResolver === undefined ||
        typeof this.identityResolver.readiness === "function");
    this.productionReady =
      this.jwtVerifier.productionReady === true &&
      this.revocation.productionReady === true &&
      identityProductionReady &&
      (this.mode !== "production" || readinessConfigured);
    if (
      this.mode === "production" &&
      (this.identityResolver === undefined ||
        !this.productionReady ||
        this.revocation.revoke === undefined ||
        (this.authenticationMethod === "private_key_jwt" &&
          this.assertionAudience === undefined))
    ) {
      throw oidcAdapterError(OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.CONFIGURATION);
    }
  }

  async verify(
    input: OidcServiceClientAdapterVerifierInput,
  ): Promise<OidcAdapterCredentialIdentity> {
    const requestId = normalizeIdentifier(input?.requestId, "requestId");
    const inputClientId = normalizeIdentifier(input?.clientId, "clientId");
    if (inputClientId !== this.clientId) {
      throw oidcAdapterError(OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.CLIENT_MISMATCH);
    }
    const audience = normalizeAudience(input?.audience);
    const assertion = validateSecretInput(input?.assertion, this.maxTokenLength);
    const nowDate = this.clockDate();
    const now = Math.floor(nowDate.getTime() / 1000);
    const fingerprint = oidcTokenFingerprint(assertion);
    const cacheAudience = audience;
    const key = cacheKey({
      issuer: this.issuer,
      audience: cacheAudience,
      tenantId: this.tenantId,
      clientId: this.clientId,
      tokenFingerprint: fingerprint,
    });
    const cached = this.cache.get(key, nowDate.getTime());
    if (cached !== undefined) {
      await assertNotRevoked(
        this.revocation,
        makeRevocationLookup({
          issuer: this.issuer,
          tenantId: this.tenantId,
          clientId: this.clientId,
          tokenFingerprint: fingerprint,
          ...(cached.tokenIdHash === undefined
            ? {}
            : { tokenIdHash: cached.tokenIdHash }),
          ...(cached.sessionIdHash === undefined
            ? {}
            : { sessionIdHash: cached.sessionIdHash }),
        }),
      );
      return cached.identity;
    }
    const tokenAudience = this.assertionAudience ?? audience;
    const tokenIssuer = this.authenticationMethod === "private_key_jwt"
      ? this.clientId
      : this.issuer;
    let result: Awaited<ReturnType<OidcServiceClientJwtVerifierPort["verify"]>>;
    try {
      result = await this.jwtVerifier.verify({
        token: assertion,
        issuer: tokenIssuer,
        audience: tokenAudience,
        algorithms: this.allowedAlgorithms,
        now,
        requestId,
        clientId: this.clientId,
        authenticationMethod: this.authenticationMethod,
      });
    } catch (error) {
      if (isOpenPlatformOidcAdapterError(error)) throw error;
      throw oidcAdapterError(
        OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.VERIFIER_UNAVAILABLE,
        true,
      );
    }
    const tokenRequiredScopes = this.authenticationMethod === "private_key_jwt"
      ? []
      : this.requiredScopes;
    const verified = validateVerifiedClaims({
      result,
      issuer: tokenIssuer,
      expectedAudience: tokenAudience,
      ...(this.authenticationMethod === "private_key_jwt"
        ? { principalAudience: audience, clientIdFallback: this.clientId }
        : {}),
      expectedTenantId: this.tenantId,
      expectedApplicationId: this.applicationId,
      expectedClientId: this.clientId,
      requiredScopes: tokenRequiredScopes,
      allowedAlgorithms: this.allowedAlgorithms,
      now,
      clockSkewSeconds: this.clockSkewSeconds,
      requireNbf: this.requireNbf,
       scopeRequired: false,
      claimNames: this.claimNames,
      token: assertion,
    });
    if (this.authenticationMethod === "private_key_jwt") {
      if (
        verified.principalClaims.issuer !== this.clientId ||
        verified.principalClaims.subject !== this.clientId ||
        verified.tokenIdHash === undefined
      ) {
        throw oidcAdapterError(OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.INVALID_TOKEN);
      }
    } else {
      assertClientCredentialsGrant(verified.raw);
    }
    await this.assertActive(verified);
    const identity = await resolveIdentity({
      authenticationType: "serviceClient",
      requestId,
      expectedAudience: audience,
      expectedTenantId: this.tenantId,
      expectedApplicationId: this.applicationId,
      expectedClientId: this.clientId,
      now,
      requiredScopes: this.requiredScopes,
      scopeMode: this.authenticationMethod === "private_key_jwt"
        ? "intersect-token-or-allowlist"
        : "intersect-token",
      ...(this.allowedScopes === undefined
        ? {}
        : { allowedScopes: this.allowedScopes }),
      claims: verified.raw,
      principalClaims: verified.principalClaims,
      claimNames: this.claimNames,
      ...(this.identityResolver === undefined
        ? {}
        : { resolver: this.identityResolver }),
    });
    this.cache.set(
      key,
      identity,
      Math.min(
        Date.parse(identity.expiresAt),
        nowDate.getTime() + this.cacheTtlMs,
      ),
      {
        ...(typeof result.protectedHeader?.kid === "string"
          ? { keyId: result.protectedHeader.kid }
          : {}),
        ...(verified.tokenIdHash === undefined
          ? {}
          : { tokenIdHash: verified.tokenIdHash }),
        ...(verified.sessionIdHash === undefined
          ? {}
          : { sessionIdHash: verified.sessionIdHash }),
      },
    );
    return identity;
  }

  async isReady(): Promise<boolean> {
    const checks = await Promise.all([
      dependencyReady(this.jwtVerifier),
      dependencyReady(this.revocation),
      dependencyReady(this.identityResolver),
    ]);
    return checks.every(Boolean);
  }

  async invalidateCache(input: OidcCacheInvalidationInput = {}): Promise<void> {
    const normalized = normalizeInvalidationInput(input);
    this.cache.invalidate(normalized);
    if (this.jwtVerifier.invalidateCache !== undefined) {
      try {
        await this.jwtVerifier.invalidateCache({
          ...(normalized.issuer === undefined ? {} : { issuer: normalized.issuer }),
          ...(normalized.keyId === undefined ? {} : { keyId: normalized.keyId }),
        });
      } catch {
        throw oidcAdapterError(
          OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.VERIFIER_UNAVAILABLE,
          true,
        );
      }
    }
  }

  async invalidate(input: OidcCacheInvalidationInput = {}): Promise<void> {
    await this.invalidateCache(input);
  }

  async clearCache(): Promise<void> {
    await this.invalidateCache();
  }

  async revoke(input: OidcRevokeInput): Promise<void> {
    const lookup = makeRevokeLookup({
      issuer: normalizeIssuer(input?.issuer, this.mode),
      tenantId: normalizeIdentifier(input?.tenantId, "tenantId"),
      clientId: normalizeIdentifier(input?.clientId, "clientId"),
      ...(input?.tokenId === undefined ? {} : { tokenId: input.tokenId }),
      ...(input?.sessionId === undefined ? {} : { sessionId: input.sessionId }),
      ...(input?.tokenFingerprint === undefined
        ? {}
        : { tokenFingerprint: input.tokenFingerprint }),
    });
    if (this.revocation.revoke === undefined) {
      throw oidcAdapterError(OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.CONFIGURATION);
    }
    try {
      await this.revocation.revoke(lookup, input?.reason ?? "token_revoked");
      if (this.revocation.invalidate !== undefined) {
        await this.revocation.invalidate({
          ...(lookup.tokenIdHash === undefined
            ? {}
            : { tokenIdHash: lookup.tokenIdHash }),
          ...(lookup.sessionIdHash === undefined
            ? {}
            : { sessionIdHash: lookup.sessionIdHash }),
          ...(lookup.tokenFingerprint === undefined
            ? {}
            : { tokenFingerprint: lookup.tokenFingerprint }),
        });
      }
    } catch {
      throw oidcAdapterError(
        OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.VERIFIER_UNAVAILABLE,
        true,
      );
    }
    await this.invalidateCache({
      ...(lookup.tokenIdHash === undefined ? {} : { tokenIdHash: lookup.tokenIdHash }),
      ...(lookup.sessionIdHash === undefined ? {} : { sessionIdHash: lookup.sessionIdHash }),
      ...(lookup.tokenFingerprint === undefined
        ? {}
        : { tokenFingerprint: lookup.tokenFingerprint }),
    });
  }

  async revokeToken(input: OidcRevokeInput): Promise<void> {
    await this.revoke(input);
  }

  cacheSize(): number {
    return this.cache.size();
  }

  private async assertActive(verified: VerifiedOidcClaims): Promise<void> {
    await assertNotRevoked(
      this.revocation,
      makeRevocationLookup({
        issuer: this.issuer,
        tenantId: this.tenantId,
        clientId: this.clientId,
        tokenFingerprint: verified.tokenFingerprint,
        ...(verified.tokenIdHash === undefined
          ? {}
          : { tokenIdHash: verified.tokenIdHash }),
        ...(verified.sessionIdHash === undefined
          ? {}
          : { sessionIdHash: verified.sessionIdHash }),
      }),
    );
  }

  private clockDate(): Date {
    const value = this.clock();
    if (!(value instanceof Date) || !Number.isFinite(value.getTime())) {
      throw oidcAdapterError(OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.CONFIGURATION);
    }
    return value;
  }
}

export function createOpenPlatformOidcServiceClientVerifierAdapter(
  options: OidcServiceClientVerifierAdapterOptions,
): OpenPlatformOidcServiceClientVerifierAdapter {
  return new OpenPlatformOidcServiceClientVerifierAdapter(options);
}

function normalizeAuthenticationMethod(
  value: unknown,
): OidcServiceClientAuthenticationMethod {
  if (value !== "private_key_jwt" && value !== "client_credentials") {
    throw oidcAdapterError(OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.CONFIGURATION);
  }
  return value;
}

function validateIdentityResolver(
  value: OidcIdentityResolverPort | undefined,
): OidcIdentityResolverPort | undefined {
  if (value === undefined) return undefined;
  if (
    value === null ||
    typeof value !== "object" ||
    typeof value.resolve !== "function" ||
    (value.productionReady !== undefined && typeof value.productionReady !== "boolean") ||
    (value.readiness !== undefined && typeof value.readiness !== "function")
  ) {
    throw oidcAdapterError(OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.CONFIGURATION);
  }
  return value;
}

function normalizeInvalidationInput(
  input: OidcCacheInvalidationInput,
): OidcCacheInvalidationInput {
  if (input === null || typeof input !== "object") {
    throw oidcAdapterError(OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.CONFIGURATION);
  }
  return Object.freeze({
    ...(input.issuer === undefined
      ? {}
      : { issuer: normalizeIssuer(input.issuer, "test") }),
    ...(input.keyId === undefined ? {} : { keyId: normalizeIdentifier(input.keyId, "keyId") }),
    ...(input.tokenFingerprint === undefined
      ? {}
      : { tokenFingerprint: normalizeOidcHash(input.tokenFingerprint, "tokenFingerprint") }),
    ...(input.tokenIdHash === undefined
      ? {}
      : { tokenIdHash: normalizeOidcHash(input.tokenIdHash, "tokenIdHash") }),
    ...(input.sessionIdHash === undefined
      ? {}
      : { sessionIdHash: normalizeOidcHash(input.sessionIdHash, "sessionIdHash") }),
    ...(input.tenantId === undefined
      ? {}
      : { tenantId: normalizeIdentifier(input.tenantId, "tenantId") }),
    ...(input.clientId === undefined
      ? {}
      : { clientId: normalizeIdentifier(input.clientId, "clientId") }),
  });
}

function assertClientCredentialsGrant(claims: Readonly<Record<string, unknown>>): void {
  if (claims.grant_type !== "client_credentials") {
    throw oidcAdapterError(OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.INVALID_TOKEN);
  }
}
