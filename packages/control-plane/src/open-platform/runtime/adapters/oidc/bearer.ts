import type {
  OpenPlatformOidcBearerVerifierPort,
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
  OidcBearerAdapterVerifierInput,
  OidcBearerJwtVerifierPort,
  OidcBearerVerifierAdapterOptions,
  OidcCacheInvalidationInput,
  OidcIdentityResolverPort,
  OidcRevokeInput,
} from "./contracts.js";
import { normalizeOidcMode as normalizeRuntimeMode } from "./shared.js";

export class OpenPlatformOidcBearerVerifierAdapter
  implements OpenPlatformOidcBearerVerifierPort {
  readonly productionReady: boolean;
  readonly readiness = (): Promise<boolean> => this.isReady();
  private readonly mode: ReturnType<typeof normalizeOidcMode>;
  private readonly issuer: string;
  private readonly tenantId: string;
  private readonly applicationId: string;
  private readonly clientId: string;
  private readonly requiredScopes: readonly string[];
  private readonly allowedAlgorithms: ReturnType<typeof normalizeAllowedAlgorithms>;
  private readonly jwtVerifier: OidcBearerJwtVerifierPort;
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

  constructor(options: OidcBearerVerifierAdapterOptions) {
    if (options === null || typeof options !== "object") {
      throw oidcAdapterError(OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.CONFIGURATION);
    }
    this.mode = normalizeRuntimeMode(options.mode);
    this.issuer = normalizeIssuer(options.issuer, this.mode);
    this.tenantId = normalizeIdentifier(options.tenantId, "tenantId");
    this.applicationId = normalizeIdentifier(options.applicationId, "applicationId");
    this.clientId = normalizeIdentifier(options.clientId, "clientId");
    this.requiredScopes = Object.freeze(
      normalizeScopeList(options.requiredScopes ?? [], "requiredScopes", false),
    );
    this.allowedAlgorithms = normalizeAllowedAlgorithms(options.allowedAlgorithms);
    this.jwtVerifier = validateCryptoPort<OidcBearerJwtVerifierPort>(
      options.jwtVerifier,
      "bearer",
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
        this.revocation.revoke === undefined)
    ) {
      throw oidcAdapterError(OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.CONFIGURATION);
    }
  }

  async verify(
    input: OidcBearerAdapterVerifierInput,
  ): Promise<OidcAdapterCredentialIdentity> {
    const requestId = normalizeIdentifier(
      input?.requestId,
      "requestId",
    );
    const audience = normalizeAudience(input?.audience);
    const token = validateSecretInput(input?.token, this.maxTokenLength);
    const currentDate = this.clockDate();
    const now = Math.floor(currentDate.getTime() / 1000);
    const nowMilliseconds = currentDate.getTime();
    const fingerprint = tokenFingerprint(token);
    const key = cacheKey({
      issuer: this.issuer,
      audience,
      tenantId: this.tenantId,
      clientId: this.clientId,
      tokenFingerprint: fingerprint,
    });
    const cached = this.cache.get(key, nowMilliseconds);
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
    let result: Awaited<ReturnType<OidcBearerJwtVerifierPort["verify"]>>;
    try {
      result = await this.jwtVerifier.verify({
        token,
        issuer: this.issuer,
        audience,
        algorithms: this.allowedAlgorithms,
        now,
        requestId,
      });
    } catch (error) {
      if (isOpenPlatformOidcAdapterError(error)) throw error;
      throw oidcAdapterError(
        OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.VERIFIER_UNAVAILABLE,
        true,
      );
    }
    const verified = validateVerifiedClaims({
      result,
      issuer: this.issuer,
      expectedAudience: audience,
      expectedTenantId: this.tenantId,
      expectedApplicationId: this.applicationId,
      expectedClientId: this.clientId,
      requiredScopes: this.requiredScopes,
      allowedAlgorithms: this.allowedAlgorithms,
      now,
      clockSkewSeconds: this.clockSkewSeconds,
      requireNbf: this.requireNbf,
      scopeRequired: true,
      claimNames: this.claimNames,
      token,
    });
    await this.assertActive(verified);
    const identity = await resolveIdentity({
      authenticationType: "oidcBearer",
      requestId,
      expectedAudience: audience,
      expectedTenantId: this.tenantId,
      expectedApplicationId: this.applicationId,
      expectedClientId: this.clientId,
      now,
      requiredScopes: this.requiredScopes,
      scopeMode: "intersect-token",
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
        nowMilliseconds + this.cacheTtlMs,
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

export function createOpenPlatformOidcBearerVerifierAdapter(
  options: OidcBearerVerifierAdapterOptions,
): OpenPlatformOidcBearerVerifierAdapter {
  return new OpenPlatformOidcBearerVerifierAdapter(options);
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

function tokenFingerprint(value: string): string {
  return oidcTokenFingerprint(value);
}
