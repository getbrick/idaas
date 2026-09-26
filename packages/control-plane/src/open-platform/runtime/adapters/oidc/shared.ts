import type { OpenPlatformAdapterCredentialIdentity } from "../../types.js";
import {
  OIDC_RUNTIME_SIGNING_ALGORITHMS,
  type OidcClaimNames,
  type OidcIdentityResolutionInput,
  type OidcIdentityResolverPort,
  type OidcJwtVerificationResult,
  type OidcRuntimeAuthenticationType,
  type OidcRuntimeMode,
  type OidcRuntimeSigningAlgorithm,
  type OidcRevocationLookup,
  type OidcRevocationPort,
  type OidcSanitizedPrincipalClaims,
  type OidcAdapterCredentialIdentity,
  type OidcScopeResolutionMode,
} from "./contracts.js";
import {
  OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES,
  oidcAdapterError,
} from "./errors.js";
import {
  InMemoryOidcRevocationStore,
  oidcTokenFingerprint,
  oidcValueHash,
} from "./revocation.js";

const MAX_TOKEN_LENGTH = 16_384;
const MAX_CLAIM_VALUE_LENGTH = 512;
const MAX_AUDIENCES = 64;
const MAX_SCOPES = 256;
const MAX_CACHE_TTL_MS = 300_000;
const DEFAULT_CACHE_TTL_MS = 30_000;
const DEFAULT_MAX_CACHE_ENTRIES = 10_000;
const MAX_MAX_CACHE_ENTRIES = 100_000;
const MAX_CLOCK_SKEW_SECONDS = 30;
const PRIVATE_CLAIM_NAMES = new Set([
  "token",
  "access_token",
  "refresh_token",
  "id_token",
  "assertion",
  "authorization",
  "client_secret",
  "private_key",
]);

export const DEFAULT_OIDC_CLAIM_NAMES: OidcClaimNames = Object.freeze({
  subject: "sub",
  issuer: "iss",
  audience: "aud",
  authorizedParty: "azp",
  expiresAt: "exp",
  notBefore: "nbf",
  issuedAt: "iat",
  tenantId: Object.freeze(["tenant_id", "tid"]),
  applicationId: Object.freeze(["application_id", "app_id"]),
  clientId: Object.freeze(["client_id", "azp"]),
  scope: Object.freeze(["scope", "scp"]),
  tokenId: Object.freeze(["jti"]),
  sessionId: Object.freeze(["sid"]),
  credentialId: Object.freeze(["credential_id", "open_platform_credential_id"]),
  credentialVersion: Object.freeze(["credential_version", "ver"]),
});

export interface VerifiedOidcClaims {
  readonly raw: Readonly<Record<string, unknown>>;
  readonly principalClaims: OidcSanitizedPrincipalClaims;
  readonly tokenFingerprint: string;
  readonly tokenIdHash?: string;
  readonly sessionIdHash?: string;
  readonly tokenAudiences: readonly string[];
  readonly scopes: readonly string[];
  readonly now: number;
}

export interface OidcVerificationCacheEntry {
  readonly identity: OidcAdapterCredentialIdentity;
  readonly expiresAt: number;
  readonly keyId?: string;
  readonly tokenIdHash?: string;
  readonly sessionIdHash?: string;
}

export class OidcVerificationCache {
  private readonly entries = new Map<string, OidcVerificationCacheEntry>();
  private readonly maxEntries: number;

  constructor(maxEntries = DEFAULT_MAX_CACHE_ENTRIES) {
    this.maxEntries = normalizeMaxCacheEntries(maxEntries);
  }

  get(key: string, now: number): OidcVerificationCacheEntry | undefined {
    const entry = this.entries.get(key);
    if (entry === undefined) return undefined;
    if (entry.expiresAt <= now) {
      this.entries.delete(key);
      return undefined;
    }
    this.entries.delete(key);
    this.entries.set(key, entry);
    return entry;
  }

  set(
    key: string,
    identity: OidcAdapterCredentialIdentity,
    expiresAt: number,
    metadata: {
      readonly keyId?: string;
      readonly tokenIdHash?: string;
      readonly sessionIdHash?: string;
    } = {},
  ): void {
    this.entries.delete(key);
    while (this.entries.size >= this.maxEntries) {
      const oldest = this.entries.keys().next().value;
      if (oldest === undefined) break;
      this.entries.delete(oldest);
    }
    this.entries.set(key, {
      identity,
      expiresAt,
      ...metadata,
    });
  }

  invalidate(input: {
    readonly issuer?: string;
    readonly keyId?: string;
    readonly tokenFingerprint?: string;
    readonly tokenIdHash?: string;
    readonly sessionIdHash?: string;
    readonly tenantId?: string;
    readonly clientId?: string;
  }): void {
    if (
      input.issuer === undefined &&
      input.keyId === undefined &&
      input.tokenFingerprint === undefined &&
      input.tokenIdHash === undefined &&
      input.sessionIdHash === undefined &&
      input.tenantId === undefined &&
      input.clientId === undefined
    ) {
      this.entries.clear();
      return;
    }
    for (const [key, entry] of this.entries) {
      const [issuer, audience, tenantId, clientId, fingerprint] = splitCacheKey(key);
      if (
        (input.issuer === undefined || input.issuer === issuer) &&
        (input.keyId === undefined || input.keyId === entry.keyId) &&
        (input.tokenFingerprint === undefined || input.tokenFingerprint === fingerprint) &&
        (input.tokenIdHash === undefined || input.tokenIdHash === entry.tokenIdHash) &&
        (input.sessionIdHash === undefined || input.sessionIdHash === entry.sessionIdHash) &&
        (input.tenantId === undefined || input.tenantId === tenantId) &&
        (input.clientId === undefined || input.clientId === clientId)
      ) {
        this.entries.delete(key);
      }
    }
  }

  clear(): void {
    this.entries.clear();
  }

  size(): number {
    return this.entries.size;
  }
}

export function normalizeOidcMode(value: unknown): OidcRuntimeMode {
  if (value === undefined) return "test";
  if (value !== "development" && value !== "test" && value !== "production") {
    throw oidcAdapterError(OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.CONFIGURATION);
  }
  return value;
}

export function normalizeIssuer(value: unknown, mode: OidcRuntimeMode): string {
  if (typeof value !== "string") {
    throw oidcAdapterError(OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.CONFIGURATION);
  }
  const issuer = value.trim();
  if (
    issuer.length < 1 ||
    issuer.length > 2048 ||
    /[\u0000-\u0020\u007f\\]/u.test(issuer) ||
    issuer.includes("?") ||
    issuer.includes("#")
  ) {
    throw oidcAdapterError(OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.CONFIGURATION);
  }
  let parsed: URL;
  try {
    parsed = new URL(issuer);
  } catch {
    throw oidcAdapterError(OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.CONFIGURATION);
  }
  if (
    (parsed.protocol !== "https:" && parsed.protocol !== "http:") ||
    parsed.hostname === "" ||
    parsed.username !== "" ||
    parsed.password !== "" ||
    (mode === "production" && parsed.protocol !== "https:")
  ) {
    throw oidcAdapterError(OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.CONFIGURATION);
  }
  return issuer;
}

export function normalizeAudience(value: unknown, field = "audience"): string {
  if (typeof value !== "string") {
    throw oidcAdapterError(OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.CONFIGURATION);
  }
  const normalized = value.trim();
  if (
    normalized.length < 1 ||
    normalized.length > 2048 ||
    /[\u0000-\u0020\u007f\\]/u.test(normalized)
  ) {
    throw oidcAdapterError(
      OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.CONFIGURATION,
    );
  }
  return normalized;
}

export function normalizeIdentifier(value: unknown, field: string): string {
  if (typeof value !== "string") {
    throw oidcAdapterError(OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.CONFIGURATION);
  }
  const normalized = value.trim();
  if (
    normalized.length < 1 ||
    normalized.length > MAX_CLAIM_VALUE_LENGTH ||
    /[\u0000-\u0020\u007f]/u.test(normalized)
  ) {
    throw oidcAdapterError(
      OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.CONFIGURATION,
    );
  }
  return normalized;
}

export function normalizeOidcHash(value: unknown, field: string): string {
  if (
    typeof value !== "string" ||
    value.length < 43 ||
    value.length > 128 ||
    !/^[A-Za-z0-9_-]+$/u.test(value)
  ) {
    throw oidcAdapterError(OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.CONFIGURATION);
  }
  return value;
}

export function normalizeScopeList(
  value: unknown,
  field = "scopes",
  required = true,
): string[] {
  if (value === undefined && !required) return [];
  if (!Array.isArray(value)) {
    throw oidcAdapterError(OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.INVALID_SCOPE);
  }
  const output: string[] = [];
  for (const item of value) {
    if (typeof item !== "string") {
      throw oidcAdapterError(OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.INVALID_SCOPE);
    }
    const normalized = item.trim();
    if (
      normalized.length < 1 ||
      normalized.length > 128 ||
      /[\s\u0000-\u001f\u007f]/u.test(normalized)
    ) {
      throw oidcAdapterError(OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.INVALID_SCOPE);
    }
    output.push(normalized);
  }
  return uniqueSorted(output);
}

function normalizeIdentityAudienceList(value: unknown): string[] {
  if (!Array.isArray(value) || value.length < 1 || value.length > MAX_AUDIENCES) {
    throw oidcAdapterError(OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.INVALID_AUDIENCE);
  }
  const output: string[] = [];
  for (const item of value) {
    if (typeof item !== "string") {
      throw oidcAdapterError(OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.INVALID_AUDIENCE);
    }
    const normalized = item.trim();
    if (
      normalized.length < 1 ||
      normalized.length > 2048 ||
      /[\u0000-\u0020\u007f\\]/u.test(normalized)
    ) {
      throw oidcAdapterError(OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.INVALID_AUDIENCE);
    }
    output.push(normalized);
  }
  return uniqueSorted(output);
}

export function normalizeAllowedAlgorithms(
  value: readonly OidcRuntimeSigningAlgorithm[] | undefined,
): OidcRuntimeSigningAlgorithm[] {
  if (value === undefined) return [...OIDC_RUNTIME_SIGNING_ALGORITHMS];
  if (!Array.isArray(value) || value.length === 0) {
    throw oidcAdapterError(OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.CONFIGURATION);
  }
  for (const algorithm of value) {
    if (
      typeof algorithm !== "string" ||
      !(OIDC_RUNTIME_SIGNING_ALGORITHMS as readonly string[]).includes(algorithm)
    ) {
      throw oidcAdapterError(OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.CONFIGURATION);
    }
  }
  return uniqueSorted(value as string[]) as OidcRuntimeSigningAlgorithm[];
}

export function normalizeClaimNames(
  value: Partial<OidcClaimNames> | undefined,
): OidcClaimNames {
  if (value === undefined) return DEFAULT_OIDC_CLAIM_NAMES;
  if (value === null || typeof value !== "object") {
    throw oidcAdapterError(OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.CONFIGURATION);
  }
  return Object.freeze({
    subject: normalizeClaimName(value.subject, DEFAULT_OIDC_CLAIM_NAMES.subject),
    issuer: normalizeClaimName(value.issuer, DEFAULT_OIDC_CLAIM_NAMES.issuer),
    audience: normalizeClaimName(value.audience, DEFAULT_OIDC_CLAIM_NAMES.audience),
    authorizedParty: normalizeClaimName(
      value.authorizedParty,
      DEFAULT_OIDC_CLAIM_NAMES.authorizedParty,
    ),
    expiresAt: normalizeClaimName(value.expiresAt, DEFAULT_OIDC_CLAIM_NAMES.expiresAt),
    notBefore: normalizeClaimName(value.notBefore, DEFAULT_OIDC_CLAIM_NAMES.notBefore),
    issuedAt: normalizeClaimName(value.issuedAt, DEFAULT_OIDC_CLAIM_NAMES.issuedAt),
    tenantId: normalizeClaimNameList(value.tenantId, DEFAULT_OIDC_CLAIM_NAMES.tenantId),
    applicationId: normalizeClaimNameList(
      value.applicationId,
      DEFAULT_OIDC_CLAIM_NAMES.applicationId,
    ),
    clientId: normalizeClaimNameList(value.clientId, DEFAULT_OIDC_CLAIM_NAMES.clientId),
    scope: normalizeClaimNameList(value.scope, DEFAULT_OIDC_CLAIM_NAMES.scope),
    tokenId: normalizeClaimNameList(value.tokenId, DEFAULT_OIDC_CLAIM_NAMES.tokenId),
    sessionId: normalizeClaimNameList(value.sessionId, DEFAULT_OIDC_CLAIM_NAMES.sessionId),
    credentialId: normalizeClaimNameList(
      value.credentialId,
      DEFAULT_OIDC_CLAIM_NAMES.credentialId,
    ),
    credentialVersion: normalizeClaimNameList(
      value.credentialVersion,
      DEFAULT_OIDC_CLAIM_NAMES.credentialVersion,
    ),
  });
}

export function validateJwtResult(
  result: OidcJwtVerificationResult,
  allowedAlgorithms: readonly OidcRuntimeSigningAlgorithm[],
): Readonly<Record<string, unknown>> {
  if (
    result === null ||
    typeof result !== "object" ||
    result.signatureVerified !== true ||
    !isRecord(result.claims) ||
    !isRecord(result.protectedHeader)
  ) {
    throw oidcAdapterError(OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.INVALID_TOKEN);
  }
  const algorithm = result.protectedHeader.alg;
  if (
    typeof algorithm !== "string" ||
    !allowedAlgorithms.includes(algorithm as OidcRuntimeSigningAlgorithm) ||
    result.protectedHeader.jku !== undefined ||
    result.protectedHeader.x5u !== undefined ||
    result.protectedHeader.crit !== undefined
  ) {
    throw oidcAdapterError(OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.INVALID_TOKEN);
  }
  if (
    result.protectedHeader.typ !== undefined &&
    !isAllowedTokenType(result.protectedHeader.typ)
  ) {
    throw oidcAdapterError(OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.INVALID_TOKEN);
  }
  return result.claims;
}

export function validateVerifiedClaims(input: {
  readonly result: OidcJwtVerificationResult;
  readonly issuer: string;
  readonly expectedAudience: string;
  readonly principalAudience?: string;
  readonly expectedTenantId: string;
  readonly expectedApplicationId: string;
  readonly expectedClientId: string;
  readonly clientIdFallback?: string;
  readonly requiredScopes: readonly string[];
  readonly allowedAlgorithms: readonly OidcRuntimeSigningAlgorithm[];
  readonly now: number;
  readonly clockSkewSeconds: number;
  readonly requireNbf: boolean;
  readonly scopeRequired: boolean;
  readonly claimNames: OidcClaimNames;
  readonly token: string;
}): VerifiedOidcClaims {
  const raw = validateJwtResult(input.result, input.allowedAlgorithms);
  const issuer = readStringClaim(raw, input.claimNames.issuer, "issuer", true);
  if (issuer !== input.issuer) {
    throw oidcAdapterError(OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.INVALID_ISSUER);
  }
  const tokenAudiences = readAudiences(raw[input.claimNames.audience]);
  if (!tokenAudiences.includes(input.expectedAudience)) {
    throw oidcAdapterError(OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.INVALID_AUDIENCE);
  }
  const authorizedPartyValue = raw[input.claimNames.authorizedParty];
  const authorizedParty = authorizedPartyValue === undefined
    ? undefined
    : readStringClaim(raw, input.claimNames.authorizedParty, "azp", true);
  if (
    authorizedParty !== undefined &&
    authorizedParty !== input.expectedClientId
  ) {
    throw oidcAdapterError(OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.CLIENT_MISMATCH);
  }
  if (tokenAudiences.length > 1 && authorizedParty === undefined) {
    throw oidcAdapterError(OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.INVALID_AUDIENCE);
  }
  const subject = readStringClaim(raw, input.claimNames.subject, "subject", true);
  const tenantId = readAliasedStringClaim(
    raw,
    input.claimNames.tenantId,
    "tenant",
    true,
  );
  if (tenantId !== input.expectedTenantId) {
    throw oidcAdapterError(OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.TENANT_MISMATCH);
  }
  const clientClaim = readOptionalAliasedStringClaim(
    raw,
    input.claimNames.clientId,
    "client",
  );
  const clientId = clientClaim ?? input.clientIdFallback;
  if (clientId === undefined) {
    throw oidcAdapterError(OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.INVALID_TOKEN);
  }
  if (clientId !== input.expectedClientId) {
    throw oidcAdapterError(OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.CLIENT_MISMATCH);
  }
  const applicationId = readOptionalAliasedStringClaim(
    raw,
    input.claimNames.applicationId,
    "application",
  );
  if (applicationId !== undefined && applicationId !== input.expectedApplicationId) {
    throw oidcAdapterError(OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.IDENTITY_INVALID);
  }
  const expiresAt = readNumericDate(raw, input.claimNames.expiresAt, "exp", true);
  const issuedAt = readNumericDate(raw, input.claimNames.issuedAt, "iat", true);
  const notBeforeValue = raw[input.claimNames.notBefore];
  if (notBeforeValue === undefined && input.requireNbf) {
    throw oidcAdapterError(OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.INVALID_TOKEN);
  }
  const notBefore = notBeforeValue === undefined
    ? issuedAt
    : readNumericDate(raw, input.claimNames.notBefore, "nbf", true);
  const skew = input.clockSkewSeconds;
  if (
    expiresAt <= input.now - skew ||
    notBefore > input.now + skew ||
    issuedAt > input.now + skew ||
    issuedAt >= expiresAt
  ) {
    if (expiresAt <= input.now - skew) {
      throw oidcAdapterError(OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.EXPIRED);
    }
    throw oidcAdapterError(OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.NOT_YET_VALID);
  }
  const scopes = readScopes(raw, input.claimNames.scope, input.scopeRequired);
  if (input.requiredScopes.some((scope) => !scopes.includes(scope))) {
    throw oidcAdapterError(OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.INVALID_SCOPE);
  }
  const tokenId = readOptionalAliasedStringClaim(
    raw,
    input.claimNames.tokenId,
    "token id",
  );
  const sessionId = readOptionalAliasedStringClaim(
    raw,
    input.claimNames.sessionId,
    "session id",
  );
  const principalAudiences = input.principalAudience === undefined
    ? tokenAudiences
    : [input.principalAudience];
  const principalClaims: OidcSanitizedPrincipalClaims = Object.freeze({
    subject,
    issuer,
    audiences: Object.freeze([...uniqueSorted(principalAudiences)]),
    ...(authorizedParty === undefined ? {} : { authorizedParty }),
    tenantId,
    applicationId: applicationId ?? input.expectedApplicationId,
    clientId,
    scopes: Object.freeze([...scopes]),
    issuedAt: new Date(issuedAt * 1000).toISOString(),
    notBefore: new Date(notBefore * 1000).toISOString(),
    expiresAt: new Date(expiresAt * 1000).toISOString(),
    ...(tokenId === undefined ? {} : { tokenIdHash: oidcValueHash(tokenId) }),
    ...(sessionId === undefined ? {} : { sessionIdHash: oidcValueHash(sessionId) }),
  });
  return Object.freeze({
    raw,
    principalClaims,
    tokenFingerprint: oidcTokenFingerprint(input.token),
    ...(tokenId === undefined ? {} : { tokenIdHash: oidcValueHash(tokenId) }),
    ...(sessionId === undefined ? {} : { sessionIdHash: oidcValueHash(sessionId) }),
    tokenAudiences: Object.freeze([...tokenAudiences]),
    scopes: Object.freeze([...scopes]),
    now: input.now,
  });
}

export async function resolveIdentity(input: {
  readonly authenticationType: OidcRuntimeAuthenticationType;
  readonly requestId: string;
  readonly expectedAudience: string;
  readonly expectedTenantId: string;
  readonly expectedApplicationId: string;
  readonly expectedClientId: string;
  readonly now: number;
  readonly requiredScopes: readonly string[];
  readonly scopeMode: OidcScopeResolutionMode;
  readonly allowedScopes?: readonly string[];
  readonly claims: Readonly<Record<string, unknown>>;
  readonly principalClaims: OidcSanitizedPrincipalClaims;
  readonly claimNames: OidcClaimNames;
  readonly resolver?: OidcIdentityResolverPort;
}): Promise<OidcAdapterCredentialIdentity> {
  let identity: OpenPlatformAdapterCredentialIdentity | undefined;
  if (input.resolver !== undefined) {
    const resolution: OidcIdentityResolutionInput = {
      authenticationType: input.authenticationType,
      audience: input.expectedAudience,
      claims: input.claims,
      principalClaims: input.principalClaims,
      requestId: input.requestId,
    };
    try {
      identity = await input.resolver.resolve(resolution);
    } catch {
      throw oidcAdapterError(
        OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.VERIFIER_UNAVAILABLE,
        true,
      );
    }
  } else {
    identity = deriveIdentity(input);
  }
  if (identity === undefined) {
    throw oidcAdapterError(OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.IDENTITY_INVALID);
  }
  return normalizeIdentity(input, identity);
}

export async function assertNotRevoked(
  revocation: OidcRevocationPort,
  lookup: OidcRevocationLookup,
): Promise<void> {
  let result: unknown;
  try {
    result = await revocation.isRevoked(lookup);
  } catch {
    throw oidcAdapterError(
      OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.VERIFIER_UNAVAILABLE,
      true,
    );
  }
  if (result !== true && result !== false) {
    throw oidcAdapterError(
      OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.VERIFIER_UNAVAILABLE,
      true,
    );
  }
  if (result) {
    throw oidcAdapterError(OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.REVOKED);
  }
}

export async function dependencyReady(
  value: { readonly readiness?: () => boolean | Promise<boolean> } | undefined,
): Promise<boolean> {
  if (value?.readiness === undefined) return false;
  try {
    return (await value.readiness()) === true;
  } catch {
    return false;
  }
}

export function normalizeCacheTtl(value: number | undefined): number {
  if (value === undefined) return DEFAULT_CACHE_TTL_MS;
  if (!Number.isSafeInteger(value) || value < 0 || value > MAX_CACHE_TTL_MS) {
    throw oidcAdapterError(OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.CONFIGURATION);
  }
  return value;
}

export function normalizeMaxCacheEntries(value: number | undefined): number {
  if (value === undefined) return DEFAULT_MAX_CACHE_ENTRIES;
  if (!Number.isSafeInteger(value) || value < 1 || value > MAX_MAX_CACHE_ENTRIES) {
    throw oidcAdapterError(OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.CONFIGURATION);
  }
  return value;
}

export function normalizeMaxTokenLength(value: number | undefined): number {
  if (value === undefined) return MAX_TOKEN_LENGTH;
  if (!Number.isSafeInteger(value) || value < 32 || value > MAX_TOKEN_LENGTH) {
    throw oidcAdapterError(OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.CONFIGURATION);
  }
  return value;
}

export function normalizeClockSkew(value: number | undefined): number {
  if (value === undefined) return 0;
  if (!Number.isSafeInteger(value) || value < 0 || value > MAX_CLOCK_SKEW_SECONDS) {
    throw oidcAdapterError(OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.CONFIGURATION);
  }
  return value;
}

export function nowSeconds(clock: () => Date): number {
  const value = clock();
  if (!(value instanceof Date) || !Number.isFinite(value.getTime())) {
    throw oidcAdapterError(OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.CONFIGURATION);
  }
  return Math.floor(value.getTime() / 1000);
}

export function validateSecretInput(
  value: unknown,
  maxLength: number,
): string {
  if (
    typeof value !== "string" ||
    value.length < 1 ||
    value.length > maxLength ||
    /[\u0000-\u0020\u007f]/u.test(value)
  ) {
    throw oidcAdapterError(OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.INVALID_TOKEN);
  }
  return value;
}

export function cacheKey(input: {
  readonly issuer: string;
  readonly audience: string;
  readonly tenantId: string;
  readonly clientId: string;
  readonly tokenFingerprint: string;
}): string {
  return [
    input.issuer,
    input.audience,
    input.tenantId,
    input.clientId,
    input.tokenFingerprint,
  ].join("\u0000");
}

export function splitCacheKey(
  value: string,
): [string, string, string, string, string] {
  const parts = value.split("\u0000");
  return [
    parts[0] ?? "",
    parts[1] ?? "",
    parts[2] ?? "",
    parts[3] ?? "",
    parts[4] ?? "",
  ];
}

export function defaultRevocation(
  value: OidcRevocationPort | undefined,
): OidcRevocationPort {
  return value ?? new InMemoryOidcRevocationStore();
}

export function validateRevocationPort(value: unknown): OidcRevocationPort {
  if (
    value === null ||
    typeof value !== "object" ||
    typeof (value as OidcRevocationPort).isRevoked !== "function" ||
    typeof (value as OidcRevocationPort).productionReady !== "boolean"
  ) {
    throw oidcAdapterError(OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.CONFIGURATION);
  }
  return value as OidcRevocationPort;
}

export function validateCryptoPort<T extends { readonly productionReady: boolean }>(
  value: unknown,
  kind: "bearer" | "serviceClient",
): T {
  if (
    value === null ||
    typeof value !== "object" ||
    (value as { readonly kind?: unknown }).kind !== kind ||
    typeof (value as { readonly verify?: unknown }).verify !== "function" ||
    typeof (value as { readonly productionReady?: unknown }).productionReady !== "boolean" ||
    ((value as { readonly readiness?: unknown }).readiness !== undefined &&
      typeof (value as { readonly readiness?: unknown }).readiness !== "function") ||
    ((value as { readonly invalidateCache?: unknown }).invalidateCache !== undefined &&
      typeof (value as { readonly invalidateCache?: unknown }).invalidateCache !== "function")
  ) {
    throw oidcAdapterError(OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.CONFIGURATION);
  }
  return value as T;
}

export function makeRevocationLookup(input: {
  readonly issuer: string;
  readonly tenantId: string;
  readonly clientId: string;
  readonly tokenFingerprint?: string;
  readonly tokenIdHash?: string;
  readonly sessionIdHash?: string;
}): OidcRevocationLookup {
  return Object.freeze({
    issuer: input.issuer,
    tenantId: input.tenantId,
    clientId: input.clientId,
    ...(input.tokenFingerprint === undefined
      ? {}
      : { tokenFingerprint: input.tokenFingerprint }),
    ...(input.tokenIdHash === undefined ? {} : { tokenIdHash: input.tokenIdHash }),
    ...(input.sessionIdHash === undefined ? {} : { sessionIdHash: input.sessionIdHash }),
  });
}

export function makeRevokeLookup(input: {
  readonly issuer: string;
  readonly tenantId: string;
  readonly clientId: string;
  readonly tokenId?: string;
  readonly sessionId?: string;
  readonly tokenFingerprint?: string;
}): OidcRevocationLookup {
  if (input.tokenFingerprint === undefined && input.tokenId === undefined && input.sessionId === undefined) {
    throw oidcAdapterError(OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.CONFIGURATION);
  }
  return makeRevocationLookup({
    issuer: input.issuer,
    tenantId: input.tenantId,
    clientId: input.clientId,
    ...(input.tokenFingerprint === undefined
      ? {}
      : { tokenFingerprint: normalizeOidcHash(input.tokenFingerprint, "tokenFingerprint") }),
    ...(input.tokenId === undefined ? {} : { tokenIdHash: oidcValueHash(input.tokenId) }),
    ...(input.sessionId === undefined ? {} : { sessionIdHash: oidcValueHash(input.sessionId) }),
  });
}

function deriveIdentity(input: {
  readonly expectedAudience: string;
  readonly expectedTenantId: string;
  readonly expectedApplicationId: string;
  readonly expectedClientId: string;
  readonly claims: Readonly<Record<string, unknown>>;
  readonly principalClaims: OidcSanitizedPrincipalClaims;
  readonly claimNames: OidcClaimNames;
}): OpenPlatformAdapterCredentialIdentity | undefined {
  const credentialId = readOptionalAliasedStringClaim(
    input.claims,
    input.claimNames.credentialId,
    "credential id",
  );
  const credentialVersionValue = readOptionalAliasedNumberClaim(
    input.claimNames.credentialVersion,
    input.claims,
  );
  if (credentialId === undefined || credentialVersionValue === undefined) return undefined;
  return {
    active: true,
    tenantId: input.expectedTenantId,
    applicationId: input.expectedApplicationId,
    clientId: input.expectedClientId,
    credentialId,
    credentialVersion: credentialVersionValue,
    scopes: [...input.principalClaims.scopes],
    audiences: [...input.principalClaims.audiences],
    issuedAt: input.principalClaims.issuedAt,
    expiresAt: input.principalClaims.expiresAt,
  };
}

function normalizeIdentity(
  input: {
    readonly expectedAudience: string;
    readonly expectedTenantId: string;
    readonly expectedApplicationId: string;
    readonly expectedClientId: string;
    readonly now: number;
    readonly requiredScopes: readonly string[];
    readonly scopeMode: OidcScopeResolutionMode;
    readonly allowedScopes?: readonly string[];
    readonly principalClaims: OidcSanitizedPrincipalClaims;
  },
  value: OpenPlatformAdapterCredentialIdentity,
): OidcAdapterCredentialIdentity {
  if (
    value === null ||
    typeof value !== "object" ||
    value.active !== true ||
    typeof value.tenantId !== "string" ||
    value.tenantId !== input.expectedTenantId ||
    typeof value.applicationId !== "string" ||
    value.applicationId !== input.expectedApplicationId ||
    typeof value.clientId !== "string" ||
    value.clientId !== input.expectedClientId ||
    typeof value.credentialId !== "string" ||
    value.credentialId.length < 1 ||
    value.credentialId.length > MAX_CLAIM_VALUE_LENGTH ||
    /[\u0000-\u0020\u007f]/u.test(value.credentialId) ||
    !Number.isSafeInteger(value.credentialVersion) ||
    value.credentialVersion < 1
  ) {
    throw oidcAdapterError(OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.IDENTITY_INVALID);
  }
  const resolverScopes = normalizeScopeList(value.scopes, "identity scopes", false);
  const tokenScopes = input.principalClaims.scopes;
  let scopes = tokenScopes.length > 0
    ? resolverScopes.filter((scope) => tokenScopes.includes(scope))
    : input.scopeMode === "intersect-token-or-allowlist" &&
        input.allowedScopes !== undefined
      ? resolverScopes.filter((scope) => input.allowedScopes?.includes(scope))
      : [];
  if (input.allowedScopes !== undefined) {
    scopes = scopes.filter((scope) => input.allowedScopes?.includes(scope));
  }
  scopes = uniqueSorted(scopes);
  const audiences = normalizeIdentityAudienceList(value.audiences);
  if (!audiences.includes(input.expectedAudience)) {
    throw oidcAdapterError(OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.INVALID_AUDIENCE);
  }
  if (input.requiredScopes.some((scope) => !scopes.includes(scope))) {
    throw oidcAdapterError(OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.INVALID_SCOPE);
  }
  const identityIssuedAt = Date.parse(value.issuedAt);
  const identityExpiresAt = Date.parse(value.expiresAt);
  if (
    !Number.isFinite(identityIssuedAt) ||
    !Number.isFinite(identityExpiresAt) ||
    identityExpiresAt <= identityIssuedAt
  ) {
    throw oidcAdapterError(OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.IDENTITY_INVALID);
  }
  const tokenExpiresAt = Date.parse(input.principalClaims.expiresAt);
  if (identityExpiresAt <= input.now * 1000) {
    throw oidcAdapterError(OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.EXPIRED);
  }
  if (identityExpiresAt <= Date.parse(input.principalClaims.issuedAt)) {
    throw oidcAdapterError(OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.IDENTITY_INVALID);
  }
  const expiresAt = Math.min(identityExpiresAt, tokenExpiresAt);
  if (expiresAt <= Date.parse(input.principalClaims.issuedAt)) {
    throw oidcAdapterError(OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.IDENTITY_INVALID);
  }
  const principalClaims: OidcSanitizedPrincipalClaims = Object.freeze({
    ...input.principalClaims,
    scopes: Object.freeze([...scopes]),
  });
  return Object.freeze({
    active: true,
    tenantId: input.expectedTenantId,
    applicationId: input.expectedApplicationId,
    clientId: input.expectedClientId,
    credentialId: value.credentialId,
    credentialVersion: value.credentialVersion,
    scopes: Object.freeze(scopes),
    audiences: Object.freeze(audiences),
    issuedAt: input.principalClaims.issuedAt,
    expiresAt: new Date(expiresAt).toISOString(),
    principalClaims,
  });
}

function readAudiences(value: unknown): string[] {
  const values = typeof value === "string" ? [value] : value;
  if (!Array.isArray(values) || values.length < 1 || values.length > MAX_AUDIENCES) {
    throw oidcAdapterError(OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.INVALID_AUDIENCE);
  }
  const output: string[] = [];
  for (const item of values) {
    if (typeof item !== "string") {
      throw oidcAdapterError(OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.INVALID_AUDIENCE);
    }
    const normalized = item.trim();
    if (
      normalized.length < 1 ||
      normalized.length > 2048 ||
      /[\u0000-\u0020\u007f\\]/u.test(normalized)
    ) {
      throw oidcAdapterError(OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.INVALID_AUDIENCE);
    }
    output.push(normalized);
  }
  return uniqueSorted(output);
}

function readScopes(
  claims: Readonly<Record<string, unknown>>,
  names: readonly string[],
  required: boolean,
): string[] {
  const value = readFirstPresent(claims, names);
  if (value === undefined) {
    if (required) {
      throw oidcAdapterError(OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.INVALID_SCOPE);
    }
    return [];
  }
  if (
    (typeof value === "string" && value.trim().length === 0) ||
    (Array.isArray(value) && value.length === 0)
  ) {
    if (required) {
      throw oidcAdapterError(OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.INVALID_SCOPE);
    }
    return [];
  }
  const raw = typeof value === "string" ? value.split(/[\u0020]+/u) : value;
  if (!Array.isArray(raw) || raw.length > MAX_SCOPES) {
    throw oidcAdapterError(OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.INVALID_SCOPE);
  }
  const scopes: string[] = [];
  for (const item of raw) {
    if (typeof item !== "string") {
      throw oidcAdapterError(OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.INVALID_SCOPE);
    }
    const normalized = item.trim();
    if (
      normalized.length < 1 ||
      normalized.length > 128 ||
      /[\s\u0000-\u001f\u007f]/u.test(normalized)
    ) {
      throw oidcAdapterError(OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.INVALID_SCOPE);
    }
    scopes.push(normalized);
  }
  return uniqueSorted(scopes);
}

function readStringClaim(
  claims: Readonly<Record<string, unknown>>,
  name: string,
  field: string,
  required: boolean,
): string {
  const value = claims[name];
  if (value === undefined) {
    if (required) {
      throw oidcAdapterError(OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.INVALID_TOKEN);
    }
    return "";
  }
  if (
    typeof value !== "string" ||
    value.length < 1 ||
    value.length > MAX_CLAIM_VALUE_LENGTH ||
    /[\u0000-\u001f\u007f]/u.test(value) ||
    PRIVATE_CLAIM_NAMES.has(value.toLowerCase())
  ) {
    throw oidcAdapterError(OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.INVALID_TOKEN);
  }
  return value;
}

function readAliasedStringClaim(
  claims: Readonly<Record<string, unknown>>,
  names: readonly string[],
  field: string,
  required: boolean,
): string {
  const value = readFirstPresent(claims, names);
  if (value === undefined) {
    if (required) {
      throw oidcAdapterError(OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.INVALID_TOKEN);
    }
    return "";
  }
  if (
    typeof value !== "string" ||
    value.length < 1 ||
    value.length > MAX_CLAIM_VALUE_LENGTH ||
    /[\u0000-\u001f\u007f]/u.test(value)
  ) {
    throw oidcAdapterError(OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.INVALID_TOKEN);
  }
  return value;
}

function readOptionalAliasedStringClaim(
  claims: Readonly<Record<string, unknown>>,
  names: readonly string[],
  field: string,
): string | undefined {
  return readAliasedStringClaim(claims, names, field, false) || undefined;
}

function readNumericDate(
  claims: Readonly<Record<string, unknown>>,
  name: string,
  field: string,
  required: boolean,
): number {
  const value = claims[name];
  if (value === undefined) {
    if (required) {
      throw oidcAdapterError(OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.INVALID_TOKEN);
    }
    return 0;
  }
  if (typeof value !== "number" || !Number.isFinite(value) || value < 0) {
    throw oidcAdapterError(OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.INVALID_TOKEN);
  }
  return value;
}

function readOptionalAliasedNumberClaim(
  names: readonly string[],
  claims: Readonly<Record<string, unknown>>,
): number | undefined {
  const value = readFirstPresent(claims, names);
  if (value === undefined) return undefined;
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 1) {
    throw oidcAdapterError(OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.IDENTITY_INVALID);
  }
  return value;
}

function readFirstPresent(
  claims: Readonly<Record<string, unknown>>,
  names: readonly string[],
): unknown {
  let found = false;
  let result: unknown;
  for (const name of names) {
    if (!Object.prototype.hasOwnProperty.call(claims, name)) continue;
    if (found && !sameClaimValue(result, claims[name])) {
      throw oidcAdapterError(OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.INVALID_TOKEN);
    }
    found = true;
    result = claims[name];
  }
  return result;
}

function sameClaimValue(left: unknown, right: unknown): boolean {
  if (left === right) return true;
  if (Array.isArray(left) && Array.isArray(right)) {
    return left.length === right.length && left.every((item, index) => item === right[index]);
  }
  return false;
}

function normalizeClaimName(value: unknown, fallback: string): string {
  if (value === undefined) return fallback;
  if (
    typeof value !== "string" ||
    value.length < 1 ||
    value.length > 128 ||
    /[^A-Za-z0-9_.:-]/u.test(value)
  ) {
    throw oidcAdapterError(OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.CONFIGURATION);
  }
  return value;
}

function normalizeClaimNameList(
  value: unknown,
  fallback: readonly string[],
): readonly string[] {
  if (value === undefined) return fallback;
  if (!Array.isArray(value) || value.length < 1 || value.length > 16) {
    throw oidcAdapterError(OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.CONFIGURATION);
  }
  return Object.freeze(value.map((item) => normalizeClaimName(item, "")));
}

function normalizeLimit(
  value: number | undefined,
  fallback: number,
  minimum: number,
  maximum: number,
): number {
  if (value === undefined) return fallback;
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw oidcAdapterError(OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.CONFIGURATION);
  }
  return value;
}

function uniqueSorted(values: readonly string[]): string[] {
  return [...new Set(values)].sort((left, right) => left.localeCompare(right));
}

function isAllowedTokenType(value: unknown): boolean {
  return value === "at+jwt" || value === "JWT" || value === "application/at+jwt";
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
