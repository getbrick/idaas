import type { MaybePromise } from "../../../types.js";
import type {
  OpenPlatformAdapterCredentialIdentity,
  OpenPlatformOidcBearerVerifierInput,
  OpenPlatformServiceClientVerifierInput,
  OpenPlatformServiceClientVerifierPort,
} from "../../types.js";

export const OIDC_RUNTIME_SIGNING_ALGORITHMS = Object.freeze([
  "RS256",
  "PS256",
  "ES256",
  "EdDSA",
] as const);

export type OidcRuntimeSigningAlgorithm =
  (typeof OIDC_RUNTIME_SIGNING_ALGORITHMS)[number];

export type OidcRuntimeMode = "development" | "test" | "production";

export type OidcRuntimeAuthenticationType = "oidcBearer" | "serviceClient";

export type OidcScopeResolutionMode =
  | "intersect-token"
  | "intersect-token-or-allowlist";

export type OidcJwksSource = "preconfigured" | "remote";

export type OidcServiceClientAuthenticationMethod =
  | "private_key_jwt"
  | "client_credentials";

export interface OidcJwtVerificationInput {
  readonly token: string;
  readonly issuer: string;
  readonly audience: string;
  readonly algorithms: readonly OidcRuntimeSigningAlgorithm[];
  readonly now: number;
  readonly requestId: string;
}

export interface OidcJwtVerificationResult {
  readonly signatureVerified: true;
  readonly claims: Readonly<Record<string, unknown>>;
  readonly protectedHeader?: Readonly<Record<string, unknown>>;
}

export interface OidcBearerJwtVerifierPort {
  readonly kind: "bearer";
  readonly productionReady: boolean;
  readonly readiness?: () => MaybePromise<boolean>;
  verify(
    input: OidcJwtVerificationInput,
  ): MaybePromise<OidcJwtVerificationResult>;
  invalidateCache?: (input: {
    readonly issuer?: string;
    readonly keyId?: string;
  }) => MaybePromise<void>;
}

export interface OidcServiceClientJwtVerifierPort {
  readonly kind: "serviceClient";
  readonly productionReady: boolean;
  readonly readiness?: () => MaybePromise<boolean>;
  verify(
    input: OidcJwtVerificationInput & {
      readonly clientId: string;
      readonly authenticationMethod: OidcServiceClientAuthenticationMethod;
    },
  ): MaybePromise<OidcJwtVerificationResult>;
  invalidateCache?: (input: {
    readonly issuer?: string;
    readonly keyId?: string;
  }) => MaybePromise<void>;
}

export interface OidcJwksResolverPort {
  readonly productionReady?: boolean;
  readonly readiness?: () => MaybePromise<boolean>;
  readonly source?: OidcJwksSource;
  readonly jwksUri?: string;
  readonly jwksUrl?: string;
  readonly issuerAllowlist?: readonly string[];
  readonly trustedHosts?: readonly string[];
  readonly allowedHosts?: readonly string[];
  resolveHost?: (hostname: string) => MaybePromise<readonly string[]>;
  resolve(input: {
    readonly issuer: string;
    readonly keyId?: string;
  }): MaybePromise<unknown>;
  invalidateCache?: (input: {
    readonly issuer?: string;
    readonly keyId?: string;
  }) => MaybePromise<void>;
}

export interface OidcJoseApi {
  readonly createLocalJWKSet: (...args: any[]) => unknown;
  readonly jwtVerify: (...args: any[]) => Promise<unknown>;
}

export interface OidcRemoteJwksResolverOptions {
  readonly mode?: OidcRuntimeMode;
  readonly jwksUri: string;
  readonly issuerAllowlist: readonly string[];
  readonly trustedHosts: readonly string[];
  readonly allowRemoteJwks?: boolean;
  readonly productionReady?: boolean;
  readonly fetch?: (input: string, init?: RequestInit) => Promise<Response>;
  readonly resolveHost?: (hostname: string) => MaybePromise<readonly string[]>;
  readonly readiness?: () => MaybePromise<boolean>;
  readonly timeoutMs?: number;
  readonly maxResponseBytes?: number;
}

export interface OidcJoseVerifierOptions {
  readonly jose: OidcJoseApi;
  readonly jwks: OidcJwksResolverPort;
  readonly mode?: OidcRuntimeMode;
  readonly source?: OidcJwksSource;
  readonly jwksUri?: string;
  readonly jwksUrl?: string;
  readonly productionReady?: boolean;
  readonly cacheTtlMs?: number;
  readonly maxJwksCacheEntries?: number;
  readonly maxUnknownKids?: number;
  readonly resolverRefreshIntervalMs?: number;
  readonly issuerAllowlist?: readonly string[];
  readonly allowedIssuers?: readonly string[];
  readonly trustedJwksHosts?: readonly string[];
  readonly allowedJwksHosts?: readonly string[];
  readonly trustedHosts?: readonly string[];
  readonly allowedHosts?: readonly string[];
  readonly allowRemoteJwks?: boolean;
  readonly clock?: () => Date;
  readonly kind?: "bearer" | "serviceClient";
}

export interface OidcRevocationLookup {
  readonly issuer: string;
  readonly tenantId: string;
  readonly clientId: string;
  readonly tokenFingerprint?: string;
  readonly tokenIdHash?: string;
  readonly sessionIdHash?: string;
}

export type OidcRevocationReason =
  | "logout"
  | "token_revoked"
  | "credential_revoked"
  | "key_rotation";

export interface OidcRevocationPort {
  readonly productionReady: boolean;
  readonly readiness?: () => MaybePromise<boolean>;
  isRevoked(input: OidcRevocationLookup): MaybePromise<boolean>;
  revoke?: (
    input: OidcRevocationLookup,
    reason: OidcRevocationReason,
  ) => MaybePromise<void>;
  invalidate?: (input: {
    readonly issuer?: string;
    readonly keyId?: string;
    readonly tokenFingerprint?: string;
    readonly tokenIdHash?: string;
    readonly sessionIdHash?: string;
  }) => MaybePromise<void>;
}

export interface OidcRevokeInput {
  readonly issuer: string;
  readonly tenantId: string;
  readonly clientId: string;
  readonly tokenId?: string;
  readonly sessionId?: string;
  readonly tokenFingerprint?: string;
  readonly reason?: OidcRevocationReason;
}

export interface OidcCacheInvalidationInput {
  readonly issuer?: string;
  readonly keyId?: string;
  readonly tokenFingerprint?: string;
  readonly tokenIdHash?: string;
  readonly sessionIdHash?: string;
  readonly tenantId?: string;
  readonly clientId?: string;
}

export interface OidcSanitizedPrincipalClaims {
  readonly subject: string;
  readonly issuer: string;
  readonly audiences: readonly string[];
  readonly authorizedParty?: string;
  readonly tenantId: string;
  readonly applicationId: string;
  readonly clientId: string;
  readonly scopes: readonly string[];
  readonly issuedAt: string;
  readonly notBefore: string;
  readonly expiresAt: string;
  readonly tokenIdHash?: string;
  readonly sessionIdHash?: string;
}

export interface OidcAdapterCredentialIdentity
  extends OpenPlatformAdapterCredentialIdentity {
  readonly principalClaims: OidcSanitizedPrincipalClaims;
}

export interface OidcIdentityResolutionInput {
  readonly authenticationType: OidcRuntimeAuthenticationType;
  readonly audience: string;
  readonly claims: Readonly<Record<string, unknown>>;
  readonly principalClaims: OidcSanitizedPrincipalClaims;
  readonly requestId: string;
}

export interface OidcIdentityResolverPort {
  readonly productionReady?: boolean;
  readonly readiness?: () => MaybePromise<boolean>;
  resolve(
    input: OidcIdentityResolutionInput,
  ): MaybePromise<OpenPlatformAdapterCredentialIdentity | undefined>;
}

export interface OidcClaimNames {
  readonly subject: string;
  readonly issuer: string;
  readonly audience: string;
  readonly authorizedParty: string;
  readonly expiresAt: string;
  readonly notBefore: string;
  readonly issuedAt: string;
  readonly tenantId: readonly string[];
  readonly applicationId: readonly string[];
  readonly clientId: readonly string[];
  readonly scope: readonly string[];
  readonly tokenId: readonly string[];
  readonly sessionId: readonly string[];
  readonly credentialId: readonly string[];
  readonly credentialVersion: readonly string[];
}

export interface OidcBearerVerifierAdapterOptions {
  readonly mode?: OidcRuntimeMode;
  readonly issuer: string;
  readonly tenantId: string;
  readonly applicationId: string;
  readonly clientId: string;
  readonly requiredScopes?: readonly string[];
  readonly allowedAlgorithms?: readonly OidcRuntimeSigningAlgorithm[];
  readonly jwtVerifier: OidcBearerJwtVerifierPort;
  readonly identityResolver?: OidcIdentityResolverPort;
  readonly revocation?: OidcRevocationPort;
  readonly clock?: () => Date;
  readonly cacheTtlMs?: number;
  readonly maxCacheEntries?: number;
  readonly maxTokenLength?: number;
  readonly clockSkewSeconds?: number;
  readonly requireNbf?: boolean;
  readonly claimNames?: Partial<OidcClaimNames>;
}

export interface OidcServiceClientVerifierAdapterOptions {
  readonly mode?: OidcRuntimeMode;
  readonly issuer: string;
  readonly tenantId: string;
  readonly applicationId: string;
  readonly clientId: string;
  readonly authenticationMethod: OidcServiceClientAuthenticationMethod;
  readonly assertionAudience?: string;
  readonly requiredScopes?: readonly string[];
  readonly allowedScopes?: readonly string[];
  readonly allowedAlgorithms?: readonly OidcRuntimeSigningAlgorithm[];
  readonly jwtVerifier: OidcServiceClientJwtVerifierPort;
  readonly identityResolver?: OidcIdentityResolverPort;
  readonly revocation?: OidcRevocationPort;
  readonly clock?: () => Date;
  readonly cacheTtlMs?: number;
  readonly maxCacheEntries?: number;
  readonly maxTokenLength?: number;
  readonly clockSkewSeconds?: number;
  readonly requireNbf?: boolean;
  readonly claimNames?: Partial<OidcClaimNames>;
}

export interface OidcBearerAdapterVerifierInput
  extends OpenPlatformOidcBearerVerifierInput {}

export interface OidcServiceClientAdapterVerifierInput
  extends OpenPlatformServiceClientVerifierInput {}

export interface OidcServiceClientVerifierAdapterPort
  extends OpenPlatformServiceClientVerifierPort {
  readonly authenticationMethod: OidcServiceClientAuthenticationMethod;
}
