import type {
  ApplicationClientAuthSigningAlgorithm,
  ApplicationTokenEndpointAuthMethod,
} from "./application-management.js";

export const OIDC_ENDPOINT_SOURCES = ["discovery", "explicit"] as const;
export type OidcEndpointSource = (typeof OIDC_ENDPOINT_SOURCES)[number];

export const OIDC_PROVIDER_APPLICATION_TYPES = ["web", "native"] as const;
export type OidcProviderApplicationType = (typeof OIDC_PROVIDER_APPLICATION_TYPES)[number];

export const OIDC_PROVIDER_CLIENT_KINDS = ["web", "native", "mp_weixin", "webview"] as const;
export type OidcProviderClientKind = (typeof OIDC_PROVIDER_CLIENT_KINDS)[number];

export const OIDC_PROVIDER_CLIENT_AUTH_METHODS = [
  "none",
  "client_secret_basic",
  "client_secret_post",
  "private_key_jwt",
] as const;
export type OidcProviderClientAuthMethod = ApplicationTokenEndpointAuthMethod;
export type OidcProviderClientAuthSigningAlgorithm = ApplicationClientAuthSigningAlgorithm;

export const OIDC_PROVIDER_GRANT_TYPES = ["authorization_code", "refresh_token"] as const;
export type OidcProviderGrantType = (typeof OIDC_PROVIDER_GRANT_TYPES)[number];

export const OIDC_PROVIDER_RESPONSE_TYPES = ["code"] as const;
export type OidcProviderResponseType = (typeof OIDC_PROVIDER_RESPONSE_TYPES)[number];

export const OIDC_ID_TOKEN_SIGNING_ALGORITHMS = ["RS256", "PS256", "ES256", "EdDSA"] as const;
export type OidcIdTokenSigningAlgorithm = (typeof OIDC_ID_TOKEN_SIGNING_ALGORITHMS)[number];

export const OIDC_CONSENT_DENIAL_REASONS = [
  "user_denied",
  "policy_denied",
  "scope_mismatch",
  "claim_mismatch",
  "interaction_required",
  "tenant_mismatch",
  "client_mismatch",
  "stale_version",
] as const;
export type OidcConsentDenialReason = (typeof OIDC_CONSENT_DENIAL_REASONS)[number];

export const OIDC_CONSENT_GRANT_STATUSES = ["pending", "active", "denied", "revoked", "expired"] as const;
export type OidcConsentGrantStatus = (typeof OIDC_CONSENT_GRANT_STATUSES)[number];

export const OIDC_CONSENT_PROJECTION_STATUSES = ["pending", "projected", "failed", "reconciling"] as const;
export type OidcConsentProjectionStatus = (typeof OIDC_CONSENT_PROJECTION_STATUSES)[number];

export const OIDC_CLAIM_SOURCES = ["identity", "tenant", "membership", "device"] as const;
export type OidcClaimSource = (typeof OIDC_CLAIM_SOURCES)[number];

export const OIDC_LOGOUT_OPERATION_STATUSES = ["pending", "revoking", "completed", "failed"] as const;
export type OidcLogoutOperationStatus = (typeof OIDC_LOGOUT_OPERATION_STATUSES)[number];

export const OIDC_LOGOUT_TARGETS = [
  "op_session",
  "offline_grant",
  "better_auth",
  "bff_cookie",
  "native_session",
  "webview_ticket",
] as const;
export type OidcLogoutTarget = (typeof OIDC_LOGOUT_TARGETS)[number];

export const OIDC_PROTOCOL_ERROR_CODES = [
  "invalid_request",
  "invalid_client",
  "invalid_grant",
  "unauthorized_client",
  "unsupported_grant_type",
  "unsupported_response_type",
  "invalid_scope",
  "login_required",
  "consent_required",
  "interaction_required",
  "access_denied",
  "temporarily_unavailable",
  "server_error",
] as const;
export type OidcProtocolErrorCode = (typeof OIDC_PROTOCOL_ERROR_CODES)[number];

export const OIDC_ERROR_CATEGORIES = ["protocol", "provider", "storage", "configuration"] as const;
export type OidcErrorCategory = (typeof OIDC_ERROR_CATEGORIES)[number];

export interface OidcProviderEndpoints {
  authorization: string;
  token: string;
  userInfo: string;
  jwks: string;
  endSession?: string;
}

export interface OidcDiscoveryMetadata {
  issuer: string;
  authorization_endpoint?: string;
  token_endpoint?: string;
  userinfo_endpoint?: string;
  jwks_uri?: string;
  end_session_endpoint?: string;
  id_token_signing_alg_values_supported?: readonly string[];
  code_challenge_methods_supported?: readonly string[];
  grant_types_supported?: readonly string[];
}

export interface OidcEndpointPolicy {
  trustedEndpointOrigins: readonly string[];
  allowInsecureHttp: boolean;
  requireHttps: boolean;
  exactIssuer: true;
}

export interface OidcResolvedProvider {
  contractVersion: 1;
  issuer: string;
  source: OidcEndpointSource;
  endpoints: OidcProviderEndpoints;
  allowedIdTokenAlgorithms: readonly OidcIdTokenSigningAlgorithm[];
}

export interface OidcProviderClientMetadata {
  clientId: string;
  applicationType: OidcProviderApplicationType;
  clientKind: OidcProviderClientKind;
  redirectUris: readonly string[];
  postLogoutRedirectUris: readonly string[];
  grantTypes: readonly OidcProviderGrantType[];
  responseTypes: readonly OidcProviderResponseType[];
  scopes: readonly string[];
  tokenEndpointAuthMethod: OidcProviderClientAuthMethod;
  tokenEndpointAuthSigningAlgorithm?: OidcProviderClientAuthSigningAlgorithm;
  requirePkce: true;
}

export interface OidcConsentContext {
  consentId: string;
  tenantId: string;
  applicationId: string;
  clientId: string;
  userId: string;
  grantId: string;
  interactionId: string;
  requestedScopes: readonly string[];
  requestedClaims: readonly string[];
  policyVersion: string;
  origin?: string;
}

export type OidcConsentDecision =
  | {
      decision: "denied";
      reason: OidcConsentDenialReason;
    }
  | {
      decision: "approved";
      consentId: string;
      approvedScopes: readonly string[];
      approvedClaims: readonly string[];
      policyVersion: string;
      userGesture: true;
    };

export interface OidcClaimDefinition {
  name: string;
  scopes: readonly string[];
  clients: readonly string[];
  source: OidcClaimSource;
  required: boolean;
  version: string;
  sensitive: boolean;
}

export interface OidcConsentGrant {
  contractVersion: 1;
  consentId: string;
  tenantId: string;
  applicationId: string;
  clientId: string;
  userId: string;
  scopeHash: string;
  claimHash: string;
  policyVersion: string;
  status: OidcConsentGrantStatus;
  projectionStatus: OidcConsentProjectionStatus;
  createdAt: string;
  expiresAt?: string;
  revokedAt?: string;
}

export interface OidcLogoutOperation {
  contractVersion: 1;
  operationId: string;
  tenantId: string;
  applicationId?: string;
  clientId: string;
  userId?: string;
  providerSessionId?: string;
  status: OidcLogoutOperationStatus;
  idempotencyKey: string;
  targets: readonly OidcLogoutTarget[];
  errorCode?: OidcProtocolErrorCode;
  createdAt: string;
  updatedAt: string;
}

export interface OidcLogoutResult {
  operation: OidcLogoutOperation;
  revokedTargets: readonly OidcLogoutTarget[];
  completed: boolean;
}

export interface OidcProtocolError {
  code: OidcProtocolErrorCode;
  category: OidcErrorCategory;
  retryable: boolean;
  requestId?: string;
}
