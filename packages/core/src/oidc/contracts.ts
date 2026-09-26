import type {
  OidcClaimDefinition,
  OidcClaimSource,
  OidcConsentContext,
  OidcConsentDecision,
  OidcConsentDenialReason,
  OidcConsentGrant,
  OidcConsentGrantStatus,
  OidcConsentProjectionStatus,
  OidcDiscoveryMetadata,
  OidcEndpointPolicy,
  OidcEndpointSource,
  OidcErrorCategory,
  OidcIdTokenSigningAlgorithm,
  OidcLogoutOperation,
  OidcLogoutOperationStatus,
  OidcLogoutResult,
  OidcLogoutTarget,
  OidcProtocolError,
  OidcProtocolErrorCode,
  OidcProviderApplicationType,
  OidcProviderClientAuthMethod,
  OidcProviderClientAuthSigningAlgorithm,
  OidcProviderClientKind,
  OidcProviderClientMetadata,
  OidcProviderEndpoints,
  OidcProviderGrantType,
  OidcProviderResponseType,
  OidcResolvedProvider,
} from "@getbrick/idaas-contracts";

export {
  OIDC_CLAIM_SOURCES,
  OIDC_CONSENT_DENIAL_REASONS,
  OIDC_CONSENT_GRANT_STATUSES,
  OIDC_CONSENT_PROJECTION_STATUSES,
  OIDC_ENDPOINT_SOURCES,
  OIDC_ERROR_CATEGORIES,
  OIDC_ID_TOKEN_SIGNING_ALGORITHMS,
  OIDC_LOGOUT_OPERATION_STATUSES,
  OIDC_LOGOUT_TARGETS,
  OIDC_PROTOCOL_ERROR_CODES,
  OIDC_PROVIDER_APPLICATION_TYPES,
  OIDC_PROVIDER_CLIENT_AUTH_METHODS,
  OIDC_PROVIDER_CLIENT_KINDS,
  OIDC_PROVIDER_GRANT_TYPES,
  OIDC_PROVIDER_RESPONSE_TYPES,
} from "@getbrick/idaas-contracts";

export type {
  OidcClaimDefinition,
  OidcClaimSource,
  OidcConsentContext,
  OidcConsentDecision,
  OidcConsentDenialReason,
  OidcConsentGrant,
  OidcConsentGrantStatus,
  OidcConsentProjectionStatus,
  OidcDiscoveryMetadata,
  OidcEndpointPolicy,
  OidcEndpointSource,
  OidcErrorCategory,
  OidcIdTokenSigningAlgorithm,
  OidcLogoutOperation,
  OidcLogoutOperationStatus,
  OidcLogoutResult,
  OidcLogoutTarget,
  OidcProtocolError,
  OidcProtocolErrorCode,
  OidcProviderApplicationType,
  OidcProviderClientAuthMethod,
  OidcProviderClientAuthSigningAlgorithm,
  OidcProviderClientKind,
  OidcProviderClientMetadata,
  OidcProviderEndpoints,
  OidcProviderGrantType,
  OidcProviderResponseType,
  OidcResolvedProvider,
} from "@getbrick/idaas-contracts";

export interface OidcProviderEndpointResolverInput {
  providerId: string;
  issuer: string;
  discoveryUrl?: string;
  authorizationUrl?: string;
  tokenUrl?: string;
  userInfoUrl?: string;
  jwksUri?: string;
  endSessionEndpoint?: string;
  trustedEndpointOrigins: readonly string[];
  allowInsecureHttp: boolean;
}

export interface OidcProviderEndpointResolver {
  resolve(input: OidcProviderEndpointResolverInput): Promise<OidcResolvedProvider>;
}

export type OidcConsentResolverV2 = (
  context: OidcConsentContext,
) => OidcConsentDecision | Promise<OidcConsentDecision>;

export interface OidcConsentGrantStore {
  findActive(input: {
    tenantId: string;
    applicationId: string;
    clientId: string;
    userId: string;
    scopeHash: string;
    claimHash: string;
    policyVersion: string;
  }): Promise<OidcConsentGrant | null>;
  createPending(input: OidcConsentContext & {
    scopeHash: string;
    claimHash: string;
  }): Promise<OidcConsentGrant>;
  markProjected(input: {
    consentId: string;
    projectionStatus: "projected" | "failed" | "reconciling";
    errorCode?: OidcProtocolErrorCode;
  }): Promise<OidcConsentGrant>;
  revoke(input: {
    consentId: string;
    reason: "user_logout" | "policy_change" | "client_unbind" | "tenant_revoked";
  }): Promise<OidcConsentGrant>;
}

export interface OidcConsentProjection {
  project(grant: OidcConsentGrant): Promise<{ grantId: string }>;
  revoke(grantId: string): Promise<void>;
}

export interface OidcVerifiedIdTokenClaims {
  issuer: string;
  subject: string;
  audience: readonly string[];
  nonce?: string;
  issuedAt: number;
  expiresAt: number;
  authTime?: number;
  accessTokenHash?: string;
}

export interface OidcJwksResolver {
  resolve(clientId: string, kid?: string): Promise<unknown>;
}

export type OidcArtifactReadMode = "active" | "replay";

export interface OidcArtifactReadOptions {
  mode?: OidcArtifactReadMode;
}

export interface OidcNamespaceBindingInput {
  tenantId: string;
  namespace?: string;
}

export interface OidcNamespaceBindingPort {
  resolveNamespace(input: OidcNamespaceBindingInput): string | Promise<string>;
}

export interface OidcGrantRevocationPort {
  revokeByGrantId(input: {
    tenantId: string;
    namespace: string;
    grantId: string;
  }): Promise<number>;
  revokeByAccountId(input: {
    tenantId: string;
    namespace: string;
    accountId: string;
  }): Promise<number>;
}

export interface OidcLogoutRequest {
  tenantId: string;
  applicationId?: string;
  clientId: string;
  userId?: string;
  providerSessionId?: string;
  postLogoutRedirectUri?: string;
  idTokenHint?: string;
  idempotencyKey: string;
}

export interface OidcLogoutRevocationInput {
  operation: OidcLogoutOperation;
  targets: readonly OidcLogoutTarget[];
}

export interface OidcLogoutRevocationResult {
  revokedTargets: readonly OidcLogoutTarget[];
  operation: OidcLogoutOperation;
}

export interface OidcLogoutCoordinator {
  prepare(request: OidcLogoutRequest): Promise<OidcLogoutOperation>;
  complete(operation: OidcLogoutOperation): Promise<OidcLogoutResult>;
}
