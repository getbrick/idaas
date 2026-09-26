export const APPLICATION_TYPES = ["web", "native"] as const;
export const KNOWN_APPLICATION_TYPES = APPLICATION_TYPES;

export type KnownApplicationType = (typeof APPLICATION_TYPES)[number];
export type ApplicationType = KnownApplicationType;

export const APPLICATION_CLIENT_KINDS = ["web", "webview", "mp_weixin", "native"] as const;
export const APPLICATION_CLIENT_KIND = APPLICATION_CLIENT_KINDS;
export const CLIENT_KIND = APPLICATION_CLIENT_KINDS;
export const OIDC_CLIENT_KIND = APPLICATION_CLIENT_KINDS;
export const CLIENT_KINDS = APPLICATION_CLIENT_KINDS;
export const OIDC_CLIENT_KINDS = APPLICATION_CLIENT_KINDS;
export const APPLICATION_CLIENT_KINDSETS = APPLICATION_CLIENT_KINDS;

export type ApplicationClientKind = (typeof APPLICATION_CLIENT_KINDS)[number];
export type ClientKind = ApplicationClientKind;
export type OidcClientKind = ApplicationClientKind;
export type ApplicationOidcClientKind = ApplicationClientKind;
export const DEFAULT_APPLICATION_CLIENT_KIND = "web" as const;
export const DEFAULT_CLIENT_KIND = DEFAULT_APPLICATION_CLIENT_KIND;

export const APPLICATION_CLIENT_AUTH_SIGNING_ALGORITHMS = ["RS256", "PS256", "ES256", "EdDSA"] as const;
export const APPLICATION_OIDC_SIGNING_ALGORITHMS = APPLICATION_CLIENT_AUTH_SIGNING_ALGORITHMS;
export const OIDC_CLIENT_AUTH_SIGNING_ALGORITHMS = APPLICATION_CLIENT_AUTH_SIGNING_ALGORITHMS;
export const OIDC_SIGNING_ALGORITHMS = APPLICATION_CLIENT_AUTH_SIGNING_ALGORITHMS;

export type ApplicationClientAuthSigningAlgorithm =
  (typeof APPLICATION_CLIENT_AUTH_SIGNING_ALGORITHMS)[number];
export type ApplicationOidcSigningAlgorithm = ApplicationClientAuthSigningAlgorithm;
export type OidcClientAuthSigningAlgorithm = ApplicationClientAuthSigningAlgorithm;
export type OidcSigningAlgorithm = ApplicationClientAuthSigningAlgorithm;

export const APPLICATION_CLIENT_SIGNING_KEY_TYPES = {
  RS256: "RSA",
  PS256: "RSA",
  ES256: "EC",
  EdDSA: "OKP",
} as const;
export const APPLICATION_OIDC_SIGNING_KEY_TYPES = APPLICATION_CLIENT_SIGNING_KEY_TYPES;
export const OIDC_CLIENT_SIGNING_KEY_TYPES = APPLICATION_CLIENT_SIGNING_KEY_TYPES;
export const OIDC_SIGNING_KEY_TYPES = APPLICATION_CLIENT_SIGNING_KEY_TYPES;

export type ApplicationClientSigningKeyType =
  (typeof APPLICATION_CLIENT_SIGNING_KEY_TYPES)[ApplicationClientAuthSigningAlgorithm];
export type ApplicationOidcSigningKeyType = ApplicationClientSigningKeyType;
export type OidcClientSigningKeyType = ApplicationClientSigningKeyType;
export type OidcSigningKeyType = ApplicationClientSigningKeyType;

export const DEFAULT_APPLICATION_CLIENT_AUTH_METHOD = "private_key_jwt" as const;
export const DEFAULT_APPLICATION_CLIENT_AUTH_SIGNING_ALGORITHM = "RS256" as const;
export const DEFAULT_OIDC_CLIENT_AUTH_METHOD = DEFAULT_APPLICATION_CLIENT_AUTH_METHOD;
export const DEFAULT_OIDC_CLIENT_AUTH_SIGNING_ALGORITHM = DEFAULT_APPLICATION_CLIENT_AUTH_SIGNING_ALGORITHM;

export const APPLICATION_CLIENT_ID_SCOPES = ["global"] as const;
export const APPLICATION_CLIENT_ID_SCOPE = "global" as const;
export const APPLICATION_CLIENT_ID_UNIQUENESS_SCOPE = APPLICATION_CLIENT_ID_SCOPE;
export type ApplicationClientIdScope = (typeof APPLICATION_CLIENT_ID_SCOPES)[number];

export const APPLICATION_PLATFORM_TYPES = [
  "web",
  "wechat_official_account",
  "wechat_open_platform",
  "wechat_component",
  "wechat_open_platform_component",
  "wechat_mini_program",
  "alipay_mini_program",
  "douyin_mini_program",
  "qq_mini_program",
  "baidu_mini_program",
  "feishu_mini_program",
  "mini_program",
] as const;

export type KnownApplicationPlatformType = (typeof APPLICATION_PLATFORM_TYPES)[number];
export type ApplicationPlatformType = KnownApplicationPlatformType | (string & {});

export type ApplicationStatus = "active" | "disabled" | "archived" | "purged";
export type ApplicationClientStatus = "active" | "disabled" | "archived" | "purged";
export type ApplicationLifecycleStatus = ApplicationStatus;
export type ApplicationAction = "archive" | "restore" | "purge";
export type ApplicationVersion = number | string;
export type ApplicationTokenEndpointAuthMethod =
  | "none"
  | "client_secret_basic"
  | "client_secret_post"
  | "private_key_jwt";
export type ApplicationClientAuthMethod = ApplicationTokenEndpointAuthMethod;
export type OidcClientAuthMethod = ApplicationTokenEndpointAuthMethod;

export type ApplicationClientGrantType = "authorization_code" | "refresh_token";
export type ApplicationClientResponseType = "code";

export type ApplicationReadinessStatus = "ready" | "not_ready" | "unknown";
export type ApplicationEffectiveStatus =
  | ApplicationStatus
  | "not_ready"
  | "invalid"
  | "unknown"
  | (string & {});

export type ApplicationSecretStatus =
  | "configured"
  | "not_configured"
  | "missing"
  | "rotating"
  | "active"
  | "retiring"
  | "revoked"
  | "not_required"
  | "expired"
  | "unknown"
  | (string & {});

export interface ApplicationReadinessCheck {
  id?: string;
  name?: string;
  status?: ApplicationReadinessStatus | (string & {});
  ready?: boolean;
  message?: string;
}

export interface ApplicationReadinessDetails {
  status: ApplicationReadinessStatus;
  ready?: boolean;
  checks?: ApplicationReadinessCheck[];
  reasons?: string[];
}

export type ApplicationReadiness = ApplicationReadinessStatus | ApplicationReadinessDetails;

export interface ApplicationSummary {
  id: string;
  name: string;
  slug: string;
  description?: string;
  applicationType?: ApplicationType;
  status: ApplicationStatus;
  lifecycleStatus?: ApplicationLifecycleStatus;
  readiness?: ApplicationReadiness;
  effectiveStatus?: ApplicationEffectiveStatus;
  version?: ApplicationVersion;
  etag?: string;
  createdAt?: string;
  updatedAt?: string;
  enabledAt?: string;
  disabledAt?: string;
  archivedAt?: string;
  purgedAt?: string;
}

export interface ApplicationPlatformSummary {
  id: string;
  applicationId: string;
  type: ApplicationPlatformType;
  externalAppId?: string;
  displayName?: string;
  loginMode?: string;
  scope?: string;
  scopes?: string[];
  redirectUris: string[];
  endpointUrl?: string;
  credentialConfigured: boolean;
  secretStatus?: ApplicationSecretStatus;
  secretVersion?: ApplicationVersion;
  componentAppId?: string;
  componentAppSecretConfigured?: boolean;
  authorizedAppId?: string;
  authorizerAppId?: string;
  componentTicketExpiresAt?: string;
  componentBindingStatus?: WechatComponentBindingStatus;
  componentBindingVersion?: ApplicationVersion;
  componentBinding?: WechatComponentPlatformBindingSummary;
  readiness?: ApplicationReadiness;
  effectiveStatus?: ApplicationEffectiveStatus;
  version?: ApplicationVersion;
  etag?: string;
  status: ApplicationStatus;
  lifecycleStatus?: ApplicationStatus;
  createdAt?: string;
  updatedAt?: string;
  enabledAt?: string;
  disabledAt?: string;
  archivedAt?: string;
  purgedAt?: string;
}

export interface ApplicationClientSummary {
  id: string;
  applicationId: string;
  applicationType?: ApplicationType;
  clientKind?: ApplicationClientKind;
  clientType?: ApplicationClientKind;
  clientId: string;
  clientIdScope?: ApplicationClientIdScope;
  redirectUriPolicy?: OidcRpRedirectUriPolicy;
  pkceMethod?: OidcRpPkceMethod;
  consent?: OidcRpConsent;
  consentRequired?: boolean;
  requireExplicitConsent?: boolean;
  rpClient?: OidcRpClient;
  status: ApplicationClientStatus;
  lifecycleStatus?: ApplicationStatus;
  redirectUris: string[];
  postLogoutRedirectUris: string[];
  grantTypes: string[];
  responseTypes: string[];
  scopes: string[];
  tokenEndpointAuthMethod: string;
  tokenEndpointAuthSigningAlg?: string;
  jwksUri?: string;
  keyId?: string;
  requirePkce: boolean;
  hasSecret: boolean;
  secretStatus?: ApplicationSecretStatus;
  secretVersion?: ApplicationVersion;
  readiness?: ApplicationReadiness;
  effectiveStatus?: ApplicationEffectiveStatus;
  version?: ApplicationVersion;
  etag?: string;
  createdAt?: string;
  updatedAt?: string;
  enabledAt?: string;
  disabledAt?: string;
  archivedAt?: string;
  purgedAt?: string;
}

export type ApplicationOidcClientSummary = ApplicationClientSummary;
export type ApplicationOIDCClientSummary = ApplicationClientSummary;

export interface ApplicationCreateRequest {
  name: string;
  slug: string;
  description?: string;
  applicationType?: ApplicationType;
}

export interface ApplicationUpdateRequest {
  name?: string;
  slug?: string;
  description?: string;
  applicationType?: ApplicationType;
}

export interface ApplicationPlatformCreateRequest {
  type: ApplicationPlatformType;
  externalAppId?: string;
  componentAppId?: string;
  authorizedAppId?: string;
  authorizerAppId?: string;
  componentBinding?: WechatComponentPlatformBinding;
  componentAppSecretRef?: string;
  componentVerifyTicketRef?: string;
  componentAccessTokenRef?: string;
  authorizerRefreshTokenRef?: string;
  authorizerAccessTokenRef?: string;
  componentTicketRef?: string;
  componentTicketExpiresAt?: string;
  componentBindingStatus?: WechatComponentBindingStatus;
  displayName?: string;
  loginMode?: string;
  scope?: string;
  redirectUris?: string[];
  endpointUrl?: string;
  secretRef?: string;
}

export interface ApplicationPlatformUpdateRequest {
  type?: ApplicationPlatformType;
  externalAppId?: string;
  componentAppId?: string;
  authorizedAppId?: string;
  authorizerAppId?: string;
  componentBinding?: WechatComponentPlatformBinding;
  componentAppSecretRef?: string;
  componentVerifyTicketRef?: string;
  componentAccessTokenRef?: string;
  authorizerRefreshTokenRef?: string;
  authorizerAccessTokenRef?: string;
  componentTicketRef?: string;
  componentTicketExpiresAt?: string;
  componentBindingStatus?: WechatComponentBindingStatus;
  displayName?: string;
  loginMode?: string;
  scope?: string;
  redirectUris?: string[];
  endpointUrl?: string;
}

export interface ApplicationClientCreateRequest {
  applicationType?: ApplicationType;
  clientKind?: ApplicationClientKind;
  clientType?: ApplicationClientKind;
  clientId: string;
  clientIdScope?: ApplicationClientIdScope;
  redirectUris?: string[];
  postLogoutRedirectUris?: string[];
  redirectUriPolicy?: OidcRpRedirectUriPolicy;
  pkceMethod?: OidcRpPkceMethod;
  consent?: OidcRpConsent;
  consentRequired?: boolean;
  requireExplicitConsent?: boolean;
  rpClient?: OidcRpClient;
  grantTypes?: string[];
  responseTypes?: string[];
  scopes?: string[];
  tokenEndpointAuthMethod?: ApplicationTokenEndpointAuthMethod;
  tokenEndpointAuthSigningAlg?: ApplicationClientAuthSigningAlgorithm;
  jwksUri?: string;
  privateKeyRef?: string;
  keyId?: string;
  requirePkce?: boolean;
  secretRef?: string;
}

export interface ApplicationClientUpdateRequest {
  applicationType?: ApplicationType;
  clientKind?: ApplicationClientKind;
  clientType?: ApplicationClientKind;
  clientId?: string;
  clientIdScope?: ApplicationClientIdScope;
  redirectUris?: string[];
  postLogoutRedirectUris?: string[];
  redirectUriPolicy?: OidcRpRedirectUriPolicy;
  pkceMethod?: OidcRpPkceMethod;
  consent?: OidcRpConsent;
  consentRequired?: boolean;
  requireExplicitConsent?: boolean;
  rpClient?: OidcRpClient;
  grantTypes?: string[];
  responseTypes?: string[];
  scopes?: string[];
  tokenEndpointAuthMethod?: ApplicationTokenEndpointAuthMethod;
  tokenEndpointAuthSigningAlg?: ApplicationClientAuthSigningAlgorithm;
  jwksUri?: string;
  privateKeyRef?: string;
  keyId?: string;
  requirePkce?: boolean;
}

export type ApplicationSharedClientCreateRequest = ApplicationClientCreateRequest & {
  tokenEndpointAuthMethod: "client_secret_basic" | "client_secret_post";
  clientIdScope: ApplicationClientIdScope;
  secretRef: string;
};

export type ApplicationSharedClientUpdateRequest = ApplicationClientUpdateRequest & {
  tokenEndpointAuthMethod: "client_secret_basic" | "client_secret_post";
  clientIdScope: ApplicationClientIdScope;
};

export type ApplicationClientSharedCreateRequest = ApplicationSharedClientCreateRequest;
export type ApplicationClientSharedUpdateRequest = ApplicationSharedClientUpdateRequest;

export interface ApplicationClientRotateSecretRequest {
  secretRef: string;
  expectedVersion?: ApplicationVersion;
}

export type ApplicationClientSecretRotateRequest = ApplicationClientRotateSecretRequest;
export type ApplicationClientSecretRotationRequest = ApplicationClientRotateSecretRequest;
export type ApplicationRotateSecretRequest = ApplicationClientRotateSecretRequest;
export type ApplicationPlatformRotateSecretRequest = ApplicationClientRotateSecretRequest;
export type RotateApplicationClientSecretRequest = ApplicationClientRotateSecretRequest;

export interface ApplicationLifecycleActionRequest {
  expectedVersion?: ApplicationVersion;
}

export type ApplicationArchiveRequest = ApplicationLifecycleActionRequest;
export type ApplicationRestoreRequest = ApplicationLifecycleActionRequest;
export interface ApplicationPurgeRequest extends ApplicationLifecycleActionRequest {
  idempotencyKey?: string;
}
export type ApplicationValidateRequest = ApplicationLifecycleActionRequest;

export type ApplicationPurgeJobStatus = "queued" | "running" | "completed" | "failed";

export interface ApplicationPurgeJob {
  id: string;
  jobId: string;
  applicationId: string;
  resourceType?: "application" | "application-platform" | "application-client";
  resourceId?: string;
  operation: "purge";
  status: ApplicationPurgeJobStatus;
  expectedVersion?: ApplicationVersion;
  createdAt: string;
  idempotencyKey?: string;
}

export type CreateApplicationRequest = ApplicationCreateRequest;
export type UpdateApplicationRequest = ApplicationUpdateRequest;
export type CreateApplicationPlatformRequest = ApplicationPlatformCreateRequest;
export type UpdateApplicationPlatformRequest = ApplicationPlatformUpdateRequest;
export type CreatePlatformRequest = ApplicationPlatformCreateRequest;
export type UpdatePlatformRequest = ApplicationPlatformUpdateRequest;
export type CreateApplicationClientRequest = ApplicationClientCreateRequest;
export type UpdateApplicationClientRequest = ApplicationClientUpdateRequest;
export type CreateClientRequest = ApplicationClientCreateRequest;
export type UpdateClientRequest = ApplicationClientUpdateRequest;

export interface ApplicationListQuery {
  cursor?: string;
  limit?: number | string;
  pageSize?: number | string;
  page?: number | string;
  offset?: number | string;
  search?: string;
  q?: string;
  status?: ApplicationStatus;
  applicationType?: ApplicationType;
  readiness?: ApplicationReadinessStatus;
  effectiveStatus?: ApplicationEffectiveStatus;
}

export interface ApplicationPlatformListQuery {
  cursor?: string;
  limit?: number | string;
  pageSize?: number | string;
  page?: number | string;
  offset?: number | string;
  search?: string;
  q?: string;
  status?: ApplicationStatus;
  readiness?: ApplicationReadinessStatus;
  effectiveStatus?: ApplicationEffectiveStatus;
}

export interface ApplicationExternalIdentityListQuery {
  cursor?: string;
  limit?: number | string;
  pageSize?: number | string;
  page?: number | string;
  offset?: number | string;
  search?: string;
  q?: string;
  provider?: string;
  platformId?: string;
}

export interface ApplicationClientListQuery {
  cursor?: string;
  limit?: number | string;
  pageSize?: number | string;
  page?: number | string;
  offset?: number | string;
  search?: string;
  q?: string;
  status?: ApplicationClientStatus;
  readiness?: ApplicationReadinessStatus;
  effectiveStatus?: ApplicationEffectiveStatus;
  clientKind?: ApplicationClientKind;
}

export interface ApplicationPage<T> {
  items: T[];
  nextCursor?: string;
  hasMore: boolean;
  total: number;
}

export type ApplicationsPage = ApplicationPage<ApplicationSummary>;
export type ApplicationPlatformsPage = ApplicationPage<ApplicationPlatformSummary>;
export type ApplicationClientsPage = ApplicationPage<ApplicationClientSummary>;
export type ApplicationExternalIdentitiesPage = ApplicationPage<ApplicationExternalIdentitySummary>;

export type ApplicationValidationSeverity = "error" | "warning" | "info";

export interface ApplicationValidationIssue {
  code?: string;
  field?: string;
  path?: string;
  message: string;
  severity?: ApplicationValidationSeverity;
}

export interface ApplicationValidationResult {
  applicationId: string;
  applicationType?: ApplicationType;
  valid: boolean;
  status: "valid" | "invalid";
  issues: ApplicationValidationIssue[];
  readiness?: ApplicationReadiness;
  effectiveStatus?: ApplicationEffectiveStatus;
  version?: ApplicationVersion;
  etag?: string;
  checkedAt: string;
}

export type ValidateApplicationResponse = ApplicationValidationResult;
export type ApplicationValidationResponse = ApplicationValidationResult;

export interface ApplicationExternalIdentitySummary {
  id: string;
  applicationId: string;
  platformId?: string;
  provider: string;
  platform?: string;
  appId?: string;
  subject: string;
  externalAppId?: string;
  openid?: string;
  unionid?: string;
  nickname?: string;
  displayName?: string;
  email?: string;
  avatarUrl?: string;
  scopes?: string[];
  canonicalUserId?: string;
  linkStatus?: "linked" | "pending" | "rejected" | "revoked" | string;
  emailVerified?: boolean;
  firstLinkedAt?: string;
  version?: ApplicationVersion;
  linkedAt?: string;
  lastAuthenticatedAt?: string;
  createdAt?: string;
  updatedAt?: string;
}

export type ApplicationExternalIdentity = ApplicationExternalIdentitySummary;
export type ApplicationExternalIdentityDto = ApplicationExternalIdentitySummary;
export type ExternalApplicationIdentitySummary = ApplicationExternalIdentitySummary;
export type ExternalIdentitySummary = ApplicationExternalIdentitySummary;
export type ExternalIdentityDto = ApplicationExternalIdentitySummary;
export type ApplicationIdentitySummary = ApplicationExternalIdentitySummary;

export const APPLICATION_MANAGEMENT_PERMISSIONS = {
  applicationsRead: "applications:read",
  applicationsWrite: "applications:write",
  applicationsValidate: "applications:validate",
  applicationsEnable: "applications:enable",
  applicationsDisable: "applications:disable",
  applicationsArchive: "applications:archive",
  applicationsRestore: "applications:restore",
  applicationsPurge: "applications:purge",
  platformsRead: "application-platforms:read",
  platformsWrite: "application-platforms:write",
  platformsValidate: "application-platforms:validate",
  platformsEnable: "application-platforms:enable",
  platformsDisable: "application-platforms:disable",
  platformsArchive: "application-platforms:archive",
  platformsRestore: "application-platforms:restore",
  platformsPurge: "application-platforms:purge",
  platformsRotateSecret: "application-platforms:rotate-secret",
  platformsRevokeSecret: "application-platforms:revoke-secret",
  clientsRead: "application-clients:read",
  clientsWrite: "application-clients:write",
  clientsValidate: "application-clients:validate",
  clientsEnable: "application-clients:enable",
  clientsDisable: "application-clients:disable",
  clientsArchive: "application-clients:archive",
  clientsRestore: "application-clients:restore",
  clientsPurge: "application-clients:purge",
  clientsRotateSecret: "application-clients:rotate-secret",
  clientsRevokeSecret: "application-clients:revoke-secret",
  externalIdentitiesRead: "application-external-identities:read",
  applicationPlatformsRead: "application-platforms:read",
  applicationPlatformsWrite: "application-platforms:write",
  applicationPlatformsValidate: "application-platforms:validate",
  applicationPlatformsEnable: "application-platforms:enable",
  applicationPlatformsDisable: "application-platforms:disable",
  applicationPlatformsArchive: "application-platforms:archive",
  applicationPlatformsRestore: "application-platforms:restore",
  applicationPlatformsPurge: "application-platforms:purge",
  applicationPlatformsRotateSecret: "application-platforms:rotate-secret",
  applicationPlatformsRevokeSecret: "application-platforms:revoke-secret",
  applicationClientsRead: "application-clients:read",
  applicationClientsWrite: "application-clients:write",
  applicationClientsValidate: "application-clients:validate",
  applicationClientsEnable: "application-clients:enable",
  applicationClientsDisable: "application-clients:disable",
  applicationClientsArchive: "application-clients:archive",
  applicationClientsRestore: "application-clients:restore",
  applicationClientsPurge: "application-clients:purge",
  applicationClientsRotateSecret: "application-clients:rotate-secret",
  applicationClientsRevokeSecret: "application-clients:revoke-secret",
  applicationExternalIdentitiesRead: "application-external-identities:read",
  applicationRead: "applications:read",
  applicationWrite: "applications:write",
  applicationValidate: "applications:validate",
  applicationEnable: "applications:enable",
  applicationDisable: "applications:disable",
  applicationArchive: "applications:archive",
  applicationRestore: "applications:restore",
  applicationPurge: "applications:purge",
  applicationPlatformRead: "application-platforms:read",
  applicationPlatformWrite: "application-platforms:write",
  applicationPlatformValidate: "application-platforms:validate",
  applicationPlatformEnable: "application-platforms:enable",
  applicationPlatformDisable: "application-platforms:disable",
  applicationPlatformArchive: "application-platforms:archive",
  applicationPlatformRestore: "application-platforms:restore",
  applicationPlatformPurge: "application-platforms:purge",
  applicationPlatformRotateSecret: "application-platforms:rotate-secret",
  applicationPlatformRevokeSecret: "application-platforms:revoke-secret",
  applicationClientRead: "application-clients:read",
  applicationClientWrite: "application-clients:write",
  applicationClientValidate: "application-clients:validate",
  applicationClientEnable: "application-clients:enable",
  applicationClientDisable: "application-clients:disable",
  applicationClientArchive: "application-clients:archive",
  applicationClientRestore: "application-clients:restore",
  applicationClientPurge: "application-clients:purge",
  applicationClientRotateSecret: "application-clients:rotate-secret",
  applicationClientRevokeSecret: "application-clients:revoke-secret",
} as const;

export const APPLICATION_PERMISSIONS = APPLICATION_MANAGEMENT_PERMISSIONS;
export const APPLICATION_MANAGEMENT_PERMISSION = APPLICATION_MANAGEMENT_PERMISSIONS;
export const APPLICATION_PERMISSION = APPLICATION_MANAGEMENT_PERMISSIONS;

export type ApplicationManagementPermission =
  (typeof APPLICATION_MANAGEMENT_PERMISSIONS)[keyof typeof APPLICATION_MANAGEMENT_PERMISSIONS];
export type ApplicationPermission = ApplicationManagementPermission;

export const APPLICATION_CLIENT_ROUTE_ALIASES = ["clients", "oidc-clients"] as const;
export const APPLICATION_PLATFORM_ROUTE_ALIASES = ["platforms", "application-platforms"] as const;
export const APPLICATION_PLATFORM_LOGIN_ROUTE_ALIASES = ["login", "oauth", "wechat"] as const;
export const APPLICATION_MANAGEMENT_ROUTE_ALIASES = {
  clients: "/clients",
  oidcClients: "/oidc-clients",
  platforms: "/platforms",
  platformLogin: "/login",
  webviewTicket: "/webview/ticket",
} as const;

export const OIDC_RP_CLIENT_TYPES = ["web"] as const;
export const OIDC_RP_CLIENT_KINDS = ["web"] as const;
export const OIDC_RP_REDIRECT_URI_POLICIES = ["exact"] as const;
export const OIDC_RP_PKCE_METHODS = ["S256"] as const;
export const OIDC_RP_CONSENT_MODES = ["explicit", "none"] as const;
export const OIDC_RP_GRANT_TYPES = ["authorization_code", "refresh_token"] as const;
export const OIDC_RP_RESPONSE_TYPES = ["code"] as const;
export const OIDC_RP_REDIRECT_URI_POLICY = "exact" as const;
export const OIDC_RP_REQUIRE_PKCE = true as const;
export const OIDC_RP_CONSENT_REQUIRED = true as const;

export type OidcRpClientType = (typeof OIDC_RP_CLIENT_TYPES)[number];
export type OidcRpClientKind = (typeof OIDC_RP_CLIENT_KINDS)[number];
export type OidcRpRedirectUriPolicy = (typeof OIDC_RP_REDIRECT_URI_POLICIES)[number];
export type OidcRpPkceMethod = (typeof OIDC_RP_PKCE_METHODS)[number];
export type OidcRpConsentMode = (typeof OIDC_RP_CONSENT_MODES)[number];
export type OidcRpGrantType = (typeof OIDC_RP_GRANT_TYPES)[number];
export type OidcRpResponseType = (typeof OIDC_RP_RESPONSE_TYPES)[number];

export interface OidcRpRedirectPolicy {
  mode: OidcRpRedirectUriPolicy;
  exact: true;
}

export interface OidcRpPkcePolicy {
  required: true;
  method?: OidcRpPkceMethod;
}

export interface StrictOidcRpPkcePolicy extends OidcRpPkcePolicy {
  method: OidcRpPkceMethod;
}

export interface OidcRpConsentPolicy {
  required: boolean;
  mode?: OidcRpConsentMode;
  scopes?: string[];
  sensitiveScopes?: string[];
  requireExplicitConsent?: boolean;
}

export interface StrictOidcRpConsentPolicy extends OidcRpConsentPolicy {
  mode: OidcRpConsentMode;
}

export type OidcRpConsent = OidcRpConsentPolicy | OidcRpConsentMode;

export interface OidcRpClient {
  clientId: string;
  clientType?: OidcRpClientType;
  clientKind?: OidcRpClientKind;
  redirectUris: string[];
  postLogoutRedirectUris?: string[];
  redirectUriPolicy?: OidcRpRedirectUriPolicy;
  redirectPolicy?: OidcRpRedirectPolicy;
  requirePkce?: boolean;
  pkceMethod?: OidcRpPkceMethod;
  pkce?: OidcRpPkcePolicy;
  consent?: OidcRpConsent;
  consentRequired?: boolean;
  requireExplicitConsent?: boolean;
  grantTypes?: OidcRpGrantType[];
  responseTypes?: OidcRpResponseType[];
  scopes?: string[];
}

export type OidcRPClient = OidcRpClient;
export type ApplicationOidcRpClient = OidcRpClient;
export type ApplicationOidcRpClientConfig = OidcRpClient;
export type OidcRpClientConfig = OidcRpClient;
export type OidcRpClientRegistration = OidcRpClient;
export type ApplicationOidcClient = OidcRpClient;

export interface StrictOidcRpClient extends OidcRpClient {
  clientType: "web";
  clientKind: "web";
  redirectUriPolicy: "exact";
  requirePkce: true;
  pkceMethod: "S256";
  pkce: StrictOidcRpPkcePolicy;
  consent: StrictOidcRpConsentPolicy;
}

export type OidcRpClientStrict = StrictOidcRpClient;
export type ApplicationOidcRpClientStrict = StrictOidcRpClient;

export interface OidcRpClientCreateRequest extends OidcRpClient {
  clientId: string;
  redirectUris: string[];
}

export interface OidcRpClientUpdateRequest {
  clientId?: string;
  clientType?: OidcRpClientType;
  clientKind?: OidcRpClientKind;
  redirectUris?: string[];
  postLogoutRedirectUris?: string[];
  redirectUriPolicy?: OidcRpRedirectUriPolicy;
  redirectPolicy?: OidcRpRedirectPolicy;
  requirePkce?: boolean;
  pkceMethod?: OidcRpPkceMethod;
  pkce?: OidcRpPkcePolicy;
  consent?: OidcRpConsent;
  consentRequired?: boolean;
  requireExplicitConsent?: boolean;
  grantTypes?: OidcRpGrantType[];
  responseTypes?: OidcRpResponseType[];
  scopes?: string[];
}

export const OPAQUE_CLIENT_SESSION_CLIENT_KINDS = ["mp_weixin", "native"] as const;
export const OPAQUE_CLIENT_SESSION_STATUSES = ["active", "expired", "revoked"] as const;
export type OpaqueClientSessionClientKind = (typeof OPAQUE_CLIENT_SESSION_CLIENT_KINDS)[number];
export type OpaqueClientSessionStatus = (typeof OPAQUE_CLIENT_SESSION_STATUSES)[number];

export interface OpaqueClientSession {
  sessionReference: string;
  expiresAt: string;
  clientKind: OpaqueClientSessionClientKind;
  sessionId?: string;
  sessionToken?: string;
  tokenType?: "Bearer";
}

export type ClientSession = OpaqueClientSession;
export type OpaqueSession = OpaqueClientSession;
export type OpaqueClientSessionDto = OpaqueClientSession;

export interface OpaqueClientSessionRecord {
  id: string;
  tenantId: string;
  applicationId: string;
  clientId: string;
  clientKind: OpaqueClientSessionClientKind;
  sessionHash: string;
  userId: string;
  status: OpaqueClientSessionStatus;
  deviceId?: string;
  bindingHash?: string;
  createdAt: string;
  updatedAt?: string;
  lastUsedAt?: string;
  expiresAt: string;
  revokedAt?: string;
}

export type OpaqueClientSessionStoreRecord = OpaqueClientSessionRecord;
export type ClientSessionRecord = OpaqueClientSessionRecord;

export interface OpaqueClientSessionIssueResult {
  session: OpaqueClientSession;
  record: OpaqueClientSessionRecord;
}

export type OpaqueClientSessionCreateResult = OpaqueClientSessionIssueResult;

export interface OpaqueClientSessionExchangeRequest {
  sessionReference: string;
  clientKind: OpaqueClientSessionClientKind;
  clientId?: string;
  applicationId?: string;
}

export interface OpaqueClientSessionExchangeResponse {
  userId: string;
  session: OpaqueClientSession;
}

export type PublicOpaqueClientSession = OpaqueClientSession;
export type OpaqueClientSessionPublicDto = OpaqueClientSession;
export type PublicClientSessionResponse = OpaqueClientSession;

export interface PublicPlatformUserDto {
  id: string;
  name: string;
  email: string | null;
  emailVerified: boolean;
  avatarUrl?: string;
}

export interface PublicPlatformIdentityDto {
  provider: string;
  platform: string;
  scopes: string[];
}

export interface PublicPlatformAccountDto {
  platform: string;
  scopes: string[];
}

export interface PublicPlatformSessionDto {
  sessionReference?: string;
  sessionId?: string;
  expiresAt?: string;
  clientKind?: ApplicationClientKind;
  tokenType?: "Bearer";
}

export type PlatformPublicSessionDto = PublicPlatformSessionDto;
export type PublicOpaquePlatformSessionDto = PublicPlatformSessionDto;
export type PublicPlatformSessionResponse = PublicPlatformSessionDto;

export interface PublicPlatformLoginStartRequest {
  redirectUri: string;
  returnTo?: string;
  scope?: string;
  clientKind?: ApplicationClientKind;
}

export interface PublicPlatformLoginStartResponse {
  authorizationUrl: string;
  state: string;
  expiresAt: string;
  client?: "web" | "webview" | "mp_weixin" | "native" | "mini_program";
}

export type PlatformPublicLoginStartRequest = PublicPlatformLoginStartRequest;
export type PlatformPublicLoginStartResponse = PublicPlatformLoginStartResponse;
export type ApplicationPlatformLoginStartRequest = PublicPlatformLoginStartRequest;
export type ApplicationPlatformLoginStartResponse = PublicPlatformLoginStartResponse;

export interface PublicPlatformLoginCallbackRequest {
  state: string;
  code?: string;
  authorizationCode?: string;
  error?: string | null;
  errorDescription?: string;
  redirectUri?: string;
}

export type PlatformPublicLoginCallbackRequest = PublicPlatformLoginCallbackRequest;
export type ApplicationPlatformLoginCallbackRequest = PublicPlatformLoginCallbackRequest;

export interface PublicPlatformSessionExchangeRequest {
  code: string;
  redirectUri?: string;
  clientKind?: Extract<ApplicationClientKind, "mp_weixin" | "native">;
}

export type PlatformPublicSessionExchangeRequest = PublicPlatformSessionExchangeRequest;
export type ApplicationPlatformSessionExchangeRequest = PublicPlatformSessionExchangeRequest;

export interface PublicPlatformLoginResultDto {
  user: PublicPlatformUserDto;
  session: PublicPlatformSessionDto;
  created: boolean;
  linked: boolean;
  client?: "web" | "webview" | "mp_weixin" | "native" | "mini_program";
}

export type PlatformPublicLoginResultDto = PublicPlatformLoginResultDto;
export type PublicPlatformSessionDtoResult = PublicPlatformLoginResultDto;
export type ApplicationPlatformPublicLoginResult = PublicPlatformLoginResultDto;
export type ApplicationPlatformSessionDto = PublicPlatformLoginResultDto;

export const WEBVIEW_TICKET_STATUSES = ["issued", "consumed", "expired", "revoked"] as const;
export type WebviewTicketStatus = (typeof WEBVIEW_TICKET_STATUSES)[number];

export interface WebviewTicket {
  ticketReference: string;
  ticket?: string;
  expiresAt: string;
  clientKind: "webview";
  redirectUri: string;
  sessionReference?: string;
  applicationId?: string;
  platformId?: string;
  client?: Extract<ApplicationClientKind, "webview" | "mp_weixin" | "native">;
}

export type PublicWebviewTicket = WebviewTicket;
export type WebviewTicketDto = WebviewTicket;
export type WebviewTicketPublicDto = WebviewTicket;

export interface WebviewTicketRecord {
  id: string;
  tenantId: string;
  applicationId: string;
  platformId: string;
  clientId?: string;
  ticketHash: string;
  sessionHash?: string;
  bindingHash?: string;
  redirectUri: string;
  status: WebviewTicketStatus;
  createdAt: string;
  updatedAt?: string;
  expiresAt: string;
  consumedAt?: string;
  revokedAt?: string;
}

export type WebviewTicketStoreRecord = WebviewTicketRecord;

export interface WebviewTicketIssueRequest {
  applicationId: string;
  platformId: string;
  clientId?: string;
  redirectUri: string;
  sessionReference?: string;
  binding?: string;
  expiresInSeconds?: number;
  ticketReference?: string;
  ticket?: string;
}

export interface WebviewTicketIssueResult {
  ticket: WebviewTicket;
  record: WebviewTicketRecord;
}

export interface WebviewTicketConsumeRequest {
  ticketReference: string;
  clientId?: string;
  sessionReference?: string;
  binding?: string;
}

export type WebviewTicketExchangeRequest = WebviewTicketConsumeRequest;
export type WebviewTicketExchangeResult = WebviewTicketRecord;

export const WECHAT_COMPONENT_PLATFORM_TYPES = ["wechat_component", "wechat_open_platform_component"] as const;
export const WECHAT_COMPONENT_BINDING_STATUSES = ["pending", "active", "expired", "revoked", "unbound"] as const;
export type WechatComponentPlatformType = (typeof WECHAT_COMPONENT_PLATFORM_TYPES)[number];
export type WechatComponentBindingStatus = (typeof WECHAT_COMPONENT_BINDING_STATUSES)[number];

export interface WechatComponentPlatformBinding {
  componentAppId: string;
  authorizedAppId?: string;
  authorizerAppId?: string;
  componentAppSecretRef?: string;
  componentVerifyTicketRef?: string;
  componentAccessTokenRef?: string;
  authorizerRefreshTokenRef?: string;
  authorizerAccessTokenRef?: string;
  componentTicketRef?: string;
  componentTicketExpiresAt?: string;
  status?: WechatComponentBindingStatus;
  version?: ApplicationVersion;
  scope?: string;
}

export type WechatThirdPartyPlatformBinding = WechatComponentPlatformBinding;
export type WechatOpenPlatformBinding = WechatComponentPlatformBinding;
export type WechatComponentBinding = WechatComponentPlatformBinding;

export interface WechatComponentPlatformBindingSummary {
  componentAppId: string;
  authorizedAppId?: string;
  authorizerAppId?: string;
  componentTicketExpiresAt?: string;
  status: WechatComponentBindingStatus;
  version?: ApplicationVersion;
  scope?: string;
}

export type WechatThirdPartyPlatformBindingSummary = WechatComponentPlatformBindingSummary;

export interface WechatComponentAuthorizerBinding extends WechatComponentPlatformBinding {
  authorizerAppId: string;
}

export type WechatComponentAuthorizer = WechatComponentAuthorizerBinding;

export type ApplicationPlatformOpaqueClient = "mp_weixin" | "native" | "mini_program";

export interface OpaqueClientSessionRequest {
  sessionReference: string;
  client?: ApplicationPlatformOpaqueClient;
  userId?: string;
}

export type ApplicationPlatformSessionRequest = OpaqueClientSessionRequest;

export interface OpaqueClientSessionResult {
  sessionReference: string;
  expiresAt: string;
  userId: string;
  applicationId: string;
  platformId: string;
  client: ApplicationPlatformOpaqueClient;
  identityKey?: string;
  refreshed?: boolean;
  revoked?: boolean;
}

export type ApplicationPlatformOpaqueSessionResult = OpaqueClientSessionResult;
export type PublicClientSessionDto = OpaqueClientSessionResult;

export interface ApplicationPlatformWebviewTicketIssueInput {
  sessionReference: string;
  userId?: string;
  client?: ApplicationPlatformOpaqueClient;
  clientId?: string;
  applicationId?: string;
  platformId?: string;
  ttlSeconds?: number;
}

export interface ApplicationPlatformWebviewTicket {
  ticket: string;
  expiresAt: string;
  sessionReference?: string;
  applicationId?: string;
  platformId?: string;
  client?: ApplicationPlatformOpaqueClient;
}

export type PublicApplicationPlatformWebviewTicket = ApplicationPlatformWebviewTicket;
export type PlatformWebviewTicketDto = ApplicationPlatformWebviewTicket;

export function isApplicationClientKind(value: unknown): value is ApplicationClientKind {
  return typeof value === "string" && (APPLICATION_CLIENT_KINDS as readonly string[]).includes(value);
}

export function assertApplicationClientKind(value: unknown): ApplicationClientKind {
  if (!isApplicationClientKind(value)) throw new TypeError("Invalid application client kind");
  return value;
}

export const validateApplicationClientKind = assertApplicationClientKind;
export const validateClientKind = assertApplicationClientKind;

export function isOidcRpClientType(value: unknown): value is OidcRpClientType {
  return value === "web";
}

export function isOidcRpPkceMethod(value: unknown): value is OidcRpPkceMethod {
  return typeof value === "string" && (OIDC_RP_PKCE_METHODS as readonly string[]).includes(value);
}

export function isOidcRpRedirectUri(value: unknown, options: { allowInsecureHttp?: boolean } = {}): value is string {
  if (typeof value !== "string" || value.length === 0 || value.length > 2048 || value !== value.trim()) return false;
  if (/[\u0000-\u001f\u007f\s\\]/u.test(value)) return false;
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    return false;
  }
  if (parsed.protocol !== "https:" && parsed.protocol !== "http:") return false;
  if (parsed.protocol === "http:" && options.allowInsecureHttp !== true) return false;
  if (parsed.username !== "" || parsed.password !== "" || parsed.hash !== "" || parsed.hostname.length === 0) return false;
  return parsed.toString() === value || parsed.origin !== "null";
}

export function validateOidcRpRedirectUri(value: unknown, options: { allowInsecureHttp?: boolean } = {}): string {
  if (!isOidcRpRedirectUri(value, options)) throw new TypeError("Invalid OIDC RP redirect URI");
  return value;
}

export function validateOidcRpRedirectUris(value: unknown, options: { allowInsecureHttp?: boolean } = {}): string[] {
  if (!Array.isArray(value) || value.length === 0 || value.length > 100) throw new TypeError("OIDC RP redirect URIs are required");
  const output: string[] = [];
  for (const item of value) {
    const normalized = validateOidcRpRedirectUri(item, options);
    if (output.includes(normalized)) throw new TypeError("Duplicate OIDC RP redirect URI");
    output.push(normalized);
  }
  return output;
}

export function validateOidcRpPkce(value: unknown): OidcRpPkcePolicy {
  if (!isRecord(value) || value.required !== true || !isOidcRpPkceMethod(value.method)) {
    throw new TypeError("OIDC RP clients require S256 PKCE");
  }
  return { required: true, method: value.method };
}

export function validateOidcRpConsent(value: unknown): OidcRpConsentPolicy {
  if (value === "explicit") return { required: true, mode: "explicit" };
  if (value === "none") return { required: false, mode: "none" };
  if (!isRecord(value)) throw new TypeError("Invalid OIDC RP consent policy");
  const required = typeof value.required === "boolean"
    ? value.required
    : typeof value.requireExplicitConsent === "boolean"
      ? value.requireExplicitConsent
      : undefined;
  const mode = value.mode === undefined && required !== undefined ? (required ? "explicit" : "none") : value.mode;
  if (required === undefined || (mode !== "explicit" && mode !== "none")) throw new TypeError("Invalid OIDC RP consent policy");
  if (mode === "explicit" && required !== true) throw new TypeError("Explicit OIDC RP consent is required");
  const scopes = value.scopes === undefined ? undefined : validateStringList(value.scopes, "consent scopes");
  const sensitiveScopes = value.sensitiveScopes === undefined ? undefined : validateStringList(value.sensitiveScopes, "sensitive consent scopes");
  return {
    required,
    mode,
    ...(scopes === undefined ? {} : { scopes }),
    ...(sensitiveScopes === undefined ? {} : { sensitiveScopes }),
    ...(typeof value.requireExplicitConsent === "boolean" ? { requireExplicitConsent: value.requireExplicitConsent } : {}),
  };
}

export function isOpaqueClientSession(value: unknown): value is OpaqueClientSession {
  if (!isRecord(value) || !isOpaqueReference(value.sessionReference) || !isDateString(value.expiresAt)) return false;
  return value.clientKind === "mp_weixin" || value.clientKind === "native";
}

export function assertOpaqueClientSession(value: unknown): OpaqueClientSession {
  if (!isOpaqueClientSession(value)) throw new TypeError("Opaque client session is invalid");
  return value;
}

export function isWebviewTicket(value: unknown): value is WebviewTicket {
  return isRecord(value) && isOpaqueReference(value.ticketReference) && value.clientKind === "webview" && isDateString(value.expiresAt) && typeof value.redirectUri === "string";
}

export function assertWebviewTicket(value: unknown): WebviewTicket {
  if (!isWebviewTicket(value)) throw new TypeError("Webview ticket is invalid");
  return value;
}

export function isWechatComponentPlatformBinding(value: unknown): value is WechatComponentPlatformBinding {
  if (!isRecord(value) || typeof value.componentAppId !== "string") return false;
  return typeof value.authorizedAppId === "string" || typeof value.authorizerAppId === "string";
}

export function validateOidcRpClient(
  value: unknown,
  options: { allowInsecureHttp?: boolean } = {},
): OidcRpClient {
  if (!isRecord(value)) throw new TypeError("OIDC RP client is invalid");
  const clientId = requiredContractText(value.clientId, "clientId", 512);
  if (value.clientType !== undefined && !isOidcRpClientType(value.clientType)) throw new TypeError("Invalid OIDC RP client type");
  if (value.clientKind !== undefined && value.clientKind !== "web") throw new TypeError("Invalid OIDC RP client kind");
  const redirectUris = validateOidcRpRedirectUris(value.redirectUris, options);
  const postLogoutRedirectUris = value.postLogoutRedirectUris === undefined
    ? undefined
    : validateOidcRpRedirectUris(value.postLogoutRedirectUris, options);
  if (value.redirectUriPolicy !== undefined && value.redirectUriPolicy !== "exact") throw new TypeError("Invalid OIDC RP redirect policy");
  if (value.redirectPolicy !== undefined && (!isRecord(value.redirectPolicy) || value.redirectPolicy.mode !== "exact" || value.redirectPolicy.exact !== true)) {
    throw new TypeError("Invalid OIDC RP redirect policy");
  }
  const pkce = value.pkce === undefined ? { required: true as const, method: "S256" as const } : validateOidcRpPkce(value.pkce);
  if (value.requirePkce !== undefined && value.requirePkce !== true) throw new TypeError("OIDC RP clients require PKCE");
  if (value.pkceMethod !== undefined && !isOidcRpPkceMethod(value.pkceMethod)) throw new TypeError("OIDC RP clients require S256 PKCE");
  if (value.consentRequired !== undefined && value.consentRequired !== true) throw new TypeError("OIDC RP clients require explicit consent");
  if (value.requireExplicitConsent !== undefined && value.requireExplicitConsent !== true) throw new TypeError("OIDC RP clients require explicit consent");
  const consent = value.consent === undefined ? validateOidcRpConsent("explicit") : validateOidcRpConsent(value.consent);
  if (consent.mode !== "explicit" || consent.required !== true) throw new TypeError("OIDC RP clients require explicit consent");
  const grantTypes = value.grantTypes === undefined ? ["authorization_code" as const] : validateEnumList(value.grantTypes, OIDC_RP_GRANT_TYPES, "grant types");
  const responseTypes = value.responseTypes === undefined ? ["code" as const] : validateEnumList(value.responseTypes, OIDC_RP_RESPONSE_TYPES, "response types");
  if (!grantTypes.includes("authorization_code")) throw new TypeError("OIDC RP clients must support authorization code");
  if (!responseTypes.includes("code")) throw new TypeError("OIDC RP clients must support code response");
  const scopes = value.scopes === undefined ? ["openid"] : validateStringList(value.scopes, "scopes");
  if (!scopes.includes("openid")) throw new TypeError("OIDC RP clients must include openid");
  return {
    clientId,
    clientType: "web",
    clientKind: "web",
    redirectUris,
    ...(postLogoutRedirectUris === undefined ? {} : { postLogoutRedirectUris }),
    redirectUriPolicy: "exact",
    redirectPolicy: { mode: "exact", exact: true },
    requirePkce: true,
    pkceMethod: "S256",
    pkce,
    consent,
    grantTypes: [...grantTypes],
    responseTypes: [...responseTypes],
    scopes,
  };
}

function validateEnumList<T extends string>(value: unknown, allowed: readonly T[], field: string): T[] {
  if (!Array.isArray(value) || value.length === 0 || value.length > allowed.length) throw new TypeError(`Invalid ${field}`);
  const output: T[] = [];
  for (const item of value) {
    if (typeof item !== "string" || !(allowed as readonly string[]).includes(item) || output.includes(item as T)) throw new TypeError(`Invalid ${field}`);
    output.push(item as T);
  }
  return output;
}

function validateStringList(value: unknown, field: string): string[] {
  if (!Array.isArray(value) || value.length > 100) throw new TypeError(`Invalid ${field}`);
  const output: string[] = [];
  for (const item of value) {
    const normalized = requiredContractText(item, field, 512);
    if (output.includes(normalized)) throw new TypeError(`Duplicate ${field}`);
    output.push(normalized);
  }
  return output;
}

function isOpaqueReference(value: unknown): value is string {
  return typeof value === "string" && /^[A-Za-z0-9_-]{16,512}$/u.test(value);
}

function isDateString(value: unknown): value is string {
  if (typeof value !== "string" || value.length > 128) return false;
  const date = new Date(value);
  return !Number.isNaN(date.getTime());
}

function requiredContractText(value: unknown, field: string, maxLength: number): string {
  if (typeof value !== "string") throw new TypeError(`Invalid ${field}`);
  const normalized = value.trim();
  if (normalized.length === 0 || normalized.length > maxLength || /[\u0000-\u001f\u007f]/u.test(normalized)) throw new TypeError(`Invalid ${field}`);
  return normalized;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export const CLIENT_AUTH_BFF_CLIENT_TYPES = ["web", "native"] as const;
export const CLIENT_AUTH_BFF_CODE_CHALLENGE_METHODS = ["S256"] as const;
export const CLIENT_AUTH_BFF_ROUTE_BASE = "/api/idaas/v1/client/auth";
export const CLIENT_AUTH_BFF_SESSION_HEADER = "x-client-session";
export const CLIENT_AUTH_BFF_ROUTES = {
  start: "/api/idaas/v1/client/auth/oidc/start",
  exchange: "/api/idaas/v1/client/auth/oidc/exchange",
  callback: "/api/idaas/v1/client/auth/oidc/callback",
  refresh: "/api/idaas/v1/client/auth/refresh",
  refreshAlias: "/api/idaas/v1/client/auth/session/refresh",
  logout: "/api/idaas/v1/client/auth/logout",
  logoutAlias: "/api/idaas/v1/client/auth/session/logout",
  me: "/api/idaas/v1/client/auth/me",
} as const;

export type ClientAuthBffClientType = (typeof CLIENT_AUTH_BFF_CLIENT_TYPES)[number];
export type ClientAuthBffCodeChallengeMethod = (typeof CLIENT_AUTH_BFF_CODE_CHALLENGE_METHODS)[number];

export interface ClientAuthBffStartRequest {
  redirectUri: string;
  clientType: ClientAuthBffClientType;
  clientId: string;
  scope: string;
  state: string;
  nonce: string;
  codeChallenge: string;
  codeChallengeMethod: ClientAuthBffCodeChallengeMethod;
}

export interface ClientAuthBffExchangeRequest {
  code: string;
  codeVerifier: string;
  redirectUri: string;
  state: string;
  clientId: string;
  clientType: ClientAuthBffClientType;
}

export interface ClientAuthBffSessionReferenceRequest {
  sessionReference: string;
}

export interface ClientAuthBffStartResponse {
  authorizationUrl: string;
  state: string;
  expiresAt: string;
  redirectUri: string;
}

export interface ClientAuthBffUserDto {
  id: string;
  name: string;
  email: string | null;
  emailVerified: boolean;
  avatarUrl?: string;
}

export interface ClientAuthBffSessionResultDto {
  sessionReference: string;
  expiresAt: string;
  clientKind: ClientAuthBffClientType;
  user: ClientAuthBffUserDto;
}

export interface ClientAuthBffWebExchangeResponse {
  status: 204;
}

export interface ClientAuthBffWebMeResponse {
  user: ClientAuthBffUserDto;
}

export type ClientAuthBffSessionResponse = ClientAuthBffSessionResultDto;
export type ClientAuthBffExchangeResponse = ClientAuthBffSessionResultDto | ClientAuthBffWebExchangeResponse;
export type ClientAuthBffMeResponse = ClientAuthBffSessionResultDto;
export type ClientAuthBffRefreshRequest = ClientAuthBffSessionReferenceRequest;
export type ClientAuthBffLogoutRequest = ClientAuthBffSessionReferenceRequest;
export type ClientAuthBffRefreshResponse = ClientAuthBffSessionResultDto;
export type ClientAuthBffLogoutResponse = ClientAuthBffSessionResultDto;
export type UniAppClientAuthStartRequest = ClientAuthBffStartRequest;
export type UniAppClientAuthExchangeRequest = ClientAuthBffExchangeRequest;
export type UniAppClientAuthStartResponse = ClientAuthBffStartResponse;
export type UniAppClientAuthSessionResponse = ClientAuthBffSessionResultDto;
export type PublicClientAuthBffStartResponse = ClientAuthBffStartResponse;
export type PublicClientAuthBffSessionResult = ClientAuthBffSessionResultDto;
export type ClientAuthStartRequest = ClientAuthBffStartRequest;
export type ClientAuthExchangeRequest = ClientAuthBffExchangeRequest;
export type ClientAuthStartResponse = ClientAuthBffStartResponse;
export type ClientAuthUserDto = ClientAuthBffUserDto;
export type ClientAuthBffPublicUserDto = ClientAuthBffUserDto;
export type ClientAuthSessionDto = ClientAuthBffSessionResultDto;
export type ClientAuthSessionResponse = ClientAuthBffSessionResultDto;
export type ClientAuthMeResponse = ClientAuthBffMeResponse;
export type ClientAuthRefreshRequest = ClientAuthBffSessionReferenceRequest;
export type ClientAuthLogoutRequest = ClientAuthBffSessionReferenceRequest;
