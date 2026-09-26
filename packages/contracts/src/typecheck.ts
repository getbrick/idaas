import type {
  ApplicationClientCreateRequest,
  ApplicationClientKind,
  ApplicationClientAuthSigningAlgorithm,
  ApplicationClientIdScope,
  ApplicationClientSummary,
  ApplicationSharedClientCreateRequest,
  ApplicationTokenEndpointAuthMethod,
  OidcRpClient,
  OpaqueClientSession,
  PublicPlatformLoginResultDto,
  WebviewTicket,
  WechatComponentPlatformBinding,
  ApplicationPlatformSummary,
  ApplicationSummary,
  AuditEventSummary,
  Capabilities,
  ControlPlaneContext,
  CursorPage,
  CursorPaginationRequest,
  ErrorEnvelope,
  OrganizationSummary,
  PermissionSummary,
  RequestId,
  RoleSummary,
  SessionSummary,
  SystemInfo,
  UserSummary,
} from "./index.js";
import {
  OIDC_CONSENT_GRANT_STATUSES,
  OIDC_ENDPOINT_SOURCES,
  OIDC_LOGOUT_TARGETS,
  OIDC_PROVIDER_CLIENT_AUTH_METHODS,
  OIDC_PROVIDER_CLIENT_KINDS,
} from "./index.js";
import {
  OPEN_PLATFORM_COMPLIANCE_CONSENT_STATUSES,
  OPEN_PLATFORM_COMPLIANCE_DATA_CLASSIFICATIONS,
  OPEN_PLATFORM_COMPLIANCE_ENTITY_KINDS,
  OPEN_PLATFORM_COMPLIANCE_ERROR_DEFINITIONS,
  OPEN_PLATFORM_COMPLIANCE_IDENTITY_VERIFICATION_STATUSES,
  OPEN_PLATFORM_COMPLIANCE_PRIVACY_REQUEST_STATUSES,
  OPEN_PLATFORM_COMPLIANCE_PRIVACY_REQUEST_TYPES,
  OPEN_PLATFORM_COMPLIANCE_REDACTED,
  OPEN_PLATFORM_COMPLIANCE_REPORT_LIMITATIONS,
  OPEN_PLATFORM_COMPLIANCE_RISK_LEVELS,
  OPEN_PLATFORM_COMPLIANCE_VENDOR_ROLES,
  canTransitionOpenPlatformCompliance,
  isOpenPlatformComplianceTerminalStatus,
  maskOpenPlatformComplianceSubjectRef,
  normalizeOpenPlatformCompliancePageRequest,
} from "./index.js";
import type {
  OpenPlatformComplianceConsentRecordDto,
  OpenPlatformComplianceCrossBorderAssessmentDto,
  OpenPlatformComplianceCrossBorderMechanism,
  OpenPlatformComplianceDataAssetDto,
  OpenPlatformComplianceEntityKind,
  OpenPlatformComplianceErrorCode,
  OpenPlatformComplianceEvidenceReference,
  OpenPlatformComplianceLegalBasis,
  OpenPlatformCompliancePrivacyRequestDto,
  OpenPlatformCompliancePrivacyRequestStatus,
  OpenPlatformCompliancePrivacyRequestType,
  OpenPlatformComplianceRedacted,
  OpenPlatformComplianceReport,
  OpenPlatformComplianceReportGapCode,
  OpenPlatformComplianceRetentionExecutionDto,
  OpenPlatformComplianceRiskLevel,
  OpenPlatformComplianceSlaState,
  OpenPlatformComplianceVendorDto,
  OpenPlatformComplianceContractError,
} from "./index.js";
import type {
  OidcConsentContext,
  OidcConsentDecision,
  OidcConsentGrant,
  OidcLogoutOperation,
  OidcLogoutResult,
  OidcProtocolError,
  OidcProviderClientMetadata,
  OidcResolvedProvider,
} from "./index.js";

type Assert<T extends true> = T;
type IsString<T> = T extends string ? true : false;
type IsUnknown<T> = unknown extends T ? ([keyof T] extends [never] ? true : false) : false;

type _RequestIdIsString = Assert<IsString<RequestId>>;
type _ErrorMessageIsString = Assert<IsString<ErrorEnvelope["message"]>>;
type _PageCursorIsOptionalString = Assert<IsString<NonNullable<CursorPage["nextCursor"]>>>;
type _CapabilitiesAcceptUnknown = Assert<IsUnknown<Capabilities[keyof Capabilities]>>;
type _ApplicationClientAuthMethodIsString = Assert<IsString<ApplicationTokenEndpointAuthMethod>>;
type _ApplicationClientSigningAlgorithmIsString = Assert<IsString<ApplicationClientAuthSigningAlgorithm>>;
type _ApplicationClientIdScopeIsGlobal = Assert<ApplicationClientIdScope extends "global" ? true : false>;
type _ApplicationClientKindIsStrict = Assert<ApplicationClientKind extends "web" | "webview" | "mp_weixin" | "native" ? true : false>;
type _OidcRpClientKindIsWeb = Assert<OidcRpClient["clientKind"] extends "web" | undefined ? true : false>;
type _OpaqueClientKindIsRestricted = Assert<OpaqueClientSession["clientKind"] extends "mp_weixin" | "native" ? true : false>;
type _WebviewTicketKindIsWebview = Assert<WebviewTicket["clientKind"] extends "webview" ? true : false>;
type _OidcEndpointSourcesAreStrict = Assert<typeof OIDC_ENDPOINT_SOURCES[number] extends "discovery" | "explicit" ? true : false>;
type _OidcProviderClientKindsAreStrict = Assert<typeof OIDC_PROVIDER_CLIENT_KINDS[number] extends "web" | "native" | "mp_weixin" | "webview" ? true : false>;
type _OidcProviderAuthMethodsAreStrict = Assert<typeof OIDC_PROVIDER_CLIENT_AUTH_METHODS[number] extends "none" | "client_secret_basic" | "client_secret_post" | "private_key_jwt" ? true : false>;
type _OidcConsentStatusesAreStrict = Assert<typeof OIDC_CONSENT_GRANT_STATUSES[number] extends "pending" | "active" | "denied" | "revoked" | "expired" ? true : false>;
type _OidcLogoutTargetsAreStrict = Assert<typeof OIDC_LOGOUT_TARGETS[number] extends "op_session" | "offline_grant" | "better_auth" | "bff_cookie" | "native_session" | "webview_ticket" ? true : false>;
type _OidcProviderMetadataHasNoSecretFields = Assert<"clientSecret" extends keyof OidcProviderClientMetadata ? false : true>;
type _OidcConsentContextHasNoTokenFields = Assert<"accessToken" extends keyof OidcConsentContext ? false : true>;
type _OidcLogoutOperationHasNoTokenFields = Assert<"idTokenHint" extends keyof OidcLogoutOperation ? false : true>;
type _OidcProtocolErrorHasStableCode = Assert<OidcProtocolError["code"] extends string ? true : false>;
type _OidcApprovedConsentRequiresUserGesture = Assert<Extract<OidcConsentDecision, { decision: "approved" }>["userGesture"] extends true ? true : false>;
type _OidcResolvedProviderUsesFrozenSource = Assert<OidcResolvedProvider["source"] extends "discovery" | "explicit" ? true : false>;
type _OidcResolvedProviderContractVersionIsStable = Assert<OidcResolvedProvider["contractVersion"] extends 1 ? true : false>;
type _OidcConsentGrantHasProjectionState = Assert<OidcConsentGrant["projectionStatus"] extends string ? true : false>;
type _OidcLogoutResultHasCompletionState = Assert<OidcLogoutResult["completed"] extends boolean ? true : false>;

type _ComplianceEntityKindsAreStrict = Assert<(typeof OPEN_PLATFORM_COMPLIANCE_ENTITY_KINDS)[number] extends "dataAsset" | "consentRecord" | "privacyRequest" | "retentionPolicy" | "retentionExecution" | "crossBorderAssessment" | "vendor" ? true : false>;
type _ComplianceClassificationsAreStrict = Assert<(typeof OPEN_PLATFORM_COMPLIANCE_DATA_CLASSIFICATIONS)[number] extends "internal" | "confidential" | "personal" | "sensitivePersonal" ? true : false>;
type _ComplianceConsentStatusesAreStrict = Assert<(typeof OPEN_PLATFORM_COMPLIANCE_CONSENT_STATUSES)[number] extends "pending" | "granted" | "withdrawn" | "expired" ? true : false>;
type _CompliancePrivacyRequestTypesAreStrict = Assert<(typeof OPEN_PLATFORM_COMPLIANCE_PRIVACY_REQUEST_TYPES)[number] extends "access" | "deletion" | "correction" | "revocation" | "portability" ? true : false>;
type _CompliancePrivacyRequestStatusesAreStrict = Assert<(typeof OPEN_PLATFORM_COMPLIANCE_PRIVACY_REQUEST_STATUSES)[number] extends "submitted" | "verifyingIdentity" | "verified" | "inProgress" | "fulfilled" | "partiallyFulfilled" | "rejected" | "cancelled" ? true : false>;
type _ComplianceRiskLevelsAreStrict = Assert<(typeof OPEN_PLATFORM_COMPLIANCE_RISK_LEVELS)[number] extends "low" | "medium" | "high" | "critical" ? true : false>;
type _ComplianceVendorRolesAreStrict = Assert<(typeof OPEN_PLATFORM_COMPLIANCE_VENDOR_ROLES)[number] extends "processor" | "subProcessor" ? true : false>;
type _ComplianceRetentionExecutionIsImmutableVersion = Assert<OpenPlatformComplianceRetentionExecutionDto["version"] extends 1 ? true : false>;
type _ComplianceConsentLegalBasisIsConsent = Assert<OpenPlatformComplianceConsentRecordDto["legalBasis"] extends "consent" ? true : false>;
type _ComplianceConsentDropsGrantedAtWhenPending = Assert<"grantedAt" extends keyof OpenPlatformComplianceConsentRecordDto ? true : false>;
type _ComplianceConsentKeepsOpaqueSubjectRef = Assert<OpenPlatformComplianceConsentRecordDto["subjectRef"] extends string ? true : false>;
type _CompliancePrivacyRequestKeepsOpaqueSubjectRef = Assert<OpenPlatformCompliancePrivacyRequestDto["subjectRef"] extends string ? true : false>;
type _ComplianceReportHasNoRawSubjectFields = Assert<"subjects" extends keyof OpenPlatformComplianceReport ? false : true>;
type _ComplianceReportAlwaysDeclaresRedaction = Assert<OpenPlatformComplianceReport["redaction"]["applies"] extends true ? true : false>;
type _ComplianceReportGapCodesAreStable = Assert<"privacyRequestSlaBreached" extends OpenPlatformComplianceReportGapCode ? true : false>;
type _ComplianceRedactedPlaceholderIsFixed = Assert<OpenPlatformComplianceRedacted extends "[redacted]" ? true : false>;
type _ComplianceMaskedSubjectRefHidesPrefix = Assert<ReturnType<typeof maskOpenPlatformComplianceSubjectRef> extends string ? true : false>;
type _ComplianceTerminalConsentIsWithdrawn = Assert<ReturnType<typeof isOpenPlatformComplianceTerminalStatus> extends boolean ? true : false>;
type _ComplianceWithdrawnConsentCannotBeRestored = Assert<ReturnType<typeof canTransitionOpenPlatformCompliance> extends boolean ? true : false>;
type _ComplianceConsentCanBeWithdrawnFromGranted = Assert<ReturnType<typeof canTransitionOpenPlatformCompliance> extends boolean ? true : false>;
type _CompliancePrivacyRequestRequiresVerification = Assert<ReturnType<typeof canTransitionOpenPlatformCompliance> extends boolean ? true : false>;
type _CompliancePrivacyRequestCanBeVerified = Assert<ReturnType<typeof canTransitionOpenPlatformCompliance> extends boolean ? true : false>;
type _ComplianceCrossBorderCanBeApproved = Assert<ReturnType<typeof canTransitionOpenPlatformCompliance> extends boolean ? true : false>;
type _ComplianceVendorCanBeSuspended = Assert<ReturnType<typeof canTransitionOpenPlatformCompliance> extends boolean ? true : false>;
type _ComplianceRetentionPolicyCanBeSuperseded = Assert<ReturnType<typeof canTransitionOpenPlatformCompliance> extends boolean ? true : false>;
type _ComplianceDataAssetCanBeRetired = Assert<ReturnType<typeof canTransitionOpenPlatformCompliance> extends boolean ? true : false>;
type _CompliancePageRequestLimitIsNormalized = Assert<ReturnType<typeof normalizeOpenPlatformCompliancePageRequest>["limit"] extends number ? true : false>;
type _ComplianceErrorHasStableCode = Assert<OpenPlatformComplianceContractError["code"] extends string ? true : false>;
type _ComplianceContractErrorMapsConflictTo409 = Assert<OpenPlatformComplianceContractError["status"] extends number ? true : false>;
type _ComplianceErrorDefinitionsAreClosed = Assert<keyof typeof OPEN_PLATFORM_COMPLIANCE_ERROR_DEFINITIONS extends OpenPlatformComplianceErrorCode ? true : false>;
type _ComplianceEntityKindCoversVendors = Assert<"vendor" extends OpenPlatformComplianceEntityKind ? true : false>;
type _ComplianceIdentityVerificationStatusesAreStrict = Assert<(typeof OPEN_PLATFORM_COMPLIANCE_IDENTITY_VERIFICATION_STATUSES)[number] extends "notStarted" | "pending" | "verified" | "failed" ? true : false>;
type _ComplianceLegalBasisCoversObligation = Assert<"legalObligation" extends OpenPlatformComplianceLegalBasis ? true : false>;
type _CompliancePrivacyRequestTypeCoversRevocation = Assert<"revocation" extends OpenPlatformCompliancePrivacyRequestType ? true : false>;
type _CompliancePrivacyRequestStatusCoversPartial = Assert<"partiallyFulfilled" extends OpenPlatformCompliancePrivacyRequestStatus ? true : false>;
type _CompliancePrivacyRequestSlaKeepsState = Assert<OpenPlatformCompliancePrivacyRequestDto["sla"]["state"] extends OpenPlatformComplianceSlaState ? true : false>;
type _ComplianceDataAssetLegalBasisIsDeclared = Assert<"legalBasis" extends keyof OpenPlatformComplianceDataAssetDto ? true : false>;
type _ComplianceDataAssetNeverExposesSubjects = Assert<"dataSubjects" extends keyof OpenPlatformComplianceDataAssetDto ? true : false>;
type _ComplianceCrossBorderMechanismsAreDeclared = Assert<OpenPlatformComplianceCrossBorderAssessmentDto["mechanisms"][number] extends OpenPlatformComplianceCrossBorderMechanism ? true : false>;
type _ComplianceCrossBorderCarriesRiskLevel = Assert<OpenPlatformComplianceCrossBorderAssessmentDto["riskLevel"] extends OpenPlatformComplianceRiskLevel ? true : false>;
type _ComplianceVendorCarriesAssessmentEvidence = Assert<OpenPlatformComplianceVendorDto["assessment"]["evidence"][number] extends OpenPlatformComplianceEvidenceReference ? true : false>;
type _ComplianceReportLimitationsAreNonEmpty = Assert<(typeof OPEN_PLATFORM_COMPLIANCE_REPORT_LIMITATIONS)[number] extends string ? true : false>;
type _ComplianceReportDeclaresNoLegalConclusion = Assert<(typeof OPEN_PLATFORM_COMPLIANCE_REPORT_LIMITATIONS)[number] extends `No legal conclusion${string}` | `The report records${string}` | `Cross-border mechanisms${string}` | `Counts are scoped${string}` ? true : false>;
type _ComplianceRetentionExecutionCarriesRunId = Assert<OpenPlatformComplianceRetentionExecutionDto["runId"] extends string ? true : false>;

const complianceReport: OpenPlatformComplianceReport = {
  contractVersion: 1,
  tenantId: "tenant-compliance",
  generatedAt: "2026-01-01T00:00:00.000Z",
  period: { from: "2025-01-01T00:00:00.000Z", to: "2026-01-01T00:00:00.000Z" },
  redaction: { placeholder: OPEN_PLATFORM_COMPLIANCE_REDACTED, applies: true },
  dataCatalog: {
    assets: { total: 1, counts: { active: 1 } },
    byClassification: { total: 1, counts: { personal: 1 } },
    personalDataAssets: 1,
    sensitivePersonalDataAssets: 0,
    crossBorderAssets: 0,
    withoutPurpose: [],
    withoutRetentionPolicy: [],
  },
  consent: {
    records: { total: 1, counts: { granted: 1 } },
    activeSubjects: 1,
    withdrawnSubjects: 0,
    withdrawnProofCount: 0,
  },
  privacyRequests: {
    requests: { total: 0, counts: {} },
    awaitingIdentityVerification: 0,
    fulfilledWithinSla: 0,
    breached: 0,
    oldestOpenDays: 0,
  },
  retention: {
    policies: { total: 0, counts: {} },
    executions: { total: 0, counts: {} },
    recordsDeleted: 0,
    recordsAnonymized: 0,
    failedExecutions: [],
  },
  crossBorder: {
    assessments: { total: 0, counts: {} },
    byRiskLevel: { total: 0, counts: {} },
    withoutMechanism: [],
    awaitingDecision: [],
  },
  vendors: {
    vendors: { total: 0, counts: {} },
    byRole: { total: 0, counts: {} },
    assessment: { total: 0, counts: {} },
    regions: [],
  },
  gaps: [
    {
      code: "privacyRequestSlaBreached",
      count: 1,
      resourceIds: ["privacy-request_00000000-0000-4000-8000-000000000000"],
    },
  ],
  limitations: [...OPEN_PLATFORM_COMPLIANCE_REPORT_LIMITATIONS],
};
const maskedComplianceSubject = maskOpenPlatformComplianceSubjectRef("subject-1234567890");

const requestId: RequestId = "req_01";
const pagination: CursorPaginationRequest = {
  cursor: "cursor_01",
  limit: "50",
};
const capabilities: Capabilities = {
  enabled: ["users", "organizations"],
  available: { audit: "stable" },
};
const error: ErrorEnvelope = {
  code: "INVALID_REQUEST",
  message: "The request is invalid",
  requestId,
  details: { field: "name" },
};
const user: UserSummary = {
  id: "user_01",
  email: "user@example.test",
  roles: ["member"],
};
const role: RoleSummary = {
  id: "role_01",
  code: "member",
  permissions: ["project:read"],
};
const permission: PermissionSummary = {
  id: "permission_01",
  key: "project:read",
};
const organization: OrganizationSummary = {
  id: "organization_01",
  name: "Example",
  memberCount: "1",
};
const session: SessionSummary = {
  id: "session_01",
  userId: user.id,
  status: "active",
};
const auditEvent: AuditEventSummary = {
  id: "audit_01",
  event: "session.created",
  requestId,
  detail: { source: "control-plane" },
};
const system: SystemInfo = {
  name: "idaas",
  version: "0.1.0",
  status: "ready",
  capabilities,
};
const page: CursorPage = {
  items: [user],
  nextCursor: "cursor_02",
  hasMore: "true",
};
const application: ApplicationSummary = {
  id: "application_01",
  name: "Example application",
  slug: "example-application",
  status: "active",
};
const platform: ApplicationPlatformSummary = {
  id: "platform_01",
  applicationId: application.id,
  type: "wechat_mini_program",
  redirectUris: [],
  credentialConfigured: false,
  status: "active",
};
const client: ApplicationClientSummary = {
  id: "client_01",
  applicationId: application.id,
  clientId: "client-01",
  status: "active",
  redirectUris: [],
  postLogoutRedirectUris: [],
  grantTypes: ["authorization_code"],
  responseTypes: ["code"],
  scopes: ["openid"],
  tokenEndpointAuthMethod: "none",
  requirePkce: true,
  hasSecret: false,
};
const confidentialClient: ApplicationClientCreateRequest = {
  applicationType: "web",
  clientId: "confidential-client",
  clientIdScope: "global",
  redirectUris: ["https://client.example.test/callback"],
  tokenEndpointAuthMethod: "private_key_jwt",
  tokenEndpointAuthSigningAlg: "EdDSA",
  privateKeyRef: "vault://clients/confidential-client",
};
const sharedClient: ApplicationSharedClientCreateRequest = {
  clientId: "shared-client",
  clientIdScope: "global",
  redirectUris: ["https://client.example.test/callback"],
  tokenEndpointAuthMethod: "client_secret_basic",
  secretRef: "vault://clients/shared-client",
};
const rpClient: OidcRpClient = {
  clientId: "rp-client",
  clientType: "web",
  clientKind: "web",
  redirectUris: ["https://client.example.test/callback"],
  redirectUriPolicy: "exact",
  requirePkce: true,
  pkceMethod: "S256",
  consent: { required: true, mode: "explicit" },
};
const resolvedOidcProvider: OidcResolvedProvider = {
  contractVersion: 1,
  issuer: "https://id.example.test/oidc",
  source: "explicit",
  endpoints: {
    authorization: "https://id.example.test/oidc/auth",
    token: "https://id.example.test/oidc/token",
    userInfo: "https://id.example.test/oidc/me",
    jwks: "https://id.example.test/oidc/jwks",
    endSession: "https://id.example.test/oidc/session/end",
  },
  allowedIdTokenAlgorithms: ["RS256"],
};
const oidcClientMetadata: OidcProviderClientMetadata = {
  clientId: "oidc-client",
  applicationType: "web",
  clientKind: "web",
  redirectUris: ["https://client.example.test/callback"],
  postLogoutRedirectUris: ["https://client.example.test/logout"],
  grantTypes: ["authorization_code", "refresh_token"],
  responseTypes: ["code"],
  scopes: ["openid", "offline_access"],
  tokenEndpointAuthMethod: "private_key_jwt",
  tokenEndpointAuthSigningAlgorithm: "RS256",
  requirePkce: true,
};
const oidcConsentContext: OidcConsentContext = {
  consentId: "consent-01",
  tenantId: "tenant-01",
  applicationId: "application-01",
  clientId: "oidc-client",
  userId: "user-01",
  grantId: "grant-01",
  interactionId: "interaction-01",
  requestedScopes: ["openid", "offline_access"],
  requestedClaims: ["email"],
  policyVersion: "policy-v1",
};
const oidcConsentDecision: OidcConsentDecision = {
  decision: "approved",
  consentId: oidcConsentContext.consentId,
  approvedScopes: ["openid", "offline_access"],
  approvedClaims: ["email"],
  policyVersion: "policy-v1",
  userGesture: true,
};
const oidcConsentGrant: OidcConsentGrant = {
  contractVersion: 1,
  consentId: "consent-01",
  tenantId: "tenant-01",
  applicationId: "application-01",
  clientId: "oidc-client",
  userId: "user-01",
  scopeHash: "scope-hash",
  claimHash: "claim-hash",
  policyVersion: "policy-v1",
  status: "active",
  projectionStatus: "projected",
  createdAt: "2026-01-01T00:00:00.000Z",
};
const oidcLogoutOperation: OidcLogoutOperation = {
  contractVersion: 1,
  operationId: "logout-01",
  tenantId: "tenant-01",
  applicationId: "application-01",
  clientId: "oidc-client",
  userId: "user-01",
  providerSessionId: "op-session-01",
  status: "pending",
  idempotencyKey: "logout-request-01",
  targets: ["op_session", "offline_grant", "better_auth"],
  createdAt: "2026-01-01T00:00:00.000Z",
  updatedAt: "2026-01-01T00:00:00.000Z",
};
const oidcLogoutResult: OidcLogoutResult = {
  operation: oidcLogoutOperation,
  revokedTargets: ["op_session", "offline_grant", "better_auth"],
  completed: true,
};
const oidcProtocolError: OidcProtocolError = {
  code: "temporarily_unavailable",
  category: "provider",
  retryable: true,
};
const opaqueSession: OpaqueClientSession = {
  sessionReference: "opaque-session-reference",
  expiresAt: "2026-01-01T00:00:00.000Z",
  clientKind: "mp_weixin",
  tokenType: "Bearer",
};
const webviewTicket: WebviewTicket = {
  ticketReference: "opaque-ticket-reference",
  expiresAt: "2026-01-01T00:00:00.000Z",
  clientKind: "webview",
  redirectUri: "https://client.example.test/webview",
};
const componentBinding: WechatComponentPlatformBinding = {
  componentAppId: "wx-component",
  authorizerAppId: "wx-authorizer",
  status: "active",
};
const publicPlatformResult: PublicPlatformLoginResultDto = {
  user: { id: "user-01", name: "User", email: null, emailVerified: false },
  session: { sessionReference: "opaque-session-reference", clientKind: "mp_weixin", expiresAt: "2026-01-01T00:00:00.000Z" },
  created: true,
  linked: false,
  client: "mp_weixin",
};
const context: ControlPlaneContext = {
  requestId,
  capabilities,
  user,
  organization,
  session,
  system,
};

void pagination;
void role;
void permission;
void error;
void auditEvent;
void page;
void application;
void platform;
void client;
void confidentialClient;
void sharedClient;
void rpClient;
void resolvedOidcProvider;
void oidcClientMetadata;
void oidcConsentContext;
void oidcConsentDecision;
void oidcConsentGrant;
void oidcLogoutOperation;
void oidcLogoutResult;
void oidcProtocolError;
void opaqueSession;
void webviewTicket;
void componentBinding;
void publicPlatformResult;
void context;
void complianceReport;
void maskedComplianceSubject;
