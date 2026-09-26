import type { SecretBindingRepository } from "./secret-binding.js";
import type {
  ApplicationClientCreateRequest,
  ApplicationClientIdScope,
  ApplicationClientKind,
  ApplicationClientListQuery,
  ApplicationClientRotateSecretRequest,
  ApplicationClientStatus,
  ApplicationClientUpdateRequest,
  ApplicationCreateRequest,
  ApplicationEffectiveStatus,
  ApplicationExternalIdentityListQuery,
  ApplicationListQuery,
  ApplicationPlatformCreateRequest,
  ApplicationPlatformListQuery,
  ApplicationPlatformType,
  ApplicationPlatformUpdateRequest,
  ApplicationReadiness,
  ApplicationReadinessStatus,
  ApplicationSecretStatus,
  ApplicationStatus,
  ApplicationType,
  ApplicationUpdateRequest,
  ApplicationVersion,
  OidcRpClient,
  OidcRpConsent,
  OidcRpPkceMethod,
  OidcRpRedirectUriPolicy,
  OpaqueClientSession,
  OpaqueClientSessionClientKind,
  OpaqueClientSessionIssueResult,
  OpaqueClientSessionRecord,
  WebviewTicket,
  WebviewTicketConsumeRequest,
  WebviewTicketIssueResult,
  WebviewTicketRecord,
  WechatComponentPlatformBinding,
  WechatComponentBindingStatus,
} from "@getbrick/idaas-contracts";
import { CONTROL_PLANE_BASE_PATH } from "./types.js";
import type { ControlPlaneActor, ControlPlaneWriteContext } from "./types.js";

export const APPLICATION_MANAGEMENT_BASE_PATH = CONTROL_PLANE_BASE_PATH;

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

export type ApplicationPermission = (typeof APPLICATION_MANAGEMENT_PERMISSIONS)[keyof typeof APPLICATION_MANAGEMENT_PERMISSIONS];
export type { ApplicationExternalIdentitySummary } from "@getbrick/idaas-contracts";
export type ApplicationDateLike = string | number | Date;
export type ApplicationActor = ControlPlaneActor;
export type ApplicationWriteContext = ControlPlaneWriteContext;

export interface ApplicationMutationRequestContext extends ApplicationWriteContext {
  ifMatch?: string;
  idempotencyKey?: string;
}

export type ApplicationMutationTransaction = <T>(operation: () => Promise<T>) => Promise<T>;

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

export interface ApplicationRecord {
  id: string;
  tenantId?: string;
  name: string;
  slug: string;
  description?: string | null;
  applicationType?: ApplicationType | string;
  status?: ApplicationStatus | string;
  lifecycleStatus?: ApplicationStatus | string;
  readiness?: ApplicationReadiness;
  effectiveStatus?: ApplicationEffectiveStatus;
  version?: ApplicationVersion;
  etag?: string;
  previousStatus?: ApplicationStatus | string;
  createdAt?: ApplicationDateLike | null;
  updatedAt?: ApplicationDateLike | null;
  enabledAt?: ApplicationDateLike | null;
  disabledAt?: ApplicationDateLike | null;
  archivedAt?: ApplicationDateLike | null;
  purgedAt?: ApplicationDateLike | null;
  [key: string]: unknown;
}

export interface ApplicationPlatformRecord {
  id: string;
  applicationId: string;
  tenantId?: string;
  type: ApplicationPlatformType | string;
  externalAppId?: string | null;
  displayName?: string | null;
  loginMode?: string | null;
  scope?: string | null;
  scopes?: string[];
  redirectUris?: string[];
  endpointUrl?: string | null;
  secretRef?: string | null;
  componentAppId?: string | null;
  componentAppSecretRef?: string | null;
  componentVerifyTicketRef?: string | null;
  componentAccessTokenRef?: string | null;
  authorizedAppId?: string | null;
  authorizerAppId?: string | null;
  authorizerRefreshTokenRef?: string | null;
  authorizerAccessTokenRef?: string | null;
  componentTicketRef?: string | null;
  componentTicketExpiresAt?: ApplicationDateLike | null;
  componentBindingStatus?: WechatComponentBindingStatus;
  componentBindingVersion?: ApplicationVersion;
  componentScope?: string | null;
  componentBinding?: WechatComponentPlatformBinding;
  credentialConfigured?: boolean;
  hasCredential?: boolean;
  secretStatus?: ApplicationSecretStatus;
  secretVersion?: ApplicationVersion;
  readiness?: ApplicationReadiness;
  effectiveStatus?: ApplicationEffectiveStatus;
  version?: ApplicationVersion;
  etag?: string;
  status?: ApplicationStatus | string;
  createdAt?: ApplicationDateLike | null;
  updatedAt?: ApplicationDateLike | null;
  enabledAt?: ApplicationDateLike | null;
  disabledAt?: ApplicationDateLike | null;
  archivedAt?: ApplicationDateLike | null;
  purgedAt?: ApplicationDateLike | null;
  [key: string]: unknown;
}

export interface ApplicationClientRecord {
  id: string;
  applicationId: string;
  tenantId?: string;
  clientId: string;
  clientIdScope?: ApplicationClientIdScope;
  applicationType?: ApplicationType;
  clientKind?: ApplicationClientKind;
  clientType?: ApplicationClientKind;
  redirectUriPolicy?: OidcRpRedirectUriPolicy;
  pkceMethod?: OidcRpPkceMethod;
  consent?: OidcRpConsent;
  consentRequired?: boolean;
  requireExplicitConsent?: boolean;
  rpClient?: OidcRpClient;
  status?: ApplicationClientStatus | string;
  redirectUris?: string[];
  postLogoutRedirectUris?: string[];
  grantTypes?: string[];
  responseTypes?: string[];
  scopes?: string[];
  tokenEndpointAuthMethod?: string | null;
  tokenEndpointAuthSigningAlg?: string | null;
  jwksUri?: string | null;
  privateKeyRef?: string | null;
  keyId?: string | null;
  requirePkce?: boolean | null;
  secretRef?: string | null;
  hasSecret?: boolean;
  secretStatus?: ApplicationSecretStatus;
  secretVersion?: ApplicationVersion;
  readiness?: ApplicationReadiness;
  effectiveStatus?: ApplicationEffectiveStatus;
  version?: ApplicationVersion;
  etag?: string;
  createdAt?: ApplicationDateLike | null;
  updatedAt?: ApplicationDateLike | null;
  enabledAt?: ApplicationDateLike | null;
  disabledAt?: ApplicationDateLike | null;
  archivedAt?: ApplicationDateLike | null;
  purgedAt?: ApplicationDateLike | null;
  [key: string]: unknown;
}

export interface ApplicationExternalIdentityRecord {
  id: string;
  applicationId: string;
  platformId?: string | null;
  provider: string;
  platform?: string | null;
  appId?: string | null;
  subject: string;
  tenantId?: string;
  externalAppId?: string | null;
  openid?: string | null;
  unionid?: string | null;
  nickname?: string | null;
  displayName?: string | null;
  email?: string | null;
  avatarUrl?: string | null;
  scopes?: string[];
  canonicalUserId?: string;
  linkStatus?: "linked" | "pending" | "rejected" | "revoked" | string;
  emailVerified?: boolean;
  version?: ApplicationVersion;
  linkedAt?: ApplicationDateLike | null;
  lastAuthenticatedAt?: ApplicationDateLike | null;
  createdAt?: ApplicationDateLike | null;
  updatedAt?: ApplicationDateLike | null;
  [key: string]: unknown;
}

export interface ApplicationExternalIdentityUpsertInput {
  platformId?: string | null;
  provider: string;
  platform?: string | null;
  appId?: string | null;
  subject: string;
  externalAppId?: string | null;
  openid?: string | null;
  unionid?: string | null;
  nickname?: string | null;
  displayName?: string | null;
  email?: string | null;
  avatarUrl?: string | null;
  scopes?: readonly string[];
  canonicalUserId?: string;
  linkStatus?: "linked" | "pending" | "rejected" | "revoked" | string;
  emailVerified?: boolean;
}

export interface ApplicationAuditEvent {
  id?: string | null;
  tenantId?: string;
  event: string;
  action?: string;
  actorId?: string | null;
  targetId?: string | null;
  requestId?: string | null;
  outcome?: string | null;
  ipAddress?: string | null;
  userAgent?: string | null;
  detail?: Record<string, unknown>;
  occurredAt?: ApplicationDateLike | null;
  createdAt?: ApplicationDateLike | null;
  [key: string]: unknown;
}

export interface ApplicationPage<T> {
  items: T[];
  nextCursor?: string;
  hasMore: boolean;
  total: number;
}

export type ApplicationsPage = ApplicationPage<ApplicationRecord>;
export type ApplicationPlatformsPage = ApplicationPage<ApplicationPlatformRecord>;
export type ApplicationClientsPage = ApplicationPage<ApplicationClientRecord>;

export interface NormalizedApplicationQuery {
  cursor?: string;
  limit: number;
  offset?: number;
  search?: string;
  q?: string;
  status?: ApplicationStatus;
  applicationType?: ApplicationType;
  readiness?: ApplicationReadinessStatus;
  effectiveStatus?: ApplicationEffectiveStatus;
}

export interface NormalizedApplicationPlatformQuery {
  cursor?: string;
  limit: number;
  offset?: number;
  search?: string;
  q?: string;
  status?: ApplicationStatus;
  readiness?: ApplicationReadinessStatus;
  effectiveStatus?: ApplicationEffectiveStatus;
}

export interface NormalizedApplicationExternalIdentityQuery {
  cursor?: string;
  limit: number;
  offset?: number;
  search?: string;
  q?: string;
  provider?: string;
  platformId?: string;
}

export interface NormalizedApplicationClientQuery {
  cursor?: string;
  limit: number;
  offset?: number;
  search?: string;
  q?: string;
  status?: ApplicationClientStatus;
  readiness?: ApplicationReadinessStatus;
  effectiveStatus?: ApplicationEffectiveStatus;
  clientKind?: ApplicationClientKind;
}

export interface OpaqueClientSessionIssueInput {
  applicationId: string;
  clientId: string;
  clientKind: OpaqueClientSessionClientKind;
  userId: string;
  deviceId?: string;
  binding?: string;
  expiresInSeconds?: number;
  sessionReference?: string;
  sessionToken?: string;
}

export interface OpaqueClientSessionRepository {
  readonly tenantId: string;
  issue(input: OpaqueClientSessionIssueInput): OpaqueClientSessionIssueResult | Promise<OpaqueClientSessionIssueResult>;
  find(sessionReference: string): OpaqueClientSessionRecord | undefined | Promise<OpaqueClientSessionRecord | undefined>;
  touch?(sessionReference: string, at?: Date): OpaqueClientSessionRecord | undefined | Promise<OpaqueClientSessionRecord | undefined>;
  revoke?(sessionReference: string, at?: Date): boolean | Promise<boolean>;
  cleanupExpired?(at?: Date): number | Promise<number>;
  purgeExpired?(at?: Date): number | Promise<number>;
}

export type ClientSessionRepository = OpaqueClientSessionRepository;

export interface WebviewTicketIssueInput {
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

export interface WebviewTicketRepository {
  readonly tenantId: string;
  issue(input: WebviewTicketIssueInput): WebviewTicketIssueResult | Promise<WebviewTicketIssueResult>;
  consume(input: WebviewTicketConsumeRequest): WebviewTicketRecord | undefined | Promise<WebviewTicketRecord | undefined>;
  revoke?(ticketReference: string): boolean | Promise<boolean>;
  cleanupExpired?(at?: Date): number | Promise<number>;
  purgeExpired?(at?: Date): number | Promise<number>;
}

export type ClientSessionTicketRepository = WebviewTicketRepository;
export type WebviewTicketStore = WebviewTicketRepository;

export interface ApplicationRepositoryOptions {
  tenantId?: string;
  applications?: readonly ApplicationRecord[];
  platforms?: readonly ApplicationPlatformRecord[];
  clients?: readonly ApplicationClientRecord[];
  auditEvents?: readonly ApplicationAuditEvent[];
  applicationPlatforms?: readonly ApplicationPlatformRecord[];
  applicationClients?: readonly ApplicationClientRecord[];
  applicationAuditEvents?: readonly ApplicationAuditEvent[];
  externalIdentities?: readonly ApplicationExternalIdentityRecord[];
  applicationExternalIdentities?: readonly ApplicationExternalIdentityRecord[];
  clientSessions?: readonly OpaqueClientSessionRecord[];
  opaqueClientSessions?: readonly OpaqueClientSessionRecord[];
  webviewTickets?: readonly WebviewTicketRecord[];
  clientSessionRepository?: OpaqueClientSessionRepository;
  webviewTicketRepository?: WebviewTicketRepository;
}

export type ApplicationManagementRepositoryOptions = ApplicationRepositoryOptions;

export type ApplicationPlatformMutationRequest = ApplicationPlatformUpdateRequest & { secretRef?: string | null };
export type ApplicationClientMutationRequest = ApplicationClientUpdateRequest & { secretRef?: string | null };

export interface ApplicationRepository {
  readonly tenantId: string;
  listApplications(
    query?: ApplicationListQuery | NormalizedApplicationQuery,
  ): ApplicationPage<ApplicationRecord> | Promise<ApplicationPage<ApplicationRecord>>;
  getApplication(id: string): ApplicationRecord | undefined | Promise<ApplicationRecord | undefined>;
  createApplication(
    input: ApplicationCreateRequest & { id?: string },
    context?: ApplicationWriteContext,
  ): ApplicationRecord | Promise<ApplicationRecord>;
  updateApplication(
    id: string,
    input: ApplicationUpdateRequest & { id?: string },
    context?: ApplicationWriteContext,
  ): ApplicationRecord | Promise<ApplicationRecord>;
  setApplicationStatus(
    id: string,
    status: ApplicationStatus,
    context?: ApplicationWriteContext,
  ): ApplicationRecord | Promise<ApplicationRecord>;
  enableApplication?(id: string, context?: ApplicationWriteContext): ApplicationRecord | Promise<ApplicationRecord>;
  disableApplication?(id: string, context?: ApplicationWriteContext): ApplicationRecord | Promise<ApplicationRecord>;
  archiveApplication?(id: string, context?: ApplicationWriteContext): ApplicationRecord | Promise<ApplicationRecord>;
  restoreApplication?(id: string, context?: ApplicationWriteContext): ApplicationRecord | Promise<ApplicationRecord>;
  purgeApplication?(id: string, context?: ApplicationWriteContext): ApplicationRecord | Promise<ApplicationRecord>;
  archive?(id: string, context?: ApplicationWriteContext): ApplicationRecord | Promise<ApplicationRecord>;
  restore?(id: string, context?: ApplicationWriteContext): ApplicationRecord | Promise<ApplicationRecord>;
  purge?(id: string, context?: ApplicationWriteContext): ApplicationRecord | Promise<ApplicationRecord>;
  deleteApplication(
    id: string,
    context?: ApplicationWriteContext,
  ): ApplicationRecord | Promise<ApplicationRecord>;
  withTransaction?<T>(operation: () => Promise<T>): Promise<T>;
  enqueuePurgeApplication?(
    id: string,
    job: ApplicationPurgeJob,
    context?: ApplicationWriteContext,
  ): ApplicationPurgeJob | Promise<ApplicationPurgeJob>;
  enqueuePurgeResource?(
    applicationId: string,
    resourceType: "application-platform" | "application-client",
    resourceId: string,
    job: ApplicationPurgeJob,
    context?: ApplicationWriteContext,
  ): ApplicationPurgeJob | Promise<ApplicationPurgeJob>;
  listPlatforms(
    applicationId: string,
    query?: ApplicationPlatformListQuery | NormalizedApplicationPlatformQuery,
  ): ApplicationPage<ApplicationPlatformRecord> | Promise<ApplicationPage<ApplicationPlatformRecord>>;
  getPlatform(
    applicationId: string,
    id: string,
  ): ApplicationPlatformRecord | undefined | Promise<ApplicationPlatformRecord | undefined>;
  createPlatform(
    applicationId: string,
    input: ApplicationPlatformCreateRequest,
    context?: ApplicationWriteContext,
  ): ApplicationPlatformRecord | Promise<ApplicationPlatformRecord>;
  updatePlatform(
    applicationId: string,
    id: string,
    input: ApplicationPlatformMutationRequest,
    context?: ApplicationWriteContext,
  ): ApplicationPlatformRecord | Promise<ApplicationPlatformRecord>;
  setPlatformStatus(
    applicationId: string,
    id: string,
    status: ApplicationStatus,
    context?: ApplicationWriteContext,
  ): ApplicationPlatformRecord | Promise<ApplicationPlatformRecord>;
  enablePlatform?(applicationId: string, id: string, context?: ApplicationWriteContext): ApplicationPlatformRecord | Promise<ApplicationPlatformRecord>;
  disablePlatform?(applicationId: string, id: string, context?: ApplicationWriteContext): ApplicationPlatformRecord | Promise<ApplicationPlatformRecord>;
  archivePlatform?(applicationId: string, id: string, context?: ApplicationWriteContext): ApplicationPlatformRecord | Promise<ApplicationPlatformRecord>;
  restorePlatform?(applicationId: string, id: string, context?: ApplicationWriteContext): ApplicationPlatformRecord | Promise<ApplicationPlatformRecord>;
  purgePlatform?(applicationId: string, id: string, context?: ApplicationWriteContext): ApplicationPlatformRecord | Promise<ApplicationPlatformRecord>;
  deletePlatform(
    applicationId: string,
    id: string,
    context?: ApplicationWriteContext,
  ): ApplicationPlatformRecord | Promise<ApplicationPlatformRecord>;
  listClients(
    applicationId: string,
    query?: ApplicationClientListQuery | NormalizedApplicationClientQuery,
  ): ApplicationPage<ApplicationClientRecord> | Promise<ApplicationPage<ApplicationClientRecord>>;
  getClient(
    applicationId: string,
    id: string,
  ): ApplicationClientRecord | undefined | Promise<ApplicationClientRecord | undefined>;
  findClientByClientId?(
    clientId: string,
  ): ApplicationClientRecord | undefined | Promise<ApplicationClientRecord | undefined>;
  createClient(
    applicationId: string,
    input: ApplicationClientCreateRequest,
    context?: ApplicationWriteContext,
  ): ApplicationClientRecord | Promise<ApplicationClientRecord>;
  updateClient(
    applicationId: string,
    id: string,
    input: ApplicationClientMutationRequest,
    context?: ApplicationWriteContext,
  ): ApplicationClientRecord | Promise<ApplicationClientRecord>;
  rotateClientSecret?(
    applicationId: string,
    id: string,
    input: ApplicationClientRotateSecretRequest,
    context?: ApplicationWriteContext,
  ): ApplicationClientRecord | Promise<ApplicationClientRecord>;
  rotateApplicationClientSecret?(
    applicationId: string,
    id: string,
    input: ApplicationClientRotateSecretRequest,
    context?: ApplicationWriteContext,
  ): ApplicationClientRecord | Promise<ApplicationClientRecord>;
  rotateSecret?(
    applicationId: string,
    id: string,
    input: ApplicationClientRotateSecretRequest,
    context?: ApplicationWriteContext,
  ): ApplicationClientRecord | Promise<ApplicationClientRecord>;
  setClientStatus(
    applicationId: string,
    id: string,
    status: ApplicationClientStatus,
    context?: ApplicationWriteContext,
  ): ApplicationClientRecord | Promise<ApplicationClientRecord>;
  enableClient?(applicationId: string, id: string, context?: ApplicationWriteContext): ApplicationClientRecord | Promise<ApplicationClientRecord>;
  disableClient?(applicationId: string, id: string, context?: ApplicationWriteContext): ApplicationClientRecord | Promise<ApplicationClientRecord>;
  archiveClient?(applicationId: string, id: string, context?: ApplicationWriteContext): ApplicationClientRecord | Promise<ApplicationClientRecord>;
  restoreClient?(applicationId: string, id: string, context?: ApplicationWriteContext): ApplicationClientRecord | Promise<ApplicationClientRecord>;
  purgeClient?(applicationId: string, id: string, context?: ApplicationWriteContext): ApplicationClientRecord | Promise<ApplicationClientRecord>;
  deleteClient(
    applicationId: string,
    id: string,
    context?: ApplicationWriteContext,
  ): ApplicationClientRecord | Promise<ApplicationClientRecord>;
  addAuditEvent(
    event: ApplicationAuditEvent,
  ): ApplicationAuditEvent | Promise<ApplicationAuditEvent>;
  appendAuditEvent?(event: ApplicationAuditEvent): ApplicationAuditEvent | Promise<ApplicationAuditEvent>;
  listExternalIdentities?(
    applicationId: string,
    query?: ApplicationExternalIdentityListQuery | NormalizedApplicationExternalIdentityQuery,
  ): ApplicationPage<ApplicationExternalIdentityRecord> | Promise<ApplicationPage<ApplicationExternalIdentityRecord>>;
  upsertExternalIdentity?(
    applicationId: string,
    input: ApplicationExternalIdentityUpsertInput,
    context?: ApplicationWriteContext,
  ): ApplicationExternalIdentityRecord | Promise<ApplicationExternalIdentityRecord>;
  issueOpaqueClientSession?(
    input: OpaqueClientSessionIssueInput,
  ): OpaqueClientSessionIssueResult | Promise<OpaqueClientSessionIssueResult>;
  findOpaqueClientSession?(
    sessionReference: string,
  ): OpaqueClientSessionRecord | undefined | Promise<OpaqueClientSessionRecord | undefined>;
  issueWebviewTicket?(
    input: WebviewTicketIssueInput,
  ): WebviewTicketIssueResult | Promise<WebviewTicketIssueResult>;
  consumeWebviewTicket?(
    input: WebviewTicketConsumeRequest,
  ): WebviewTicketRecord | undefined | Promise<WebviewTicketRecord | undefined>;
  isReady?(): boolean | Promise<boolean>;

}

export type ApplicationManagementRepository = ApplicationRepository;

export interface ApplicationServiceOptions {
  requireActor?: boolean;
  adminRoles?: readonly string[];
  defaultLimit?: number;
  maxLimit?: number;
  allowedClientScopes?: readonly string[];
  readiness?: () => boolean | Promise<boolean>;
  secretBindings?: SecretBindingRepository;
  requireSecretBindings?: boolean;
  mutationTransaction?: ApplicationMutationTransaction;
  transaction?: ApplicationMutationTransaction;
}

export interface ApplicationSnapshot {
  applications: ApplicationRecord[];
  platforms: ApplicationPlatformRecord[];
  clients: ApplicationClientRecord[];
  auditEvents: ApplicationAuditEvent[];
  externalIdentities?: ApplicationExternalIdentityRecord[];
  clientSessions?: OpaqueClientSessionRecord[];
  webviewTickets?: WebviewTicketRecord[];
}

export type ApplicationManagementSnapshot = ApplicationSnapshot;

export type ApplicationCreateData = ApplicationCreateRequest;
export type ApplicationUpdateData = ApplicationUpdateRequest;
export type ApplicationPlatformCreateData = ApplicationPlatformCreateRequest;
export type ApplicationPlatformUpdateData = ApplicationPlatformUpdateRequest;
export type ApplicationClientCreateData = ApplicationClientCreateRequest;
export type ApplicationClientUpdateData = ApplicationClientUpdateRequest;
export type ApplicationClientRotateSecretData = ApplicationClientRotateSecretRequest;

export {
  InMemoryClientSessionRepository,
  InMemoryOpaqueClientSessionRepository,
  InMemoryOpaqueSessionRepository,
  SqlClientSessionRepository,
  SqlOpaqueClientSessionRepository,
  SqlOpaqueSessionRepository,
  createClientSessionRepository,
  createInMemoryClientSessionRepository,
  createInMemoryOpaqueClientSessionRepository,
  createSqlClientSessionRepository,
  generateOpaqueClientSessionReference,
  hashClientSession,
  hashClientSessionReference,
  hashOpaqueClientSession,
} from "./client-session-repository.js";
export {
  InMemoryClientTicketRepository,
  InMemoryWebviewTicketRepository,
  InMemoryWebviewTicketStore,
  SqlClientTicketRepository,
  SqlWebviewTicketRepository,
  SqlWebviewTicketStore,
  createInMemoryWebviewTicketRepository,
  createSqlWebviewTicketRepository,
  createWebviewTicketRepository,
  generateWebviewTicket,
  hashClientWebviewTicket,
  hashWebviewTicket,
  hashWebviewTicketReference,
} from "./webview-ticket-repository.js";
