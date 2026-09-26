import type {
  OpenPlatformAuthorizationPort,
  OpenPlatformContextAssurance,
  OpenPlatformRequestContext,
} from "./authorization.js";
import type {
  OpenPlatformEventPublishResult,
  OpenPlatformEventPublisherPort,
  OpenPlatformOutboxPort,
} from "./events.js";
import type {
  OpenPlatformAuditEventRecord,
  OpenPlatformAuditPage,
  OpenPlatformAuditPort,
  OpenPlatformAuditQuery,
} from "./audit.js";
import type {
  OpenPlatformWebhook,
  OpenPlatformWebhookDelivery,
  OpenPlatformWebhookDeliveryPage,
  OpenPlatformWebhookDeliveryQuery as OpenPlatformWebhookDeliveryQueryType,
  OpenPlatformWebhookDeliveryPort,
  OpenPlatformWebhookDispatchResult,
  OpenPlatformWebhookEventEnvelope,
  OpenPlatformWebhookPage,
  OpenPlatformWebhookPort,
  OpenPlatformWebhookQuery,
  OpenPlatformWebhookSecretPort,
  OpenPlatformWebhookSecretResult,
  OpenPlatformWebhookTransport,
  OpenPlatformWebhookTransportFunction,
  OpenPlatformWebhookServiceOptions,
} from "./webhook.js";

export type { OpenPlatformRequestContext } from "./authorization.js";

export type {
  OpenPlatformDomainEvent,
  OpenPlatformDomainEventAction,
  OpenPlatformDomainEventData,
  OpenPlatformDomainEventDescriptor,
  OpenPlatformDomainEventFactory,
  OpenPlatformDomainEventInput,
  OpenPlatformDomainEventRecord,
  OpenPlatformDomainEventStatus,
  OpenPlatformDomainEventType,
  OpenPlatformEventPublishResult,
  OpenPlatformEventPublisherOptions,
  OpenPlatformEventPublisherPort,
  OpenPlatformEventSink,
  OpenPlatformEventSinkResult,
  OpenPlatformOutboxClaimRequest,
  OpenPlatformOutboxClaimResult,
  OpenPlatformOutboxCompleteRequest,
  OpenPlatformOutboxFailRequest,
  OpenPlatformOutboxPage,
  OpenPlatformOutboxPort,
  OpenPlatformOutboxQuery,
  OpenPlatformOutboxRecord,
} from "./events.js";

export const OPEN_PLATFORM_LIFECYCLE_STATUSES = [
  "draft",
  "published",
  "disabled",
  "archived",
] as const;

export type OpenPlatformLifecycleStatus =
  (typeof OPEN_PLATFORM_LIFECYCLE_STATUSES)[number];

export const OPEN_PLATFORM_CREDENTIAL_STATUSES = [
  "active",
  "rotated",
  "revoked",
] as const;

export type OpenPlatformCredentialStatus =
  (typeof OPEN_PLATFORM_CREDENTIAL_STATUSES)[number];

export const OPEN_PLATFORM_SCOPE_GRANT_STATUSES = [
  "active",
  "revoked",
] as const;

export type OpenPlatformScopeGrantStatus =
  (typeof OPEN_PLATFORM_SCOPE_GRANT_STATUSES)[number];

export const OPEN_PLATFORM_LIFECYCLE_RESOURCE_KINDS = [
  "tenant",
  "developerOrganization",
  "application",
  "applicationEnvironment",
  "apiProduct",
  "apiVersion",
  "subscription",
] as const;

export type OpenPlatformLifecycleResourceKind =
  (typeof OPEN_PLATFORM_LIFECYCLE_RESOURCE_KINDS)[number];

export type OpenPlatformEntityKind =
  | OpenPlatformLifecycleResourceKind
  | "credential"
  | "scopeGrant"
  | "usage"
  | "webhook"
  | "auditEvent";

export interface OpenPlatformRecordBase {
  id: string;
  tenantId: string;
  kind: OpenPlatformEntityKind;
  version: number;
  createdAt: string;
  updatedAt: string;
}

export interface OpenPlatformLifecycleRecordBase extends OpenPlatformRecordBase {
  status: OpenPlatformLifecycleStatus;
  archivedAt?: string;
}

export interface Tenant extends OpenPlatformLifecycleRecordBase {
  kind: "tenant";
  name: string;
}

export interface DeveloperOrganization extends OpenPlatformLifecycleRecordBase {
  kind: "developerOrganization";
  name: string;
  description?: string;
}

export interface Application extends OpenPlatformLifecycleRecordBase {
  kind: "application";
  organizationId: string;
  name: string;
  description?: string;
}

export interface ApplicationEnvironment extends OpenPlatformLifecycleRecordBase {
  kind: "applicationEnvironment";
  applicationId: string;
  name: string;
}

export interface ApiProduct extends OpenPlatformLifecycleRecordBase {
  kind: "apiProduct";
  name: string;
  description?: string;
  scopes: string[];
}

export interface ApiVersion extends OpenPlatformLifecycleRecordBase {
  kind: "apiVersion";
  productId: string;
  apiVersion: string;
  description?: string;
  scopes: string[];
}

export interface CredentialSecretStorage {
  digest: string;
  reference?: string;
}

export interface CredentialRecord extends OpenPlatformRecordBase {
  kind: "credential";
  applicationId: string;
  environmentId?: string;
  name: string;
  status: OpenPlatformCredentialStatus;
  scopes: string[];
  secret: CredentialSecretStorage;
  fingerprint: string;
  expiresAt?: string;
  rotatedAt?: string;
  revokedAt?: string;
  replacedByCredentialId?: string;
  previousCredentialId?: string;
}

export interface CredentialDto {
  id: string;
  tenantId: string;
  kind: "credential";
  applicationId: string;
  environmentId?: string;
  name: string;
  status: OpenPlatformCredentialStatus;
  scopes: string[];
  expiresAt?: string;
  rotatedAt?: string;
  revokedAt?: string;
  replacedByCredentialId?: string;
  previousCredentialId?: string;
  version: number;
  createdAt: string;
  updatedAt: string;
}

export interface Subscription extends OpenPlatformLifecycleRecordBase {
  kind: "subscription";
  applicationId: string;
  productId: string;
  apiVersionId?: string;
  name: string;
  scopes: string[];
}

export interface ScopeGrant extends OpenPlatformRecordBase {
  kind: "scopeGrant";
  credentialId: string;
  applicationId: string;
  productId: string;
  apiVersionId?: string;
  scopes: string[];
  status: OpenPlatformScopeGrantStatus;
  grantedAt: string;
  revokedAt?: string;
}

export interface UsageRecord extends Readonly<OpenPlatformRecordBase> {
  kind: "usage";
  subscriptionId: string;
  credentialId?: string;
  productId: string;
  apiVersionId?: string;
  metric: string;
  quantity: number;
  occurredAt: string;
  idempotencyKey: string;
}

export type OpenPlatformLifecycleRecord =
  | Tenant
  | DeveloperOrganization
  | Application
  | ApplicationEnvironment
  | ApiProduct
  | ApiVersion
  | Subscription;

export type OpenPlatformRecord =
  | OpenPlatformLifecycleRecord
  | CredentialRecord
  | ScopeGrant
  | UsageRecord
  | OpenPlatformWebhook;

export type MaybePromise<T> = T | Promise<T>;

export type OpenPlatformStorageKind = "memory" | "persistent";

export interface OpenPlatformDependencyReadiness {
  readonly storage: OpenPlatformStorageKind;
  readonly distributed: boolean;
  ready(): MaybePromise<boolean>;
}

export interface TenantScopedRepository<T extends OpenPlatformRecord> {
  create(record: T): Promise<T>;
  get(tenantId: string, id: string): Promise<T | undefined>;
  list(tenantId: string): Promise<T[]>;
  save(record: T): Promise<T>;
}

export interface TenantRepository extends TenantScopedRepository<Tenant> {
  getByTenantId(tenantId: string): Promise<Tenant | undefined>;
}

export type DeveloperOrganizationRepository =
  TenantScopedRepository<DeveloperOrganization>;
export type ApplicationRepository = TenantScopedRepository<Application>;
export type ApplicationEnvironmentRepository =
  TenantScopedRepository<ApplicationEnvironment>;
export type ApiProductRepository = TenantScopedRepository<ApiProduct>;
export type ApiVersionRepository = TenantScopedRepository<ApiVersion>;

export interface CredentialRepository
  extends TenantScopedRepository<CredentialRecord> {
  rotate(
    previousCredential: CredentialRecord,
    replacementCredential: CredentialRecord,
  ): Promise<{
    credential: CredentialRecord;
    previousCredential: CredentialRecord;
  }>;
}

export type SubscriptionRepository = TenantScopedRepository<Subscription>;

export interface ScopeGrantRepository
  extends TenantScopedRepository<ScopeGrant> {
  revoke(tenantId: string, id: string, revokedAt: string): Promise<ScopeGrant>;
}

export interface UsageRepository {
  append(record: UsageRecord): Promise<UsageRecord>;
  get(tenantId: string, id: string): Promise<UsageRecord | undefined>;
  list(tenantId: string): Promise<UsageRecord[]>;
}

export interface IdempotencyScope {
  tenantId: string;
  actorId: string;
  operation: string;
  key: string;
}

export interface IdempotencyRecord {
  scope: IdempotencyScope;
  requestHash: string;
  state: "inProgress" | "completed";
  leaseToken?: string;
  leaseExpiresAt: string;
  expiresAt: string;
  createdAt: string;
  completedAt?: string;
  response?: unknown;
}

export interface IdempotencyAcquireRequest {
  scope: IdempotencyScope;
  requestHash: string;
  leaseToken: string;
  now: string;
  leaseExpiresAt: string;
  expiresAt: string;
}

export type IdempotencyAcquireResult =
  | { state: "acquired" }
  | { state: "replay"; response: unknown }
  | { state: "inProgress" }
  | { state: "conflict" };

export interface IdempotencyExecution<T> {
  replayed: boolean;
  result: T;
}

export interface IdempotencyCompleteRequest {
  scope: IdempotencyScope;
  requestHash: string;
  leaseToken: string;
  now: string;
  expiresAt: string;
  response: unknown;
}

export interface IdempotencyReleaseRequest {
  scope: IdempotencyScope;
  requestHash: string;
  leaseToken: string;
  now: string;
}

export interface IdempotencyStore {
  readonly readiness: OpenPlatformDependencyReadiness;
  acquire(request: IdempotencyAcquireRequest): Promise<IdempotencyAcquireResult>;
  complete(request: IdempotencyCompleteRequest): Promise<boolean>;
  release(request: IdempotencyReleaseRequest): Promise<boolean>;
}

export interface OpenPlatformRepositories {
  readiness: OpenPlatformDependencyReadiness;
  tenants: TenantRepository;
  developerOrganizations: DeveloperOrganizationRepository;
  applications: ApplicationRepository;
  applicationEnvironments: ApplicationEnvironmentRepository;
  apiProducts: ApiProductRepository;
  apiVersions: ApiVersionRepository;
  credentials: CredentialRepository;
  subscriptions: SubscriptionRepository;
  scopeGrants: ScopeGrantRepository;
  usage: UsageRepository;
  idempotency: IdempotencyStore;
  auditEvents?: OpenPlatformAuditPort;
  webhooks?: OpenPlatformWebhookPort;
  webhookDeliveries?: OpenPlatformWebhookDeliveryPort;
  domainEvents?: OpenPlatformOutboxPort;
}

export interface CreateTenantCommand {
  tenantId: string;
  name: string;
  idempotencyKey: string;
}

export interface TenantQuery {
  tenantId: string;
}

export interface CreateDeveloperOrganizationCommand {
  tenantId: string;
  name: string;
  description?: string;
  idempotencyKey: string;
}

export interface DeveloperOrganizationQuery {
  tenantId: string;
  id?: string;
}

export interface CreateApplicationCommand {
  tenantId: string;
  organizationId: string;
  name: string;
  description?: string;
  idempotencyKey: string;
}

export interface ApplicationQuery {
  tenantId: string;
  id?: string;
}

export interface CreateApplicationEnvironmentCommand {
  tenantId: string;
  applicationId: string;
  name: string;
  idempotencyKey: string;
}

export interface ApplicationEnvironmentQuery {
  tenantId: string;
  applicationId?: string;
  id?: string;
}

export interface CreateApiProductCommand {
  tenantId: string;
  name: string;
  description?: string;
  scopes: readonly string[];
  idempotencyKey: string;
}

export interface ApiProductQuery {
  tenantId: string;
  id?: string;
}

export interface CreateApiVersionCommand {
  tenantId: string;
  productId: string;
  apiVersion: string;
  description?: string;
  scopes: readonly string[];
  idempotencyKey: string;
}

export interface ApiVersionQuery {
  tenantId: string;
  productId?: string;
  id?: string;
}

export interface IssueCredentialCommand {
  tenantId: string;
  applicationId: string;
  environmentId?: string;
  name: string;
  scopes: readonly string[];
  expiresAt?: string;
  idempotencyKey: string;
}

export interface RotateCredentialCommand {
  tenantId: string;
  credentialId: string;
  idempotencyKey: string;
}

export interface RevokeCredentialCommand {
  tenantId: string;
  credentialId: string;
  idempotencyKey: string;
}

export interface CredentialQuery {
  tenantId: string;
  applicationId?: string;
  environmentId?: string;
  id?: string;
}

export interface CreateSubscriptionCommand {
  tenantId: string;
  applicationId: string;
  productId: string;
  apiVersionId?: string;
  name: string;
  scopes: readonly string[];
  idempotencyKey: string;
}

export interface SubscriptionQuery {
  tenantId: string;
  applicationId?: string;
  productId?: string;
  id?: string;
}

export interface LifecycleTransitionCommand {
  resource: OpenPlatformLifecycleResourceKind;
  tenantId: string;
  id: string;
  targetStatus: OpenPlatformLifecycleStatus;
  idempotencyKey: string;
}

export interface LifecycleCommand {
  resource: OpenPlatformLifecycleResourceKind;
  tenantId: string;
  id: string;
  idempotencyKey: string;
}

export interface GrantScopesCommand {
  tenantId: string;
  credentialId: string;
  productId: string;
  apiVersionId?: string;
  scopes: readonly string[];
  idempotencyKey: string;
}

export interface RevokeScopeGrantCommand {
  tenantId: string;
  scopeGrantId: string;
  idempotencyKey: string;
}

export interface AuthorizeScopesCommand {
  tenantId: string;
  credentialId: string;
  productId: string;
  apiVersionId?: string;
  scopes: readonly string[];
}

export interface ScopeGrantQuery {
  tenantId: string;
  credentialId?: string;
  productId?: string;
  apiVersionId?: string;
  id?: string;
}

export interface ScopeAuthorizationResult {
  valid: true;
  scopeGrantId: string;
  credentialId: string;
  productId: string;
  apiVersionId?: string;
  scopes: string[];
}

export interface RecordUsageCommand {
  tenantId: string;
  subscriptionId: string;
  metric: string;
  quantity: number;
  occurredAt?: string;
  credentialId?: string;
  idempotencyKey: string;
}

export interface UsageQuery {
  tenantId: string;
  subscriptionId?: string;
  credentialId?: string;
  from?: string;
  to?: string;
}

export interface VerifyCredentialSecretCommand {
  tenantId: string;
  credentialId: string;
  secret: string;
}

export interface CredentialIssuanceResult {
  credential: CredentialDto;
  secret: string | undefined;
  replayed: boolean;
}

export interface CredentialRotationResult {
  credential: CredentialDto;
  previousCredential: CredentialDto;
  secret: string | undefined;
  replayed: boolean;
}

export interface CredentialSecretMaterial {
  secret: string;
  reference?: string;
}

export type CredentialSecretRevokeReason = "rotation" | "revocation";

export interface CredentialSecretRevokeInput {
  tenantId: string;
  applicationId: string;
  credentialId: string;
  digest: string;
  reference?: string;
  reason: CredentialSecretRevokeReason;
}

export type CredentialSecretCompensationReason =
  | "issuePersistenceFailed"
  | "rotationPersistenceFailed"
  | "rotationRevokeFailed";

export interface CredentialSecretCompensationInput {
  tenantId: string;
  applicationId: string;
  credentialId: string;
  digest: string;
  reference?: string;
  reason: CredentialSecretCompensationReason;
}

export interface CredentialSecretProvider {
  readonly readiness?: OpenPlatformDependencyReadiness;
  issue(input: {
    tenantId: string;
    applicationId: string;
    credentialId: string;
    reason: "issue" | "rotate";
  }): MaybePromise<CredentialSecretMaterial>;
  revoke(input: CredentialSecretRevokeInput): MaybePromise<void>;
  compensate(input: CredentialSecretCompensationInput): MaybePromise<void>;
}

export type OpenPlatformRuntimeMode = "development" | "test" | "production";

export interface OpenPlatformServiceOptions {
  mode: OpenPlatformRuntimeMode;
  authorization: OpenPlatformAuthorizationPort;
  repositories?: OpenPlatformRepositories;
  audit?: OpenPlatformAuditPort;
  auditPort?: OpenPlatformAuditPort;
  auditEventStore?: OpenPlatformAuditPort;
  webhookRepository?: OpenPlatformWebhookPort;
  webhookDeliveryRepository?: OpenPlatformWebhookDeliveryPort;
  webhookSecretProvider?: OpenPlatformWebhookSecretPort;
  webhookTransport?: OpenPlatformWebhookTransport | OpenPlatformWebhookTransportFunction;
  webhookService?: Partial<OpenPlatformWebhookServiceOptions>;
  outbox?: OpenPlatformOutboxPort;
  eventPublisher?: OpenPlatformEventPublisherPort;
  eventsEnabled?: boolean;
  usageEventThresholds?: Readonly<Record<string, number>>;
  eventDeliveryEnabled?: boolean;
  requiredContextAssurance?: OpenPlatformContextAssurance;
  allowInMemoryInProduction?: boolean;
  clock?: () => Date;
  idGenerator?: (kind: OpenPlatformEntityKind) => string;
  secretProvider?: CredentialSecretProvider;
}

export interface OpenPlatformReadiness {
  ready: boolean;
  mode: OpenPlatformRuntimeMode;
  storage: OpenPlatformStorageKind;
  distributed: boolean;
  events: boolean;
}

export interface OpenPlatformDomainService {
  isReady(): Promise<OpenPlatformReadiness>;

  createTenant(
    context: OpenPlatformRequestContext,
    command: CreateTenantCommand,
  ): Promise<Tenant>;
  getTenant(
    context: OpenPlatformRequestContext,
    query: TenantQuery,
  ): Promise<Tenant>;
  listTenants(
    context: OpenPlatformRequestContext,
    query: TenantQuery,
  ): Promise<Tenant[]>;

  createDeveloperOrganization(
    context: OpenPlatformRequestContext,
    command: CreateDeveloperOrganizationCommand,
  ): Promise<DeveloperOrganization>;
  getDeveloperOrganization(
    context: OpenPlatformRequestContext,
    query: DeveloperOrganizationQuery & { id: string },
  ): Promise<DeveloperOrganization>;
  listDeveloperOrganizations(
    context: OpenPlatformRequestContext,
    query: DeveloperOrganizationQuery,
  ): Promise<DeveloperOrganization[]>;

  createApplication(
    context: OpenPlatformRequestContext,
    command: CreateApplicationCommand,
  ): Promise<Application>;
  getApplication(
    context: OpenPlatformRequestContext,
    query: ApplicationQuery & { id: string },
  ): Promise<Application>;
  listApplications(
    context: OpenPlatformRequestContext,
    query: ApplicationQuery,
  ): Promise<Application[]>;

  createApplicationEnvironment(
    context: OpenPlatformRequestContext,
    command: CreateApplicationEnvironmentCommand,
  ): Promise<ApplicationEnvironment>;
  getApplicationEnvironment(
    context: OpenPlatformRequestContext,
    query: ApplicationEnvironmentQuery & { id: string },
  ): Promise<ApplicationEnvironment>;
  listApplicationEnvironments(
    context: OpenPlatformRequestContext,
    query: ApplicationEnvironmentQuery,
  ): Promise<ApplicationEnvironment[]>;

  createApiProduct(
    context: OpenPlatformRequestContext,
    command: CreateApiProductCommand,
  ): Promise<ApiProduct>;
  getApiProduct(
    context: OpenPlatformRequestContext,
    query: ApiProductQuery & { id: string },
  ): Promise<ApiProduct>;
  listApiProducts(
    context: OpenPlatformRequestContext,
    query: ApiProductQuery,
  ): Promise<ApiProduct[]>;

  createApiVersion(
    context: OpenPlatformRequestContext,
    command: CreateApiVersionCommand,
  ): Promise<ApiVersion>;
  getApiVersion(
    context: OpenPlatformRequestContext,
    query: ApiVersionQuery & { id: string },
  ): Promise<ApiVersion>;
  listApiVersions(
    context: OpenPlatformRequestContext,
    query: ApiVersionQuery,
  ): Promise<ApiVersion[]>;

  issueCredential(
    context: OpenPlatformRequestContext,
    command: IssueCredentialCommand,
  ): Promise<CredentialIssuanceResult>;
  rotateCredential(
    context: OpenPlatformRequestContext,
    command: RotateCredentialCommand,
  ): Promise<CredentialRotationResult>;
  revokeCredential(
    context: OpenPlatformRequestContext,
    command: RevokeCredentialCommand,
  ): Promise<CredentialDto>;
  getCredential(
    context: OpenPlatformRequestContext,
    query: CredentialQuery & { id: string },
  ): Promise<CredentialDto>;
  listCredentials(
    context: OpenPlatformRequestContext,
    query: CredentialQuery,
  ): Promise<CredentialDto[]>;
  verifyCredentialSecret(
    context: OpenPlatformRequestContext,
    command: VerifyCredentialSecretCommand,
  ): Promise<boolean>;

  createSubscription(
    context: OpenPlatformRequestContext,
    command: CreateSubscriptionCommand,
  ): Promise<Subscription>;
  getSubscription(
    context: OpenPlatformRequestContext,
    query: SubscriptionQuery & { id: string },
  ): Promise<Subscription>;
  listSubscriptions(
    context: OpenPlatformRequestContext,
    query: SubscriptionQuery,
  ): Promise<Subscription[]>;

  getLifecycleRecord(
    context: OpenPlatformRequestContext,
    resource: OpenPlatformLifecycleResourceKind,
    query: { tenantId: string; id: string },
  ): Promise<OpenPlatformLifecycleRecord>;
  listLifecycleRecords(
    context: OpenPlatformRequestContext,
    resource: OpenPlatformLifecycleResourceKind,
    query: { tenantId: string },
  ): Promise<OpenPlatformLifecycleRecord[]>;
  transitionLifecycle(
    context: OpenPlatformRequestContext,
    command: LifecycleTransitionCommand,
  ): Promise<OpenPlatformLifecycleRecord>;
  publish(
    context: OpenPlatformRequestContext,
    command: LifecycleCommand,
  ): Promise<OpenPlatformLifecycleRecord>;
  deactivate(
    context: OpenPlatformRequestContext,
    command: LifecycleCommand,
  ): Promise<OpenPlatformLifecycleRecord>;
  archive(
    context: OpenPlatformRequestContext,
    command: LifecycleCommand,
  ): Promise<OpenPlatformLifecycleRecord>;
  submitReview(
    context: OpenPlatformRequestContext,
    command: LifecycleCommand,
  ): Promise<OpenPlatformLifecycleRecord>;

  grantScopes(
    context: OpenPlatformRequestContext,
    command: GrantScopesCommand,
  ): Promise<ScopeGrant>;
  revokeScopeGrant(
    context: OpenPlatformRequestContext,
    command: RevokeScopeGrantCommand,
  ): Promise<ScopeGrant>;
  authorizeScopes(
    context: OpenPlatformRequestContext,
    command: AuthorizeScopesCommand,
  ): Promise<ScopeAuthorizationResult>;
  getScopeGrant(
    context: OpenPlatformRequestContext,
    query: ScopeGrantQuery & { id: string },
  ): Promise<ScopeGrant>;
  listScopeGrants(
    context: OpenPlatformRequestContext,
    query: ScopeGrantQuery,
  ): Promise<ScopeGrant[]>;

  recordUsage(
    context: OpenPlatformRequestContext,
    command: RecordUsageCommand,
  ): Promise<UsageRecord>;
  listUsage(
    context: OpenPlatformRequestContext,
    query: UsageQuery,
  ): Promise<UsageRecord[]>;

  listAuditEvents(
    context: OpenPlatformRequestContext,
    query: OpenPlatformAuditQuery,
  ): Promise<OpenPlatformAuditPage>;

  getAuditEvent(
    context: OpenPlatformRequestContext,
    query: { tenantId: string; id: string },
  ): Promise<OpenPlatformAuditEventRecord>;

  listWebhooks(
    context: OpenPlatformRequestContext,
    query: OpenPlatformWebhookQuery,
  ): Promise<OpenPlatformWebhookPage>;

  getWebhook(
    context: OpenPlatformRequestContext,
    query: OpenPlatformWebhookQuery & { id: string },
  ): Promise<OpenPlatformWebhook>;

  createWebhook(
    context: OpenPlatformRequestContext,
    command: OpenPlatformWebhookCreateCommand,
  ): Promise<OpenPlatformWebhookSecretResult>;

  pauseWebhook(
    context: OpenPlatformRequestContext,
    command: OpenPlatformWebhookLifecycleCommand,
  ): Promise<OpenPlatformWebhook>;

  disableWebhook(
    context: OpenPlatformRequestContext,
    command: OpenPlatformWebhookLifecycleCommand,
  ): Promise<OpenPlatformWebhook>;

  resumeWebhook(
    context: OpenPlatformRequestContext,
    command: OpenPlatformWebhookLifecycleCommand,
  ): Promise<OpenPlatformWebhook>;

  rotateWebhookSecret(
    context: OpenPlatformRequestContext,
    command: OpenPlatformWebhookRotateSecretCommand,
  ): Promise<OpenPlatformWebhookSecretResult>;

  dispatchWebhookEvent(
    context: OpenPlatformRequestContext,
    command: OpenPlatformWebhookDispatchCommand,
  ): Promise<OpenPlatformWebhookDispatchResult>;

  replayWebhookDelivery(
    context: OpenPlatformRequestContext,
    command: OpenPlatformWebhookReplayCommand,
  ): Promise<OpenPlatformWebhookDispatchResult>;

  listWebhookDeliveries(
    context: OpenPlatformRequestContext,
    query: OpenPlatformWebhookDeliveryQueryType,
  ): Promise<OpenPlatformWebhookDeliveryPage>;

  retryDomainEvents(
    context: OpenPlatformRequestContext,
    query: { tenantId: string; eventType?: string; limit?: number },
  ): Promise<OpenPlatformEventPublishResult[]>;
}

export interface OpenPlatformWebhookReplayCommand {
  tenantId: string;
  webhookId: string;
  deliveryId: string;
  idempotencyKey: string;
}

export interface OpenPlatformWebhookCreateCommand {
  tenantId: string;
  developerOrganizationId?: string;
  applicationId: string;
  environmentId: string;
  name: string;
  endpointUrl: string;
  events: readonly string[];
  idempotencyKey: string;
}

export interface OpenPlatformWebhookLifecycleCommand {
  tenantId: string;
  webhookId: string;
  idempotencyKey: string;
}

export interface OpenPlatformWebhookRotateSecretCommand {
  tenantId: string;
  webhookId: string;
  idempotencyKey: string;
}

export interface OpenPlatformWebhookDispatchCommand {
  tenantId: string;
  webhookId: string;
  event: OpenPlatformWebhookEventEnvelope;
  idempotencyKey: string;
  replay?: boolean;
}

