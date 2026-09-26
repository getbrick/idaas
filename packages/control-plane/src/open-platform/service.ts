import { createHash, randomBytes, randomUUID, timingSafeEqual } from "node:crypto";
import {
  isDevelopmentOpenPlatformAuthorization,
  isOpenPlatformRequestContext,
  openPlatformLifecycleAuthorizationActionForStatus,
  type OpenPlatformAuthorizationAction,
  type OpenPlatformAuthorizationPort,
  type OpenPlatformLifecycleAuthorizationAction,
  type OpenPlatformRequestContext,
} from "./authorization.js";
import {
  cloneCredentialDto,
  toCredentialDto,
  toCredentialDtoList,
} from "./credential-dto.js";
import {
  authenticationRequired,
  configurationError,
  credentialUnavailable,
  forbidden,
  idempotencyKeyReused,
  idempotencyRequestInProgress,
  isOpenPlatformDomainError,
  resourceConflict,
  resourceNotFound,
  resourceUnavailable,
  scopeGrantInvalid,
  scopeNotAllowed,
  secretIssuanceFailed,
  storageUnavailable,
  tenantMismatch,
  usageRejected,
  validationError,
} from "./errors.js";
import {
  hashOpenPlatformIdempotencyRequest,
} from "./idempotency.js";
import { InMemoryOpenPlatformRepositories } from "./repositories.js";
import {
  InMemoryOpenPlatformAuditEventStore,
  type OpenPlatformAuditEventInput,
  type OpenPlatformAuditEventRecord,
  type OpenPlatformAuditPage,
  type OpenPlatformAuditPort,
  type OpenPlatformAuditQuery,
  type OpenPlatformAuditResourceType,
} from "./audit.js";
import {
  InMemoryOpenPlatformWebhookDeliveryRepository,
  InMemoryOpenPlatformWebhookRepository,
  InMemoryOpenPlatformWebhookSecretProvider,
  OpenPlatformWebhookService,
  toOpenPlatformWebhookDto,
  type OpenPlatformWebhook,
  type OpenPlatformWebhookDeliveryPage,
  type OpenPlatformWebhookDeliveryQuery,
  type OpenPlatformWebhookDispatchResult,
  type OpenPlatformWebhookPage,

  type OpenPlatformWebhookQuery,
  type OpenPlatformWebhookSecretResult,
} from "./webhook.js";
import {
  InMemoryOpenPlatformOutbox,
  OpenPlatformEventPublisher,
  createdDomainEvent,
  openPlatformDomainEventActionForStatus,
  openPlatformDomainEventTypeForLifecycle,
  type OpenPlatformDomainEventDescriptor,
  type OpenPlatformDomainEventFactory,
  type OpenPlatformEventPublishResult,
  type OpenPlatformEventPublisherPort,
  type OpenPlatformOutboxPort,
  type OpenPlatformOutboxRecord,
} from "./events.js";
import {
  assertCredentialTransition,
  assertLifecycleTransition,
} from "./state-machine.js";
import type {
  ApiProduct,
  ApiProductQuery,
  ApiVersion,
  ApiVersionQuery,
  Application,
  ApplicationEnvironment,
  ApplicationEnvironmentQuery,
  ApplicationQuery,
  AuthorizeScopesCommand,
  CreateApiProductCommand,
  CreateApiVersionCommand,
  CreateApplicationCommand,
  CreateApplicationEnvironmentCommand,
  CreateDeveloperOrganizationCommand,
  CreateSubscriptionCommand,
  CreateTenantCommand,
  CredentialDto,
  CredentialIssuanceResult,
  CredentialQuery,
  CredentialRecord,
  CredentialRotationResult,
  CredentialSecretCompensationInput,
  CredentialSecretMaterial,
  CredentialSecretProvider,
  CredentialSecretRevokeInput,
  DeveloperOrganization,
  DeveloperOrganizationQuery,
  GrantScopesCommand,
  IdempotencyExecution,
  IssueCredentialCommand,
  LifecycleCommand,
  LifecycleTransitionCommand,
  OpenPlatformDomainService,
  OpenPlatformEntityKind,
  OpenPlatformLifecycleStatus,
  OpenPlatformWebhookCreateCommand,
  OpenPlatformWebhookDispatchCommand,
  OpenPlatformWebhookLifecycleCommand,
  OpenPlatformWebhookRotateSecretCommand,
  OpenPlatformWebhookReplayCommand,
  OpenPlatformLifecycleRecord,
  OpenPlatformLifecycleResourceKind,
  OpenPlatformReadiness,
  OpenPlatformRecord,
  OpenPlatformRepositories,
  OpenPlatformRuntimeMode,
  OpenPlatformServiceOptions,
  RecordUsageCommand,
  RevokeCredentialCommand,
  RevokeScopeGrantCommand,
  RotateCredentialCommand,
  ScopeAuthorizationResult,
  ScopeGrant,
  ScopeGrantQuery,
  Subscription,
  SubscriptionQuery,
  Tenant,
  TenantQuery,
  TenantScopedRepository,
  UsageQuery,
  UsageRecord,
  VerifyCredentialSecretCommand,
} from "./types.js";
import {
  normalizeApiProductQuery,
  normalizeApiVersionQuery,
  normalizeApplicationEnvironmentQuery,
  normalizeApplicationQuery,
  normalizeAuthorizeScopesCommand,
  normalizeCreateApiProductCommand,
  normalizeCreateApiVersionCommand,
  normalizeCreateApplicationCommand,
  normalizeCreateApplicationEnvironmentCommand,
  normalizeCreateDeveloperOrganizationCommand,
  normalizeCreateSubscriptionCommand,
  normalizeCreateTenantCommand,
  normalizeCredentialQuery,
  normalizeDeveloperOrganizationQuery,
  normalizeGrantScopesCommand,
  normalizeIdentifier,
  normalizeIssueCredentialCommand,
  normalizeLifecycleCommand,
  normalizeLifecycleResource,
  normalizeLifecycleTransitionCommand,
  normalizeRecordUsageCommand,
  normalizeResourceId,
  normalizeRevokeCredentialCommand,
  normalizeRevokeScopeGrantCommand,
  normalizeRotateCredentialCommand,
  normalizeScopeGrantQuery,
  normalizeSubscriptionQuery,
  normalizeTenantKey,
  normalizeTenantQuery,
  normalizeTimestamp,
  normalizeUsageQuery,
  type NormalizedLifecycleTransitionCommand,
} from "./validation.js";

export class OpenPlatformService implements OpenPlatformDomainService {
  readonly repositories: OpenPlatformRepositories;
  readonly mode: OpenPlatformRuntimeMode;
  readonly webhooks: OpenPlatformWebhookService;
  readonly outbox: OpenPlatformOutboxPort;
  readonly eventPublisher: OpenPlatformEventPublisherPort;
  private readonly authorization: OpenPlatformAuthorizationPort;
  private readonly audit: OpenPlatformAuditPort;
  private readonly requiredContextAssurance: "development" | "authenticated";
  private readonly clock: () => Date;
  private readonly idGenerator: (kind: OpenPlatformEntityKind) => string;
  private readonly secretProvider: CredentialSecretProvider;
  private readonly leaseMs: number;
  private readonly retentionMs: number;
  private readonly eventsEnabled: boolean;
  private readonly usageEventThresholds: ReadonlyMap<string, number>;

  constructor(options: OpenPlatformServiceOptions) {
    if (options === null || options === undefined) {
      throw configurationError("Open platform service configuration is required");
    }
    this.mode = options.mode;
    this.authorization = options.authorization;
    this.requiredContextAssurance = options.requiredContextAssurance ??
      (options.mode === "production" ? "authenticated" : "development");
    this.clock = options.clock ?? (() => new Date());
    this.idGenerator = options.idGenerator ?? createOpenPlatformId;
    this.secretProvider = options.secretProvider ?? createRandomCredentialSecretProvider();
    this.leaseMs = 30_000;
    this.retentionMs = 86_400_000;
    this.eventsEnabled = options.eventsEnabled !== false && options.eventDeliveryEnabled !== false;
    this.usageEventThresholds = normalizeUsageEventThresholds(options.usageEventThresholds);
    this.repositories = options.repositories ?? new InMemoryOpenPlatformRepositories({
      clock: this.clock,
      production: options.mode === "production",
    });
    this.audit = options.audit ?? options.auditPort ?? options.auditEventStore ??
      this.repositories.auditEvents ?? new InMemoryOpenPlatformAuditEventStore({
        clock: this.clock,
        production: options.mode === "production",
      });
    this.webhooks = new OpenPlatformWebhookService({
      mode: this.mode,
      authorization: this.authorization,
      webhooks: options.webhookRepository ?? this.repositories.webhooks ?? new InMemoryOpenPlatformWebhookRepository(),
      deliveries: options.webhookDeliveryRepository ?? this.repositories.webhookDeliveries ?? new InMemoryOpenPlatformWebhookDeliveryRepository(),
      secretProvider: options.webhookSecretProvider ?? new InMemoryOpenPlatformWebhookSecretProvider({ production: options.mode === "production" }),
      ...(options.webhookTransport === undefined ? {} : { transport: options.webhookTransport }),
      audit: this.audit,
      auditEnabled: false,
      auditDeniedEnabled: false,
      clock: this.clock,
      idGenerator: this.idGenerator,
      ...(options.webhookService === undefined ? {} : options.webhookService),
    });
    this.outbox = options.outbox ??
      this.repositories.domainEvents ??
      new InMemoryOpenPlatformOutbox({
        clock: this.clock,
        production: options.mode === "production",
      });
    this.eventPublisher = options.eventPublisher ??
      new OpenPlatformEventPublisher({
        outbox: this.outbox,
        clock: this.clock,
        idGenerator: () =>
          `open_platform_event_${this.newId("auditEvent").slice("audit_".length)}`,
        sink: {
          deliver: async (event) => {
            const result = await this.webhooks.dispatchDomainEvent(event);
            return {
              delivered: result.deliveries.length,
              deadLettered: result.deadLettered,
            };
          },
        },
      });

    if (!isRuntimeMode(this.mode)) {
      throw configurationError("Open platform runtime mode is invalid");
    }
    if (!isContextAssurance(this.requiredContextAssurance)) {
      throw configurationError("Open platform context assurance is invalid");
    }
    if (
      this.authorization === null ||
      typeof this.authorization !== "object" ||
      typeof this.authorization.authorize !== "function"
    ) {
      throw configurationError("Open platform authorization is required");
    }
    if (options.mode === "production") {
      if (!this.authorization.productionReady) {
        throw configurationError(
          "Production open platform requires a production authorization port",
        );
      }
      if (isDevelopmentOpenPlatformAuthorization(this.authorization)) {
        throw configurationError(
          "Development authorization cannot be used in production",
        );
      }
      if (
        this.repositories.readiness.storage !== "persistent" &&
        options.allowInMemoryInProduction !== true
      ) {
        throw configurationError(
          "Production open platform cannot use in-memory repositories",
        );
      }
      if (!isPersistentDistributed(this.repositories.readiness)) {
        if (options.allowInMemoryInProduction !== true) {
          throw configurationError(
            "Production open platform requires persistent distributed storage",
          );
        }
      }
      if (!isPersistentDistributed(this.repositories.idempotency.readiness)) {
        if (options.allowInMemoryInProduction !== true) {
          throw configurationError(
            "Production open platform requires a distributed idempotency store",
          );
        }
      }
      if (!isPersistentDistributed(this.secretProvider.readiness)) {
        if (options.allowInMemoryInProduction !== true) {
          throw configurationError(
            "Production open platform requires a persistent secret provider",
          );
        }
      }
      if (this.eventsEnabled) {
        if (options.outbox === undefined && options.repositories?.domainEvents === undefined) {
          if (options.allowInMemoryInProduction !== true) {
            throw configurationError(
              "Production open platform requires a persistent domain event outbox",
            );
          }
        }
        if (options.eventPublisher === undefined) {
          if (
            this.outbox.readiness === undefined ||
            !isPersistentDistributed(this.outbox.readiness)
          ) {
            if (options.allowInMemoryInProduction !== true) {
              throw configurationError(
                "Production open platform requires a distributed domain event outbox",
              );
            }
          }
        }
      }
    }
  }

  async isReady(): Promise<OpenPlatformReadiness> {
    const storageReady = await safelyReady(this.repositories.readiness);
    const idempotencyReady = await safelyReady(
      this.repositories.idempotency.readiness,
    );
    const secretReady = this.secretProvider.readiness === undefined
      ? this.mode !== "production"
      : await safelyReady(this.secretProvider.readiness);
    const auditReady = this.audit.readiness === undefined
      ? true
      : await safelyReady(this.audit.readiness);
    const webhookReady = await this.webhooks.isReady().catch(() => false);
    const eventsReady = !this.eventsEnabled || await this.eventsOperationalReady();
    const productionShape = this.mode !== "production" ||
      (isPersistentDistributed(this.repositories.readiness) &&
        isPersistentDistributed(this.repositories.idempotency.readiness) &&
        isPersistentDistributed(this.secretProvider.readiness));
    return {
      ready: storageReady && idempotencyReady && secretReady && auditReady && webhookReady && eventsReady && productionShape,
      mode: this.mode,
      storage: this.repositories.readiness.storage,
      distributed: this.repositories.readiness.distributed,
      events: eventsReady,
    };
  }

  async retryDomainEvents(
    context: OpenPlatformRequestContext,
    query: { tenantId: string; eventType?: string; limit?: number },
  ): Promise<OpenPlatformEventPublishResult[]> {
    const tenantId = normalizeTenantKey(query?.tenantId);
    const actor = await this.authorize(context, tenantId, "record", "webhook");
    if (typeof this.eventPublisher.flush !== "function") {
      throw configurationError("Open platform event publisher cannot retry events");
    }
    return this.eventPublisher.flush({
      tenantId: actor.tenantId,
      ...(query.eventType === undefined ? {} : { eventType: query.eventType }),
      ...(query.limit === undefined ? {} : { limit: query.limit }),
    });
  }

  async listAuditEvents(
    context: OpenPlatformRequestContext,
    query: OpenPlatformAuditQuery,
  ): Promise<OpenPlatformAuditPage> {
    const tenantId = normalizeTenantKey(query?.tenantId);
    const actor = await this.authorize(context, tenantId, "read", "auditEvent");
    if (this.audit.list === undefined) throw resourceNotFound("auditEvent");
    return this.audit.list({ ...query, tenantId: actor.tenantId });
  }

  async getAuditEvent(
    context: OpenPlatformRequestContext,
    query: { tenantId: string; id: string },
  ): Promise<OpenPlatformAuditEventRecord> {
    const tenantId = normalizeTenantKey(query?.tenantId);
    const actor = await this.authorize(context, tenantId, "read", "auditEvent", query.id);
    if (this.audit.get === undefined) throw resourceNotFound("auditEvent");
    const event = await this.audit.get(actor.tenantId, query.id);
    if (event === undefined) throw resourceNotFound("auditEvent");
    return event;
  }

  async listWebhooks(
    context: OpenPlatformRequestContext,
    query: OpenPlatformWebhookQuery,
  ): Promise<OpenPlatformWebhookPage> {
    return this.webhooks.listWebhooks(context, query);
  }

  async getWebhook(
    context: OpenPlatformRequestContext,
    query: OpenPlatformWebhookQuery & { id: string },
  ): Promise<OpenPlatformWebhook> {
    return this.webhooks.getWebhook(context, query);
  }

  async createWebhook(
    context: OpenPlatformRequestContext,
    command: OpenPlatformWebhookCreateCommand,
  ): Promise<OpenPlatformWebhookSecretResult> {
    const execution = await this.execute(
      context,
      command.idempotencyKey,
      "webhook.create",
      command,
      () => this.webhooks.createWebhook(context, command),
      projectWebhookSecretResult,
    );
    return {
      ...execution.result,
      secret: execution.result.secret ?? "",
      replayed: execution.replayed,
    };
  }

  async pauseWebhook(
    context: OpenPlatformRequestContext,
    command: OpenPlatformWebhookLifecycleCommand,
  ): Promise<OpenPlatformWebhook> {
    const execution = await this.execute(
      context,
      command.idempotencyKey,
      "webhook.pause",
      command,
      () => this.webhooks.pauseWebhook(context, command),
      projectWebhookRecord,
    );
    return execution.result;
  }

  async disableWebhook(
    context: OpenPlatformRequestContext,
    command: OpenPlatformWebhookLifecycleCommand,
  ): Promise<OpenPlatformWebhook> {
    const execution = await this.execute(
      context,
      command.idempotencyKey,
      "webhook.disable",
      command,
      () => this.webhooks.disableWebhook(context, command),
      projectWebhookRecord,
    );
    return execution.result;
  }

  async resumeWebhook(
    context: OpenPlatformRequestContext,
    command: OpenPlatformWebhookLifecycleCommand,
  ): Promise<OpenPlatformWebhook> {
    const execution = await this.execute(
      context,
      command.idempotencyKey,
      "webhook.resume",
      command,
      () => this.webhooks.resumeWebhook(context, command),
      projectWebhookRecord,
    );
    return execution.result;
  }

  async rotateWebhookSecret(
    context: OpenPlatformRequestContext,
    command: OpenPlatformWebhookRotateSecretCommand,
  ): Promise<OpenPlatformWebhookSecretResult> {
    const execution = await this.execute(
      context,
      command.idempotencyKey,
      "webhook.rotate_secret",
      command,
      () => this.webhooks.rotateWebhookSecret(context, command),
      projectWebhookSecretResult,
    );
    return {
      ...execution.result,
      secret: execution.result.secret ?? "",
      replayed: execution.replayed,
    };
  }

  async dispatchWebhookEvent(
    context: OpenPlatformRequestContext,
    command: OpenPlatformWebhookDispatchCommand,
  ): Promise<OpenPlatformWebhookDispatchResult> {
    const execution = await this.execute(
      context,
      command.idempotencyKey,
      "webhook.dispatch",
      command,
      () => this.webhooks.dispatchWebhookEvent(context, command),
    );
    return execution.result;
  }

  async replayWebhookDelivery(
    context: OpenPlatformRequestContext,
    command: OpenPlatformWebhookReplayCommand,
  ): Promise<OpenPlatformWebhookDispatchResult> {
    const execution = await this.execute(
      context,
      command.idempotencyKey,
      "webhook.replay",
      command,
      () => this.webhooks.replayDelivery(context, command),
    );
    return execution.result;
  }

  async listWebhookDeliveries(
    context: OpenPlatformRequestContext,
    query: OpenPlatformWebhookDeliveryQuery,
  ): Promise<OpenPlatformWebhookDeliveryPage> {
    return this.webhooks.listWebhookDeliveries(context, query);
  }

  async createTenant(
    context: OpenPlatformRequestContext,
    command: CreateTenantCommand,
  ): Promise<Tenant> {
    const normalized = normalizeCreateTenantCommand(command);
    const actor = await this.authorize(
      context,
      normalized.tenantId,
      "create",
      "tenant",
    );
    const execution = await this.execute(
      actor,
      normalized.idempotencyKey,
      "tenant.create",
      normalized,
      async () => {
        const timestamp = this.timestamp();
        return this.repositories.tenants.create({
          id: this.newId("tenant"),
          tenantId: actor.tenantId,
          kind: "tenant",
          name: normalized.name,
          status: "draft",
          version: 1,
          createdAt: timestamp,
          updatedAt: timestamp,
        });
      },
      undefined,
      (created) => createdDomainEvent("tenant.created", created),
    );
    return execution.result;
  }

  async getTenant(
    context: OpenPlatformRequestContext,
    query: TenantQuery,
  ): Promise<Tenant> {
    const normalized = normalizeTenantQuery(query);
    const actor = await this.authorize(
      context,
      normalized.tenantId,
      "read",
      "tenant",
    );
    return this.requireTenantByKey(actor.tenantId);
  }

  async listTenants(
    context: OpenPlatformRequestContext,
    query: TenantQuery,
  ): Promise<Tenant[]> {
    const normalized = normalizeTenantQuery(query);
    const actor = await this.authorize(
      context,
      normalized.tenantId,
      "read",
      "tenant",
    );
    return this.repositories.tenants.list(actor.tenantId);
  }

  async createDeveloperOrganization(
    context: OpenPlatformRequestContext,
    command: CreateDeveloperOrganizationCommand,
  ): Promise<DeveloperOrganization> {
    const normalized = normalizeCreateDeveloperOrganizationCommand(command);
    const actor = await this.authorize(
      context,
      normalized.tenantId,
      "create",
      "developerOrganization",
    );
    const execution = await this.execute(
      actor,
      normalized.idempotencyKey,
      "developerOrganization.create",
      normalized,
      async () => {
        await this.requirePublishedTenant(actor.tenantId);
        const timestamp = this.timestamp();
        return this.repositories.developerOrganizations.create({
          id: this.newId("developerOrganization"),
          tenantId: actor.tenantId,
          kind: "developerOrganization",
          name: normalized.name,
          ...(normalized.description === undefined
            ? {}
            : { description: normalized.description }),
          status: "draft",
          version: 1,
          createdAt: timestamp,
          updatedAt: timestamp,
        });
      },
      undefined,
      (created) => createdDomainEvent("developer_organization.created", created),
    );
    return execution.result;
  }

  async getDeveloperOrganization(
    context: OpenPlatformRequestContext,
    query: DeveloperOrganizationQuery & { id: string },
  ): Promise<DeveloperOrganization> {
    const normalized = normalizeDeveloperOrganizationQuery(query);
    const actor = await this.authorize(
      context,
      normalized.tenantId,
      "read",
      "developerOrganization",
      normalized.id,
    );
    return this.requireResource(
      this.repositories.developerOrganizations,
      actor.tenantId,
      normalized.id ?? "",
      "developerOrganization",
    );
  }

  async listDeveloperOrganizations(
    context: OpenPlatformRequestContext,
    query: DeveloperOrganizationQuery,
  ): Promise<DeveloperOrganization[]> {
    const normalized = normalizeDeveloperOrganizationQuery(query);
    const actor = await this.authorize(
      context,
      normalized.tenantId,
      "read",
      "developerOrganization",
      normalized.id,
    );
    const records = await this.repositories.developerOrganizations.list(
      actor.tenantId,
    );
    return normalized.id === undefined
      ? records
      : records.filter((record) => record.id === normalized.id);
  }

  async createApplication(
    context: OpenPlatformRequestContext,
    command: CreateApplicationCommand,
  ): Promise<Application> {
    const normalized = normalizeCreateApplicationCommand(command);
    const actor = await this.authorize(
      context,
      normalized.tenantId,
      "create",
      "application",
    );
    const execution = await this.execute(
      actor,
      normalized.idempotencyKey,
      "application.create",
      normalized,
      async () => {
        await this.requirePublishedTenant(actor.tenantId);
        await this.requirePublished(
          this.repositories.developerOrganizations,
          actor.tenantId,
          normalized.organizationId,
          "developerOrganization",
        );
        const timestamp = this.timestamp();
        return this.repositories.applications.create({
          id: this.newId("application"),
          tenantId: actor.tenantId,
          kind: "application",
          organizationId: normalized.organizationId,
          name: normalized.name,
          ...(normalized.description === undefined
            ? {}
            : { description: normalized.description }),
          status: "draft",
          version: 1,
          createdAt: timestamp,
          updatedAt: timestamp,
        });
      },
      undefined,
      (created) =>
        createdDomainEvent("application.created", created, {
          organizationId: created.organizationId,
        }),
    );
    return execution.result;
  }

  async getApplication(
    context: OpenPlatformRequestContext,
    query: ApplicationQuery & { id: string },
  ): Promise<Application> {
    const normalized = normalizeApplicationQuery(query);
    const actor = await this.authorize(
      context,
      normalized.tenantId,
      "read",
      "application",
      normalized.id,
    );
    return this.requireResource(
      this.repositories.applications,
      actor.tenantId,
      normalized.id ?? "",
      "application",
    );
  }

  async listApplications(
    context: OpenPlatformRequestContext,
    query: ApplicationQuery,
  ): Promise<Application[]> {
    const normalized = normalizeApplicationQuery(query);
    const actor = await this.authorize(
      context,
      normalized.tenantId,
      "read",
      "application",
      normalized.id,
    );
    const records = await this.repositories.applications.list(actor.tenantId);
    return normalized.id === undefined
      ? records
      : records.filter((record) => record.id === normalized.id);
  }

  async createApplicationEnvironment(
    context: OpenPlatformRequestContext,
    command: CreateApplicationEnvironmentCommand,
  ): Promise<ApplicationEnvironment> {
    const normalized = normalizeCreateApplicationEnvironmentCommand(command);
    const actor = await this.authorize(
      context,
      normalized.tenantId,
      "create",
      "applicationEnvironment",
    );
    const execution = await this.execute(
      actor,
      normalized.idempotencyKey,
      "applicationEnvironment.create",
      normalized,
      async () => {
        await this.requirePublishedTenant(actor.tenantId);
        await this.requirePublished(
          this.repositories.applications,
          actor.tenantId,
          normalized.applicationId,
          "application",
        );
        const timestamp = this.timestamp();
        return this.repositories.applicationEnvironments.create({
          id: this.newId("applicationEnvironment"),
          tenantId: actor.tenantId,
          kind: "applicationEnvironment",
          applicationId: normalized.applicationId,
          name: normalized.name,
          status: "draft",
          version: 1,
          createdAt: timestamp,
          updatedAt: timestamp,
        });
      },
      undefined,
      (created) =>
        createdDomainEvent("client.created", created, {
          applicationId: created.applicationId,
        }),
    );
    return execution.result;
  }

  async getApplicationEnvironment(
    context: OpenPlatformRequestContext,
    query: ApplicationEnvironmentQuery & { id: string },
  ): Promise<ApplicationEnvironment> {
    const normalized = normalizeApplicationEnvironmentQuery(query);
    const actor = await this.authorize(
      context,
      normalized.tenantId,
      "read",
      "applicationEnvironment",
      normalized.id,
    );
    const record = await this.requireResource(
      this.repositories.applicationEnvironments,
      actor.tenantId,
      normalized.id ?? "",
      "applicationEnvironment",
    );
    if (
      normalized.applicationId !== undefined &&
      record.applicationId !== normalized.applicationId
    ) {
      throw resourceNotFound("applicationEnvironment");
    }
    return record;
  }

  async listApplicationEnvironments(
    context: OpenPlatformRequestContext,
    query: ApplicationEnvironmentQuery,
  ): Promise<ApplicationEnvironment[]> {
    const normalized = normalizeApplicationEnvironmentQuery(query);
    const actor = await this.authorize(
      context,
      normalized.tenantId,
      "read",
      "applicationEnvironment",
      normalized.id,
    );
    const records = await this.repositories.applicationEnvironments.list(
      actor.tenantId,
    );
    return records.filter((record) =>
      (normalized.applicationId === undefined ||
        record.applicationId === normalized.applicationId) &&
      (normalized.id === undefined || record.id === normalized.id)
    );
  }

  async createApiProduct(
    context: OpenPlatformRequestContext,
    command: CreateApiProductCommand,
  ): Promise<ApiProduct> {
    const normalized = normalizeCreateApiProductCommand(command);
    const actor = await this.authorize(
      context,
      normalized.tenantId,
      "create",
      "apiProduct",
    );
    const execution = await this.execute(
      actor,
      normalized.idempotencyKey,
      "apiProduct.create",
      normalized,
      async () => {
        await this.requirePublishedTenant(actor.tenantId);
        const timestamp = this.timestamp();
        return this.repositories.apiProducts.create({
          id: this.newId("apiProduct"),
          tenantId: actor.tenantId,
          kind: "apiProduct",
          name: normalized.name,
          ...(normalized.description === undefined
            ? {}
            : { description: normalized.description }),
          scopes: normalized.scopes,
          status: "draft",
          version: 1,
          createdAt: timestamp,
          updatedAt: timestamp,
        });
      },
      undefined,
      (created) => createdDomainEvent("api_product.created", created),
    );
    return execution.result;
  }

  async getApiProduct(
    context: OpenPlatformRequestContext,
    query: ApiProductQuery & { id: string },
  ): Promise<ApiProduct> {
    const normalized = normalizeApiProductQuery(query);
    const actor = await this.authorize(
      context,
      normalized.tenantId,
      "read",
      "apiProduct",
      normalized.id,
    );
    return this.requireResource(
      this.repositories.apiProducts,
      actor.tenantId,
      normalized.id ?? "",
      "apiProduct",
    );
  }

  async listApiProducts(
    context: OpenPlatformRequestContext,
    query: ApiProductQuery,
  ): Promise<ApiProduct[]> {
    const normalized = normalizeApiProductQuery(query);
    const actor = await this.authorize(
      context,
      normalized.tenantId,
      "read",
      "apiProduct",
      normalized.id,
    );
    const records = await this.repositories.apiProducts.list(actor.tenantId);
    return normalized.id === undefined
      ? records
      : records.filter((record) => record.id === normalized.id);
  }

  async createApiVersion(
    context: OpenPlatformRequestContext,
    command: CreateApiVersionCommand,
  ): Promise<ApiVersion> {
    const normalized = normalizeCreateApiVersionCommand(command);
    const actor = await this.authorize(
      context,
      normalized.tenantId,
      "create",
      "apiVersion",
    );
    const execution = await this.execute(
      actor,
      normalized.idempotencyKey,
      "apiVersion.create",
      normalized,
      async () => {
        await this.requirePublishedTenant(actor.tenantId);
        const product = await this.requirePublished(
          this.repositories.apiProducts,
          actor.tenantId,
          normalized.productId,
          "apiProduct",
        );
        assertScopesAllowed(normalized.scopes, product.scopes);
        const existing = await this.repositories.apiVersions.list(actor.tenantId);
        if (
          existing.some((record) =>
            record.productId === normalized.productId &&
            record.apiVersion === normalized.apiVersion
          )
        ) {
          throw resourceConflict("API version already exists for this product");
        }
        const timestamp = this.timestamp();
        return this.repositories.apiVersions.create({
          id: this.newId("apiVersion"),
          tenantId: actor.tenantId,
          kind: "apiVersion",
          productId: normalized.productId,
          apiVersion: normalized.apiVersion,
          ...(normalized.description === undefined
            ? {}
            : { description: normalized.description }),
          scopes: normalized.scopes,
          status: "draft",
          version: 1,
          createdAt: timestamp,
          updatedAt: timestamp,
        });
      },
      undefined,
      (created) =>
        createdDomainEvent("api_version.created", created, {
          productId: created.productId,
        }),
    );
    return execution.result;
  }

  async getApiVersion(
    context: OpenPlatformRequestContext,
    query: ApiVersionQuery & { id: string },
  ): Promise<ApiVersion> {
    const normalized = normalizeApiVersionQuery(query);
    const actor = await this.authorize(
      context,
      normalized.tenantId,
      "read",
      "apiVersion",
      normalized.id,
    );
    const record = await this.requireResource(
      this.repositories.apiVersions,
      actor.tenantId,
      normalized.id ?? "",
      "apiVersion",
    );
    if (
      normalized.productId !== undefined &&
      record.productId !== normalized.productId
    ) {
      throw resourceNotFound("apiVersion");
    }
    return record;
  }

  async listApiVersions(
    context: OpenPlatformRequestContext,
    query: ApiVersionQuery,
  ): Promise<ApiVersion[]> {
    const normalized = normalizeApiVersionQuery(query);
    const actor = await this.authorize(
      context,
      normalized.tenantId,
      "read",
      "apiVersion",
      normalized.id,
    );
    const records = await this.repositories.apiVersions.list(actor.tenantId);
    return records.filter((record) =>
      (normalized.productId === undefined ||
        record.productId === normalized.productId) &&
      (normalized.id === undefined || record.id === normalized.id)
    );
  }

  async issueCredential(
    context: OpenPlatformRequestContext,
    command: IssueCredentialCommand,
  ): Promise<CredentialIssuanceResult> {
    const normalized = normalizeIssueCredentialCommand(command);
    const actor = await this.authorize(
      context,
      normalized.tenantId,
      "issue",
      "credential",
      normalized.applicationId,
    );
    const execution = await this.execute(
      actor,
      normalized.idempotencyKey,
      "credential.issue",
      normalized,
      async () => {
        const application = await this.requirePublishedApplication(
          actor.tenantId,
          normalized.applicationId,
        );
        if (normalized.environmentId !== undefined) {
          await this.requirePublishedEnvironment(
            actor.tenantId,
            application.id,
            normalized.environmentId,
          );
        }
        if (
          normalized.expiresAt !== undefined &&
          Date.parse(normalized.expiresAt) <= Date.parse(this.timestamp())
        ) {
          throw validationError("Credential expiration must be in the future");
        }
        const credentialId = this.newId("credential");
        const material = await this.generateSecret({
          tenantId: actor.tenantId,
          applicationId: application.id,
          credentialId,
          reason: "issue",
        });
        const digest = digestSecret(material.secret);
        const timestamp = this.timestamp();
        let record: CredentialRecord;
        try {
          record = await this.repositories.credentials.create({
            id: credentialId,
            tenantId: actor.tenantId,
            kind: "credential",
            applicationId: application.id,
            ...(normalized.environmentId === undefined
              ? {}
              : { environmentId: normalized.environmentId }),
            name: normalized.name,
            status: "active",
            scopes: normalized.scopes,
            secret: {
              digest,
              ...(material.reference === undefined
                ? {}
                : { reference: material.reference }),
            },
            fingerprint: digest.slice(7, 31),
            ...(normalized.expiresAt === undefined
              ? {}
              : { expiresAt: normalized.expiresAt }),
            version: 1,
            createdAt: timestamp,
            updatedAt: timestamp,
          });
        } catch (error) {
          await this.compensateSecret({
            tenantId: actor.tenantId,
            applicationId: application.id,
            credentialId,
            digest,
            ...(material.reference === undefined
              ? {}
              : { reference: material.reference }),
          }, "issuePersistenceFailed");
          throw error;
        }
        return {
          credential: toCredentialDto(record),
          secret: material.secret,
          replayed: false,
        };
      },
      projectCredentialIssuance,
      (issued) =>
        createdDomainEvent("credential.created", issued.credential, {
          applicationId: issued.credential.applicationId,
          ...(issued.credential.environmentId === undefined
            ? {}
            : { environmentId: issued.credential.environmentId }),
        }),
    );
    return { ...execution.result, replayed: execution.replayed };
  }

  async rotateCredential(
    context: OpenPlatformRequestContext,
    command: RotateCredentialCommand,
  ): Promise<CredentialRotationResult> {
    const normalized = normalizeRotateCredentialCommand(command);
    const actor = await this.authorize(
      context,
      normalized.tenantId,
      "rotate",
      "credential",
      normalized.credentialId,
    );
    const execution = await this.execute(
      actor,
      normalized.idempotencyKey,
      "credential.rotate",
      normalized,
      async () => {
        const current = await this.requireUsableCredential(
          actor.tenantId,
          normalized.credentialId,
        );
        const credentialId = this.newId("credential");
        const material = await this.generateSecret({
          tenantId: actor.tenantId,
          applicationId: current.applicationId,
          credentialId,
          reason: "rotate",
        });
        const digest = digestSecret(material.secret);
        if (digest === current.secret.digest) {
          await this.compensateSecret({
            tenantId: actor.tenantId,
            applicationId: current.applicationId,
            credentialId,
            digest,
            ...(material.reference === undefined
              ? {}
              : { reference: material.reference }),
          }, "rotationPersistenceFailed");
          throw secretIssuanceFailed();
        }
        const timestamp = this.timestamp();
        const previousCredential: CredentialRecord = {
          ...current,
          status: "rotated",
          version: current.version + 1,
          rotatedAt: timestamp,
          updatedAt: timestamp,
          replacedByCredentialId: credentialId,
        };
        const replacementCredential: CredentialRecord = {
          id: credentialId,
          tenantId: current.tenantId,
          kind: "credential",
          applicationId: current.applicationId,
          ...(current.environmentId === undefined
            ? {}
            : { environmentId: current.environmentId }),
          name: current.name,
          status: "active",
          scopes: [...current.scopes],
          secret: {
            digest,
            ...(material.reference === undefined
              ? {}
              : { reference: material.reference }),
          },
          fingerprint: digest.slice(7, 31),
          ...(current.expiresAt === undefined
            ? {}
            : { expiresAt: current.expiresAt }),
          previousCredentialId: current.id,
          version: 1,
          createdAt: timestamp,
          updatedAt: timestamp,
        };
        let rotated: {
          credential: CredentialRecord;
          previousCredential: CredentialRecord;
        };
        try {
          rotated = await this.repositories.credentials.rotate(
            previousCredential,
            replacementCredential,
          );
        } catch (error) {
          await this.compensateSecret({
            tenantId: actor.tenantId,
            applicationId: current.applicationId,
            credentialId,
            digest,
            ...(material.reference === undefined
              ? {}
              : { reference: material.reference }),
          }, "rotationPersistenceFailed");
          throw error;
        }
        try {
          await this.revokeStoredSecret(current, "rotation");
        } catch {
          try {
            await this.repositories.credentials.save({
              ...rotated.credential,
              status: "revoked",
              version: rotated.credential.version + 1,
              revokedAt: this.timestamp(),
              updatedAt: this.timestamp(),
            });
          } catch {
            await this.compensateSecret({
              tenantId: actor.tenantId,
              applicationId: current.applicationId,
              credentialId,
              digest,
              ...(material.reference === undefined
                ? {}
                : { reference: material.reference }),
            }, "rotationRevokeFailed");
            throw secretIssuanceFailed();
          }
          await this.compensateSecret({
            tenantId: actor.tenantId,
            applicationId: current.applicationId,
            credentialId,
            digest,
            ...(material.reference === undefined
              ? {}
              : { reference: material.reference }),
          }, "rotationRevokeFailed");
          throw secretIssuanceFailed();
        }
        return {
          credential: toCredentialDto(rotated.credential),
          previousCredential: toCredentialDto(rotated.previousCredential),
          secret: material.secret,
          replayed: false,
        };
      },
      projectCredentialRotation,
      (rotated) => ({
        eventType: "credential.status_changed",
        resourceType: "credential",
        resourceId: rotated.credential.id,
        resourceVersion: rotated.credential.version,
        resourceStatus: rotated.credential.status,
        data: {
          action: "rotated",
          applicationId: rotated.credential.applicationId,
          previousId: rotated.previousCredential.id,
        },
      }),
    );
    return { ...execution.result, replayed: execution.replayed };
  }

  async revokeCredential(
    context: OpenPlatformRequestContext,
    command: RevokeCredentialCommand,
  ): Promise<CredentialDto> {
    const normalized = normalizeRevokeCredentialCommand(command);
    const actor = await this.authorize(
      context,
      normalized.tenantId,
      "revoke",
      "credential",
      normalized.credentialId,
    );
    let transitioned = false;
    const execution = await this.execute(
      actor,
      normalized.idempotencyKey,
      "credential.revoke",
      normalized,
      async () => {
        const current = await this.requireCredential(
          actor.tenantId,
          normalized.credentialId,
        );
        if (current.status === "revoked" || current.status === "rotated") {
          await this.revokeStoredSecret(current, "revocation");
          return toCredentialDto(current);
        }
        assertCredentialTransition(current.status, "revoked");
        const timestamp = this.timestamp();
        const record = await this.repositories.credentials.save({
          ...current,
          status: "revoked",
          version: current.version + 1,
          revokedAt: timestamp,
          updatedAt: timestamp,
        });
        await this.revokeStoredSecret(record, "revocation");
        transitioned = true;
        return toCredentialDto(record);
      },
      undefined,
      (revoked) =>
        transitioned
          ? {
              eventType: "credential.status_changed",
              resourceType: "credential",
              resourceId: revoked.id,
              resourceVersion: revoked.version,
              resourceStatus: revoked.status,
              data: {
                action: "revoked",
                applicationId: revoked.applicationId,
              },
            }
          : undefined,
    );
    return execution.result;
  }

  async getCredential(
    context: OpenPlatformRequestContext,
    query: CredentialQuery & { id: string },
  ): Promise<CredentialDto> {
    const normalized = normalizeCredentialQuery(query);
    const actor = await this.authorize(
      context,
      normalized.tenantId,
      "read",
      "credential",
      normalized.id,
    );
    const credential = await this.requireResource(
      this.repositories.credentials,
      actor.tenantId,
      normalized.id ?? "",
      "credential",
    );
    if (
      (normalized.applicationId !== undefined &&
        credential.applicationId !== normalized.applicationId) ||
      (normalized.environmentId !== undefined &&
        credential.environmentId !== normalized.environmentId)
    ) {
      throw resourceNotFound("credential");
    }
    return toCredentialDto(credential);
  }

  async listCredentials(
    context: OpenPlatformRequestContext,
    query: CredentialQuery,
  ): Promise<CredentialDto[]> {
    const normalized = normalizeCredentialQuery(query);
    const actor = await this.authorize(
      context,
      normalized.tenantId,
      "read",
      "credential",
      normalized.id,
    );
    const records = await this.repositories.credentials.list(actor.tenantId);
    return toCredentialDtoList(records.filter((record) =>
      (normalized.id === undefined || record.id === normalized.id) &&
      (normalized.applicationId === undefined ||
        record.applicationId === normalized.applicationId) &&
      (normalized.environmentId === undefined ||
        record.environmentId === normalized.environmentId)
    ));
  }

  async verifyCredentialSecret(
    context: OpenPlatformRequestContext,
    command: VerifyCredentialSecretCommand,
  ): Promise<boolean> {
    const tenantId = normalizeTenantKey(command?.tenantId);
    const credentialId = normalizeResourceId(
      command?.credentialId,
      "credential",
    );
    await this.authorize(context, tenantId, "read", "credential", credentialId);
    if (
      typeof command?.secret !== "string" ||
      command.secret.length < 1 ||
      command.secret.length > 4096 ||
      /[\u0000\u0001-\u0008\u000b\u000c\u000e-\u001f\u007f]/u.test(
        command.secret,
      )
    ) {
      throw validationError("Credential secret is invalid");
    }
    let credential: CredentialRecord;
    try {
      credential = await this.requireUsableCredential(tenantId, credentialId);
    } catch (error) {
      if (isOpenPlatformDomainError(error)) return false;
      throw error;
    }
    const actual = Buffer.from(digestSecret(command.secret), "utf8");
    const expected = Buffer.from(credential.secret.digest, "utf8");
    return actual.length === expected.length && timingSafeEqual(actual, expected);
  }

  async createSubscription(
    context: OpenPlatformRequestContext,
    command: CreateSubscriptionCommand,
  ): Promise<Subscription> {
    const normalized = normalizeCreateSubscriptionCommand(command);
    const actor = await this.authorize(
      context,
      normalized.tenantId,
      "create",
      "subscription",
    );
    const execution = await this.execute(
      actor,
      normalized.idempotencyKey,
      "subscription.create",
      normalized,
      async () => {
        await this.requirePublishedApplication(
          actor.tenantId,
          normalized.applicationId,
        );
        const product = await this.requirePublished(
          this.repositories.apiProducts,
          actor.tenantId,
          normalized.productId,
          "apiProduct",
        );
        assertScopesAllowed(normalized.scopes, product.scopes);
        if (normalized.apiVersionId !== undefined) {
          const version = await this.requirePublished(
            this.repositories.apiVersions,
            actor.tenantId,
            normalized.apiVersionId,
            "apiVersion",
          );
          if (version.productId !== product.id) {
            throw resourceNotFound("apiVersion");
          }
          assertScopesAllowed(normalized.scopes, version.scopes);
        }
        const timestamp = this.timestamp();
        return this.repositories.subscriptions.create({
          id: this.newId("subscription"),
          tenantId: actor.tenantId,
          kind: "subscription",
          applicationId: normalized.applicationId,
          productId: product.id,
          ...(normalized.apiVersionId === undefined
            ? {}
            : { apiVersionId: normalized.apiVersionId }),
          name: normalized.name,
          scopes: normalized.scopes,
          status: "draft",
          version: 1,
          createdAt: timestamp,
          updatedAt: timestamp,
        });
      },
      undefined,
      (created) =>
        createdDomainEvent("subscription.created", created, {
          applicationId: created.applicationId,
          productId: created.productId,
          ...(created.apiVersionId === undefined
            ? {}
            : { apiVersionId: created.apiVersionId }),
        }),
    );
    return execution.result;
  }

  async getSubscription(
    context: OpenPlatformRequestContext,
    query: SubscriptionQuery & { id: string },
  ): Promise<Subscription> {
    const normalized = normalizeSubscriptionQuery(query);
    const actor = await this.authorize(
      context,
      normalized.tenantId,
      "read",
      "subscription",
      normalized.id,
    );
    const record = await this.requireResource(
      this.repositories.subscriptions,
      actor.tenantId,
      normalized.id ?? "",
      "subscription",
    );
    if (
      (normalized.applicationId !== undefined &&
        record.applicationId !== normalized.applicationId) ||
      (normalized.productId !== undefined &&
        record.productId !== normalized.productId)
    ) {
      throw resourceNotFound("subscription");
    }
    return record;
  }

  async listSubscriptions(
    context: OpenPlatformRequestContext,
    query: SubscriptionQuery,
  ): Promise<Subscription[]> {
    const normalized = normalizeSubscriptionQuery(query);
    const actor = await this.authorize(
      context,
      normalized.tenantId,
      "read",
      "subscription",
      normalized.id,
    );
    const records = await this.repositories.subscriptions.list(actor.tenantId);
    return records.filter((record) =>
      (normalized.id === undefined || record.id === normalized.id) &&
      (normalized.applicationId === undefined ||
        record.applicationId === normalized.applicationId) &&
      (normalized.productId === undefined ||
        record.productId === normalized.productId)
    );
  }

  async getLifecycleRecord(
    context: OpenPlatformRequestContext,
    resource: OpenPlatformLifecycleResourceKind,
    query: { tenantId: string; id: string },
  ): Promise<OpenPlatformLifecycleRecord> {
    const normalizedResource = normalizeLifecycleResource(resource);
    const tenantId = normalizeTenantKey(query?.tenantId);
    const id = normalizeResourceId(query?.id, normalizedResource);
    const actor = await this.authorize(
      context,
      tenantId,
      "read",
      normalizedResource,
      id,
    );
    return this.getLifecycle(normalizedResource, actor.tenantId, id);
  }

  async listLifecycleRecords(
    context: OpenPlatformRequestContext,
    resource: OpenPlatformLifecycleResourceKind,
    query: { tenantId: string },
  ): Promise<OpenPlatformLifecycleRecord[]> {
    const normalizedResource = normalizeLifecycleResource(resource);
    const tenantId = normalizeTenantKey(query?.tenantId);
    const actor = await this.authorize(
      context,
      tenantId,
      "read",
      normalizedResource,
    );
    return this.listLifecycle(normalizedResource, actor.tenantId);
  }

  async transitionLifecycle(
    context: OpenPlatformRequestContext,
    command: LifecycleTransitionCommand,
  ): Promise<OpenPlatformLifecycleRecord> {
    const normalized = normalizeLifecycleTransitionCommand(command);
    const action = openPlatformLifecycleAuthorizationActionForStatus(
      normalized.targetStatus,
    );
    if (action === undefined) {
      throw validationError("Lifecycle target status is invalid", {
        field: "targetStatus",
      });
    }
    return this.applyLifecycleTransition(context, normalized, action);
  }

  async publish(
    context: OpenPlatformRequestContext,
    command: LifecycleCommand,
  ): Promise<OpenPlatformLifecycleRecord> {
    const normalized = normalizeLifecycleCommand(command);
    return this.applyLifecycleTransition(context, {
      ...normalized,
      targetStatus: "published",
    }, "publish");
  }

  async deactivate(
    context: OpenPlatformRequestContext,
    command: LifecycleCommand,
  ): Promise<OpenPlatformLifecycleRecord> {
    const normalized = normalizeLifecycleCommand(command);
    return this.applyLifecycleTransition(context, {
      ...normalized,
      targetStatus: "disabled",
    }, "disable");
  }

  async archive(
    context: OpenPlatformRequestContext,
    command: LifecycleCommand,
  ): Promise<OpenPlatformLifecycleRecord> {
    const normalized = normalizeLifecycleCommand(command);
    return this.applyLifecycleTransition(context, {
      ...normalized,
      targetStatus: "archived",
    }, "archive");
  }

  async submitReview(
    context: OpenPlatformRequestContext,
    command: LifecycleCommand,
  ): Promise<OpenPlatformLifecycleRecord> {
    const normalized = normalizeLifecycleCommand(command);
    return this.applyLifecycleTransition(context, {
      ...normalized,
      targetStatus: "published",
    }, "submitReview");
  }

  async grantScopes(
    context: OpenPlatformRequestContext,
    command: GrantScopesCommand,
  ): Promise<ScopeGrant> {
    const normalized = normalizeGrantScopesCommand(command);
    const actor = await this.authorize(
      context,
      normalized.tenantId,
      "grant",
      "scopeGrant",
      normalized.credentialId,
    );
    let granted = false;
    const execution = await this.execute(
      actor,
      normalized.idempotencyKey,
      "scopeGrant.grant",
      normalized,
      async () => {
        const credential = await this.requireUsableCredential(
          actor.tenantId,
          normalized.credentialId,
        );
        const product = await this.requirePublished(
          this.repositories.apiProducts,
          actor.tenantId,
          normalized.productId,
          "apiProduct",
        );
        let version: ApiVersion | undefined;
        if (normalized.apiVersionId !== undefined) {
          version = await this.requirePublished(
            this.repositories.apiVersions,
            actor.tenantId,
            normalized.apiVersionId,
            "apiVersion",
          );
          if (version.productId !== product.id) {
            throw resourceNotFound("apiVersion");
          }
        }
        assertScopesAllowed(normalized.scopes, credential.scopes);
        assertScopesAllowed(normalized.scopes, product.scopes);
        if (version !== undefined) {
          assertScopesAllowed(normalized.scopes, version.scopes);
        }
        const existing = (await this.repositories.scopeGrants.list(
          actor.tenantId,
        )).filter((record) =>
          record.status === "active" &&
          record.credentialId === credential.id &&
          record.productId === product.id &&
          record.apiVersionId === normalized.apiVersionId
        );
        if (existing.length > 0) {
          if (
            existing.length === 1 &&
            sameScopes(existing[0].scopes, normalized.scopes)
          ) {
            return existing[0];
          }
          throw resourceConflict("Scope grant already exists for this target");
        }
        const timestamp = this.timestamp();
        const created = await this.repositories.scopeGrants.create({
          id: this.newId("scopeGrant"),
          tenantId: actor.tenantId,
          kind: "scopeGrant",
          credentialId: credential.id,
          applicationId: credential.applicationId,
          productId: product.id,
          ...(normalized.apiVersionId === undefined
            ? {}
            : { apiVersionId: normalized.apiVersionId }),
          scopes: normalized.scopes,
          status: "active",
          grantedAt: timestamp,
          version: 1,
          createdAt: timestamp,
          updatedAt: timestamp,
        });
        granted = true;
        return created;
      },
      undefined,
      (created) =>
        granted
          ? createdDomainEvent("scope_grant.created", created, {
              applicationId: created.applicationId,
              productId: created.productId,
              ...(created.apiVersionId === undefined
                ? {}
                : { apiVersionId: created.apiVersionId }),
            })
          : undefined,
    );
    return execution.result;
  }

  async revokeScopeGrant(
    context: OpenPlatformRequestContext,
    command: RevokeScopeGrantCommand,
  ): Promise<ScopeGrant> {
    const normalized = normalizeRevokeScopeGrantCommand(command);
    const actor = await this.authorize(
      context,
      normalized.tenantId,
      "revoke",
      "scopeGrant",
      normalized.scopeGrantId,
    );
    const execution = await this.execute(
      actor,
      normalized.idempotencyKey,
      "scopeGrant.revoke",
      normalized,
      async () => {
        const current = await this.requireResource(
          this.repositories.scopeGrants,
          actor.tenantId,
          normalized.scopeGrantId,
          "scopeGrant",
        );
        return this.repositories.scopeGrants.revoke(
          actor.tenantId,
          current.id,
          this.timestamp(),
        );
      },
      undefined,
      (revoked) => ({
        eventType: "scope_grant.status_changed",
        resourceType: "scopeGrant",
        resourceId: revoked.id,
        resourceVersion: revoked.version,
        resourceStatus: revoked.status,
        data: {
          action: "revoked",
          credentialId: revoked.credentialId,
          productId: revoked.productId,
          ...(revoked.apiVersionId === undefined
            ? {}
            : { apiVersionId: revoked.apiVersionId }),
        },
      }),
    );
    return execution.result;
  }

  async authorizeScopes(
    context: OpenPlatformRequestContext,
    command: AuthorizeScopesCommand,
  ): Promise<ScopeAuthorizationResult> {
    const normalized = normalizeAuthorizeScopesCommand(command);
    const actor = await this.authorize(
      context,
      normalized.tenantId,
      "authorize",
      "scopeGrant",
      normalized.credentialId,
    );
    const credential = await this.requireUsableCredential(
      actor.tenantId,
      normalized.credentialId,
    );
    const product = await this.requirePublished(
      this.repositories.apiProducts,
      actor.tenantId,
      normalized.productId,
      "apiProduct",
    );
    let version: ApiVersion | undefined;
    if (normalized.apiVersionId !== undefined) {
      version = await this.requirePublished(
        this.repositories.apiVersions,
        actor.tenantId,
        normalized.apiVersionId,
        "apiVersion",
      );
      if (version.productId !== product.id) {
        throw resourceNotFound("apiVersion");
      }
    }
    assertScopesAllowed(normalized.scopes, credential.scopes);
    assertScopesAllowed(normalized.scopes, product.scopes);
    if (version !== undefined) {
      assertScopesAllowed(normalized.scopes, version.scopes);
    }
    const grant = await this.requireEffectiveGrant(
      actor.tenantId,
      credential,
      product,
      version,
      normalized.scopes,
    );
    return {
      valid: true,
      scopeGrantId: grant.id,
      credentialId: credential.id,
      productId: product.id,
      ...(version === undefined ? {} : { apiVersionId: version.id }),
      scopes: [...normalized.scopes],
    };
  }

  async getScopeGrant(
    context: OpenPlatformRequestContext,
    query: ScopeGrantQuery & { id: string },
  ): Promise<ScopeGrant> {
    const normalized = normalizeScopeGrantQuery(query);
    const actor = await this.authorize(
      context,
      normalized.tenantId,
      "read",
      "scopeGrant",
      normalized.id,
    );
    const record = await this.requireResource(
      this.repositories.scopeGrants,
      actor.tenantId,
      normalized.id ?? "",
      "scopeGrant",
    );
    if (
      (normalized.credentialId !== undefined &&
        record.credentialId !== normalized.credentialId) ||
      (normalized.productId !== undefined &&
        record.productId !== normalized.productId) ||
      (normalized.apiVersionId !== undefined &&
        record.apiVersionId !== normalized.apiVersionId)
    ) {
      throw resourceNotFound("scopeGrant");
    }
    return record;
  }

  async listScopeGrants(
    context: OpenPlatformRequestContext,
    query: ScopeGrantQuery,
  ): Promise<ScopeGrant[]> {
    const normalized = normalizeScopeGrantQuery(query);
    const actor = await this.authorize(
      context,
      normalized.tenantId,
      "read",
      "scopeGrant",
      normalized.id,
    );
    const records = await this.repositories.scopeGrants.list(actor.tenantId);
    return records.filter((record) =>
      (normalized.id === undefined || record.id === normalized.id) &&
      (normalized.credentialId === undefined ||
        record.credentialId === normalized.credentialId) &&
      (normalized.productId === undefined ||
        record.productId === normalized.productId) &&
      (normalized.apiVersionId === undefined ||
        record.apiVersionId === normalized.apiVersionId)
    );
  }

  async recordUsage(
    context: OpenPlatformRequestContext,
    command: RecordUsageCommand,
  ): Promise<UsageRecord> {
    const normalized = normalizeRecordUsageCommand(command);
    const actor = await this.authorize(
      context,
      normalized.tenantId,
      "record",
      "usage",
      normalized.subscriptionId,
    );
    const execution = await this.execute(
      actor,
      normalized.idempotencyKey,
      "usage.record",
      normalized,
      async () => {
        const subscription = await this.requirePublished(
          this.repositories.subscriptions,
          actor.tenantId,
          normalized.subscriptionId,
          "subscription",
        );
        await this.requirePublishedApplication(
          actor.tenantId,
          subscription.applicationId,
        );
        const product = await this.requirePublished(
          this.repositories.apiProducts,
          actor.tenantId,
          subscription.productId,
          "apiProduct",
        );
        let version: ApiVersion | undefined;
        if (subscription.apiVersionId !== undefined) {
          version = await this.requirePublished(
            this.repositories.apiVersions,
            actor.tenantId,
            subscription.apiVersionId,
            "apiVersion",
          );
          if (version.productId !== product.id) {
            throw resourceNotFound("apiVersion");
          }
        }
        if (normalized.credentialId !== undefined) {
          const credential = await this.requireUsableCredential(
            actor.tenantId,
            normalized.credentialId,
          );
          if (credential.applicationId !== subscription.applicationId) {
            throw usageRejected("Credential is not bound to the subscription");
          }
          await this.requireEffectiveGrant(
            actor.tenantId,
            credential,
            product,
            version,
            subscription.scopes,
          );
        }
        const timestamp = this.timestamp();
        const occurredAt = normalized.occurredAt ?? timestamp;
        if (Date.parse(occurredAt) > Date.parse(timestamp)) {
          throw usageRejected("Usage timestamp cannot be in the future");
        }
        return this.repositories.usage.append({
          id: this.newId("usage"),
          tenantId: actor.tenantId,
          kind: "usage",
          subscriptionId: subscription.id,
          ...(normalized.credentialId === undefined
            ? {}
            : { credentialId: normalized.credentialId }),
          productId: subscription.productId,
          ...(version === undefined ? {} : { apiVersionId: version.id }),
          metric: normalized.metric,
          quantity: normalized.quantity,
          occurredAt,
          idempotencyKey: normalized.idempotencyKey,
          version: 1,
          createdAt: timestamp,
          updatedAt: timestamp,
        });
      },
      undefined,
      (recorded) => {
        const threshold = this.usageEventThresholds.get(recorded.metric);
        if (threshold === undefined || recorded.quantity < threshold) return undefined;
        return {
          eventType: "usage.threshold_reached" as const,
          resourceType: "subscription" as const,
          resourceId: recorded.subscriptionId,
          resourceVersion: recorded.version,
          data: {
            action: "threshold_reached" as const,
            metric: recorded.metric,
            quantity: recorded.quantity,
            threshold,
            productId: recorded.productId,
            ...(recorded.apiVersionId === undefined
              ? {}
              : { apiVersionId: recorded.apiVersionId }),
          },
        };
      },
    );
    return execution.result;
  }

  async listUsage(
    context: OpenPlatformRequestContext,
    query: UsageQuery,
  ): Promise<UsageRecord[]> {
    const normalized = normalizeUsageQuery(query);
    const actor = await this.authorize(
      context,
      normalized.tenantId,
      "read",
      "usage",
      normalized.subscriptionId,
    );
    if (
      normalized.from !== undefined &&
      normalized.to !== undefined &&
      Date.parse(normalized.from) > Date.parse(normalized.to)
    ) {
      throw validationError("Usage query date range is invalid");
    }
    const records = await this.repositories.usage.list(actor.tenantId);
    return records
      .filter((record) =>
        (normalized.subscriptionId === undefined ||
          record.subscriptionId === normalized.subscriptionId) &&
        (normalized.credentialId === undefined ||
          record.credentialId === normalized.credentialId) &&
        (normalized.from === undefined ||
          Date.parse(record.occurredAt) >= Date.parse(normalized.from)) &&
        (normalized.to === undefined ||
          Date.parse(record.occurredAt) <= Date.parse(normalized.to))
      )
      .sort((left, right) => {
        const occurred = left.occurredAt.localeCompare(right.occurredAt);
        return occurred === 0 ? left.id.localeCompare(right.id) : occurred;
      });
  }

  private async authorize(
    contextValue: unknown,
    requestedTenantId: string,
    action: OpenPlatformAuthorizationAction,
    resource: OpenPlatformEntityKind,
    resourceId?: string,
  ): Promise<OpenPlatformRequestContext> {
    if (!isOpenPlatformRequestContext(contextValue)) {
      throw authenticationRequired();
    }
    const context = contextValue;
    if (context.tenantId !== requestedTenantId) {
      if (isWriteAuditAction(action)) await this.appendDeniedAudit(context, `${resource}.${action}`, "unknown");
      throw tenantMismatch();
    }
    if (!this.contextAssuranceAllowed(context.assurance)) {
      throw authenticationRequired();
    }
    if (!(await this.isOperationalReady())) {
      throw storageUnavailable();
    }
    let allowed = false;
    try {
      allowed = await this.authorization.authorize({
        context,
        tenantId: context.tenantId,
        action,
        resource,
        ...(resourceId === undefined ? {} : { resourceId }),
      });
    } catch {
      if (isWriteAuditAction(action)) await this.appendDeniedAudit(context, `${resource}.${action}`, resourceId ?? "unknown");
      throw forbidden();
    }
    if (allowed !== true) {
      if (isWriteAuditAction(action)) await this.appendDeniedAudit(context, `${resource}.${action}`, resourceId ?? "unknown");
      throw forbidden();
    }
    return context;
  }

  private contextAssuranceAllowed(
    assurance: "development" | "authenticated",
  ): boolean {
    return this.requiredContextAssurance === "development"
      ? assurance === "development" || assurance === "authenticated"
      : assurance === "authenticated";
  }

  private async isOperationalReady(): Promise<boolean> {
    return (await this.isReady()).ready;
  }

  private async eventsOperationalReady(): Promise<boolean> {
    if (!this.eventsEnabled) return true;
    const outboxReady = this.outbox.readiness === undefined
      ? this.outbox.productionReady === true
      : await safelyReady(this.outbox.readiness);
    const publisherReady = this.eventPublisher.readiness === undefined
      ? true
      : await safelyReady(this.eventPublisher.readiness);
    return outboxReady && publisherReady;
  }

  private async execute<T>(
    context: OpenPlatformRequestContext,
    idempotencyKey: string,
    operation: string,
    request: unknown,
    action: () => Promise<T>,
    projectResponse?: (result: T) => unknown,
    event?: OpenPlatformDomainEventFactory<T>,
  ): Promise<IdempotencyExecution<T>> {
    const now = this.timestamp();
    const nowTimestamp = Date.parse(now);
    const requestHash = hashOpenPlatformIdempotencyRequest(request);
    const scope = {
      tenantId: context.tenantId,
      actorId: context.actorId,
      operation,
      key: idempotencyKey,
    };
    const leaseToken = randomUUID();
    const acquired = await this.repositories.idempotency.acquire({
      scope,
      requestHash,
      leaseToken,
      now,
      leaseExpiresAt: new Date(nowTimestamp + this.leaseMs).toISOString(),
      expiresAt: new Date(nowTimestamp + this.retentionMs).toISOString(),
    });
    if (acquired.state === "conflict") {
      await this.appendFailureAudit(context, operation, request, idempotencyKey, idempotencyKeyReused());
      throw idempotencyKeyReused();
    }
    if (acquired.state === "inProgress") {
      await this.appendFailureAudit(context, operation, request, idempotencyKey, idempotencyRequestInProgress());
      throw idempotencyRequestInProgress();
    }
    if (acquired.state === "replay") {
      const result = structuredClone(acquired.response) as T;
      await this.appendSuccessAudit(context, operation, request, idempotencyKey, result, true);
      if (event !== undefined) {
        await this.publishDomainEvent(context, operation, result, event, idempotencyKey);
      }
      return { replayed: true, result };
    }
    let result: T;
    try {
      result = await action();
    } catch (error) {
      await this.appendFailureAudit(context, operation, request, idempotencyKey, error);
      await this.releaseLease(scope, requestHash, leaseToken);
      throw error;
    }
    try {
      const response = structuredClone(
        projectResponse === undefined ? result : projectResponse(result),
      );
      const completed = await this.repositories.idempotency.complete({
        scope,
        requestHash,
        leaseToken,
        now: this.timestamp(),
        expiresAt: new Date(
          Date.parse(this.timestamp()) + this.retentionMs,
        ).toISOString(),
        response,
      });
      if (!completed) {
        throw resourceConflict("Idempotency lease was lost");
      }
    } catch (error) {
      await this.appendFailureAudit(context, operation, request, idempotencyKey, error);
      await this.releaseLease(scope, requestHash, leaseToken);
      throw error;
    }
    await this.appendSuccessAudit(context, operation, request, idempotencyKey, result, false);
    if (event !== undefined) {
      await this.publishDomainEvent(context, operation, result, event, idempotencyKey);
    }
    return { replayed: false, result };
  }

  private async publishDomainEvent<T>(
    context: OpenPlatformRequestContext,
    operation: string,
    result: T,
    factory: OpenPlatformDomainEventFactory<T>,
    idempotencyKey: string,
  ): Promise<OpenPlatformOutboxRecord | undefined> {
    if (!this.eventsEnabled) return undefined;
    let descriptor: OpenPlatformDomainEventDescriptor | undefined;
    try {
      descriptor = factory(result);
    } catch {
      return undefined;
    }
    if (descriptor === undefined) return undefined;
    try {
      const record = await this.eventPublisher.record({
        eventId: domainEventId(context, operation, idempotencyKey),
        tenantId: context.tenantId,
        eventType: descriptor.eventType,
        resourceType: descriptor.resourceType,
        resourceId: descriptor.resourceId,
        ...(descriptor.resourceVersion === undefined
          ? {}
          : { resourceVersion: descriptor.resourceVersion }),
        ...(descriptor.resourceStatus === undefined
          ? {}
          : { resourceStatus: descriptor.resourceStatus }),
        actorId: context.actorId,
        requestId: context.requestId,
        occurredAt: this.timestamp(),
        ...(descriptor.data === undefined ? {} : { data: descriptor.data }),
      });
      await this.eventPublisher.publish(record);
      return record;
    } catch (error) {
      if (this.mode === "production" && this.eventsEnabled) {
        await this.appendFailureAudit(context, `${operation}.event`, undefined, undefined, error);
        throw storageUnavailable();
      }
      return undefined;
    }
  }

  private async releaseLease(
    scope: { tenantId: string; actorId: string; operation: string; key: string },
    requestHash: string,
    leaseToken: string,
  ): Promise<void> {
    try {
      await this.repositories.idempotency.release({
        scope,
        requestHash,
        leaseToken,
        now: this.timestamp(),
      });
    } catch {
      return;
    }
  }

  private async appendSuccessAudit(
    context: OpenPlatformRequestContext,
    operation: string,
    request: unknown,
    idempotencyKey: string,
    result: unknown,
    replayed: boolean,
  ): Promise<void> {
    try {
      await this.audit.append({
        ...this.auditInput(context, operation, request, idempotencyKey, result),
        outcome: "success",
        metadata: { replayed },
      });
    } catch {
      throw storageUnavailable();
    }
  }

  private async appendFailureAudit(
    context: OpenPlatformRequestContext,
    operation: string,
    request: unknown,
    idempotencyKey: string | undefined,
    error: unknown,
  ): Promise<void> {
    try {
      await this.audit.append({
        ...this.auditInput(context, operation, request, idempotencyKey ?? "", undefined),
        outcome: isDeniedAuditError(error) ? "denied" : "failure",
        metadata: { errorCode: auditErrorCode(error) },
      });
    } catch {
      return;
    }
  }

  private async appendDeniedAudit(
    context: OpenPlatformRequestContext,
    operation: string,
    targetId: string,
  ): Promise<void> {
    try {
      await this.audit.append({
        tenantId: context.tenantId,
        action: operation,
        outcome: "denied",
        actor: { type: "user", id: context.actorId },
        target: auditTargetForOperation(operation, targetId),
        requestId: context.requestId,
        metadata: { source: "authorization" },
        source: "open-platform",
      });
    } catch {
      return;
    }
  }

  private auditInput(
    context: OpenPlatformRequestContext,
    operation: string,
    request: unknown,
    idempotencyKey: string,
    result: unknown,
  ): OpenPlatformAuditEventInput {
    const target = auditTargetForResult(operation, request, result);
    return {
      tenantId: context.tenantId,
      action: operation,
      outcome: "success",
      actor: { type: "user", id: context.actorId },
      target,
      requestId: context.requestId,
      metadata: { operation, idempotencyKey: auditHash(idempotencyKey) },
      source: "open-platform",
    };
  }

  private timestamp(): string {
    return normalizeTimestamp(this.clock());
  }

  private newId(kind: OpenPlatformEntityKind): string {
    return normalizeResourceId(this.idGenerator(kind), kind);
  }

  private async requireTenantByKey(tenantId: string): Promise<Tenant> {
    const tenant = await this.repositories.tenants.getByTenantId(tenantId);
    if (tenant === undefined) throw resourceNotFound("tenant");
    return tenant;
  }

  private async requirePublishedTenant(tenantId: string): Promise<Tenant> {
    const tenant = await this.requireTenantByKey(tenantId);
    if (tenant.status !== "published") throw resourceUnavailable("tenant");
    return tenant;
  }

  private async requirePublishedApplication(
    tenantId: string,
    applicationId: string,
  ): Promise<Application> {
    await this.requirePublishedTenant(tenantId);
    return this.requirePublished(
      this.repositories.applications,
      tenantId,
      applicationId,
      "application",
    );
  }

  private async requirePublishedEnvironment(
    tenantId: string,
    applicationId: string,
    environmentId: string,
  ): Promise<ApplicationEnvironment> {
    const environment = await this.requirePublished(
      this.repositories.applicationEnvironments,
      tenantId,
      environmentId,
      "applicationEnvironment",
    );
    if (environment.applicationId !== applicationId) {
      throw resourceNotFound("applicationEnvironment");
    }
    return environment;
  }

  private async requirePublished<T extends OpenPlatformLifecycleRecord>(
    repository: TenantScopedRepository<T>,
    tenantId: string,
    id: string,
    kind: string,
  ): Promise<T> {
    const record = await this.requireResource(
      repository,
      tenantId,
      id,
      kind,
    );
    if (record.status !== "published") throw resourceUnavailable(kind);
    return record;
  }

  private async requireResource<T extends OpenPlatformRecord>(
    repository: TenantScopedRepository<T>,
    tenantId: string,
    id: string,
    kind: string,
  ): Promise<T> {
    const record = await repository.get(tenantId, id);
    if (record === undefined) throw resourceNotFound(kind);
    return record;
  }

  private async requireCredential(
    tenantId: string,
    credentialId: string,
  ): Promise<CredentialRecord> {
    return this.requireResource(
      this.repositories.credentials,
      tenantId,
      credentialId,
      "credential",
    );
  }

  private async requireUsableCredential(
    tenantId: string,
    credentialId: string,
  ): Promise<CredentialRecord> {
    const credential = await this.requireCredential(tenantId, credentialId);
    const application = await this.requirePublishedApplication(
      tenantId,
      credential.applicationId,
    );
    if (credential.environmentId !== undefined) {
      await this.requirePublishedEnvironment(
        tenantId,
        application.id,
        credential.environmentId,
      );
    }
    if (
      credential.status !== "active" ||
      (credential.expiresAt !== undefined &&
        Date.parse(credential.expiresAt) <= Date.parse(this.timestamp()))
    ) {
      throw credentialUnavailable();
    }
    return credential;
  }

  private async requireEffectiveGrant(
    tenantId: string,
    credential: CredentialRecord,
    product: ApiProduct,
    version: ApiVersion | undefined,
    requestedScopes: readonly string[],
  ): Promise<ScopeGrant> {
    const grants = (await this.repositories.scopeGrants.list(tenantId)).filter(
      (grant) =>
        grant.status === "active" &&
        grant.revokedAt === undefined &&
        grant.credentialId === credential.id &&
        grant.productId === product.id &&
        grant.apiVersionId === version?.id &&
        grant.applicationId === credential.applicationId &&
        requestedScopes.every((scope) => grant.scopes.includes(scope)),
    );
    if (grants.length !== 1) throw scopeGrantInvalid();
    return grants[0];
  }

  private async revokeStoredSecret(
    credential: CredentialRecord,
    reason: "rotation" | "revocation",
  ): Promise<void> {
    const request: CredentialSecretRevokeInput = {
      tenantId: credential.tenantId,
      applicationId: credential.applicationId,
      credentialId: credential.id,
      digest: credential.secret.digest,
      ...(credential.secret.reference === undefined
        ? {}
        : { reference: credential.secret.reference }),
      reason,
    };
    for (let attempt = 0; attempt < 2; attempt += 1) {
      try {
        await this.runSecretLifecycle(() =>
          this.secretProvider.revoke(request)
        );
        return;
      } catch {
        if (attempt === 1) throw secretIssuanceFailed();
      }
    }
    throw secretIssuanceFailed();
  }

  private async compensateSecret(
    request: Omit<CredentialSecretCompensationInput, "reason">,
    reason: "issuePersistenceFailed" |
      "rotationPersistenceFailed" |
      "rotationRevokeFailed",
  ): Promise<void> {
    const compensation = { ...request, reason };
    for (let attempt = 0; attempt < 2; attempt += 1) {
      try {
        await this.runSecretLifecycle(() =>
          this.secretProvider.compensate(compensation)
        );
        return;
      } catch {
        if (attempt === 1) throw secretIssuanceFailed();
      }
    }
    throw secretIssuanceFailed();
  }

  private async runSecretLifecycle(
    action: () => void | Promise<void>,
  ): Promise<void> {
    try {
      const result = await action();
      if (result !== undefined) throw secretIssuanceFailed();
    } catch {
      throw secretIssuanceFailed();
    }
  }

  private async generateSecret(input: {
    tenantId: string;
    applicationId: string;
    credentialId: string;
    reason: "issue" | "rotate";
  }): Promise<CredentialSecretMaterial> {
    let material: CredentialSecretMaterial;
    try {
      material = await this.secretProvider.issue(input);
    } catch {
      throw secretIssuanceFailed();
    }
    if (
      material === null ||
      typeof material !== "object" ||
      typeof material.secret !== "string" ||
      material.secret.length < 32 ||
      material.secret.length > 4096 ||
      /[\u0000\u0001-\u0008\u000b\u000c\u000e-\u001f\u007f]/u.test(
        material.secret,
      )
    ) {
      throw secretIssuanceFailed();
    }
    let reference: string | undefined;
    if (material.reference !== undefined) {
      try {
        reference = normalizeOpaqueSecretReference(
          material.reference,
          material.secret,
        );
      } catch {
        await this.compensateSecret({
          tenantId: input.tenantId,
          applicationId: input.applicationId,
          credentialId: input.credentialId,
          digest: digestSecret(material.secret),
          reference: typeof material.reference === "string"
            ? material.reference
            : undefined,
        }, input.reason === "issue"
          ? "issuePersistenceFailed"
          : "rotationPersistenceFailed");
        throw secretIssuanceFailed();
      }
    }
    return {
      secret: material.secret,
      ...(reference === undefined ? {} : { reference }),
    };
  }

  private async applyLifecycleTransition(
    context: OpenPlatformRequestContext,
    normalized: NormalizedLifecycleTransitionCommand,
    action: OpenPlatformLifecycleAuthorizationAction,
  ): Promise<OpenPlatformLifecycleRecord> {
    const actor = await this.authorize(
      context,
      normalized.tenantId,
      action,
      normalized.resource,
      normalized.id,
    );
    let fromStatus: OpenPlatformLifecycleStatus | undefined;
    const execution = await this.execute(
      actor,
      normalized.idempotencyKey,
      "lifecycle.transition",
      normalized,
      async () => {
        const current = await this.getLifecycle(
          normalized.resource,
          actor.tenantId,
          normalized.id,
        );
        if (current.kind !== normalized.resource) {
          throw resourceNotFound(normalized.resource);
        }
        fromStatus = current.status;
        assertLifecycleTransition(current.status, normalized.targetStatus);
        const timestamp = this.timestamp();
        const updated = {
          ...current,
          status: normalized.targetStatus,
          version: current.version + 1,
          updatedAt: timestamp,
          ...(normalized.targetStatus === "archived"
            ? { archivedAt: timestamp }
            : {}),
        } as OpenPlatformLifecycleRecord;
        return this.saveLifecycle(updated);
      },
      undefined,
      (updated) =>
        lifecycleDomainEvent(
          updated,
          normalized.resource,
          normalized.targetStatus,
          action,
          fromStatus,
        ),
    );
    return execution.result;
  }

  private async getLifecycle(
    resource: OpenPlatformLifecycleResourceKind,
    tenantId: string,
    id: string,
  ): Promise<OpenPlatformLifecycleRecord> {
    switch (resource) {
      case "tenant":
        return this.requireResource(
          this.repositories.tenants,
          tenantId,
          id,
          "tenant",
        );
      case "developerOrganization":
        return this.requireResource(
          this.repositories.developerOrganizations,
          tenantId,
          id,
          "developerOrganization",
        );
      case "application":
        return this.requireResource(
          this.repositories.applications,
          tenantId,
          id,
          "application",
        );
      case "applicationEnvironment":
        return this.requireResource(
          this.repositories.applicationEnvironments,
          tenantId,
          id,
          "applicationEnvironment",
        );
      case "apiProduct":
        return this.requireResource(
          this.repositories.apiProducts,
          tenantId,
          id,
          "apiProduct",
        );
      case "apiVersion":
        return this.requireResource(
          this.repositories.apiVersions,
          tenantId,
          id,
          "apiVersion",
        );
      case "subscription":
        return this.requireResource(
          this.repositories.subscriptions,
          tenantId,
          id,
          "subscription",
        );
    }
  }

  private async listLifecycle(
    resource: OpenPlatformLifecycleResourceKind,
    tenantId: string,
  ): Promise<OpenPlatformLifecycleRecord[]> {
    switch (resource) {
      case "tenant":
        return this.repositories.tenants.list(tenantId);
      case "developerOrganization":
        return this.repositories.developerOrganizations.list(tenantId);
      case "application":
        return this.repositories.applications.list(tenantId);
      case "applicationEnvironment":
        return this.repositories.applicationEnvironments.list(tenantId);
      case "apiProduct":
        return this.repositories.apiProducts.list(tenantId);
      case "apiVersion":
        return this.repositories.apiVersions.list(tenantId);
      case "subscription":
        return this.repositories.subscriptions.list(tenantId);
    }
  }

  private async saveLifecycle(
    record: OpenPlatformLifecycleRecord,
  ): Promise<OpenPlatformLifecycleRecord> {
    switch (record.kind) {
      case "tenant":
        return this.repositories.tenants.save(record);
      case "developerOrganization":
        return this.repositories.developerOrganizations.save(record);
      case "application":
        return this.repositories.applications.save(record);
      case "applicationEnvironment":
        return this.repositories.applicationEnvironments.save(record);
      case "apiProduct":
        return this.repositories.apiProducts.save(record);
      case "apiVersion":
        return this.repositories.apiVersions.save(record);
      case "subscription":
        return this.repositories.subscriptions.save(record);
    }
  }
}

export function createOpenPlatformService(
  options: OpenPlatformServiceOptions,
): OpenPlatformService {
  return new OpenPlatformService(options);
}

export function createOpenPlatformId(
  kind: OpenPlatformEntityKind,
): string {
  const prefixes: Record<OpenPlatformEntityKind, string> = {
    tenant: "tenant",
    developerOrganization: "org",
    application: "app",
    applicationEnvironment: "env",
    apiProduct: "product",
    apiVersion: "apiver",
    subscription: "subscription",
    credential: "credential",
    scopeGrant: "grant",
    usage: "usage",
    webhook: "webhook",
    auditEvent: "audit",
  };
  return `${prefixes[kind]}_${randomUUID()}`;
}

export function createRandomCredentialSecretProvider(): CredentialSecretProvider {
  return Object.freeze({
    readiness: Object.freeze({
      storage: "memory" as const,
      distributed: false,
      ready: () => true,
    }),
    issue: () => ({ secret: randomBytes(32).toString("base64url") }),
    revoke: () => undefined,
    compensate: () => undefined,
  });
}

function normalizeOpaqueSecretReference(
  value: unknown,
  secret: string,
): string {
  if (typeof value !== "string") {
    throw secretIssuanceFailed();
  }
  const normalized = value.trim();
  if (
    normalized.length < 8 ||
    normalized.length > 2048 ||
    normalized !== value ||
    normalized === secret ||
    normalized.includes(secret) ||
    !/^[a-z][a-z0-9+.-]{1,31}:\/\/[A-Za-z0-9][A-Za-z0-9._~:/?+=%-]{0,2010}$/u.test(
      normalized,
    )
  ) {
    throw secretIssuanceFailed();
  }
  return normalized;
}

function digestSecret(secret: string): string {
  return `sha256:${createHash("sha256").update(secret, "utf8").digest("hex")}`;
}

function assertScopesAllowed(
  requested: readonly string[],
  allowed: readonly string[],
): void {
  if (requested.some((scope) => !allowed.includes(scope))) {
    throw scopeNotAllowed();
  }
}

function sameScopes(
  left: readonly string[],
  right: readonly string[],
): boolean {
  return left.length === right.length &&
    left.every((scope, index) => scope === right[index]);
}

function domainEventId(
  context: OpenPlatformRequestContext,
  operation: string,
  idempotencyKey: string,
): string {
  const digest = createHash("sha256")
    .update([context.tenantId, context.actorId, operation, idempotencyKey].join("\u0000"), "utf8")
    .digest("hex")
    .slice(0, 32);
  return `open_platform_event_${digest}`;
}

function lifecycleDomainEvent(
  record: OpenPlatformLifecycleRecord,
  resource: OpenPlatformLifecycleResourceKind,
  targetStatus: OpenPlatformLifecycleStatus,
  action: OpenPlatformLifecycleAuthorizationAction,
  fromStatus: OpenPlatformLifecycleStatus | undefined,
): OpenPlatformDomainEventDescriptor | undefined {
  const eventType = openPlatformDomainEventTypeForLifecycle(resource, targetStatus);
  if (eventType === undefined) return undefined;
  return {
    eventType,
    resourceType: resource,
    resourceId: record.id,
    resourceVersion: record.version,
    resourceStatus: record.status,
    data: {
      action: openPlatformDomainEventActionForStatus(targetStatus),
      trigger: action,
      ...(fromStatus === undefined ? {} : { fromStatus }),
      toStatus: targetStatus,
    },
  };
}

function normalizeUsageEventThresholds(
  value: Readonly<Record<string, number>> | undefined,
): ReadonlyMap<string, number> {
  if (value === undefined) return new Map();
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw configurationError("Open platform usage event thresholds are invalid");
  }
  const thresholds = new Map<string, number>();
  for (const [metric, threshold] of Object.entries(value)) {
    if (
      typeof metric !== "string" ||
      metric.length < 1 ||
      metric.length > 128 ||
      !Number.isFinite(threshold) ||
      threshold <= 0
    ) {
      throw configurationError("Open platform usage event thresholds are invalid");
    }
    thresholds.set(metric, threshold);
  }
  return thresholds;
}

function auditTargetForResult(
  operation: string,
  request: unknown,
  result: unknown,
): { readonly type: OpenPlatformAuditResourceType; readonly id: string } {
  const requestRecord = isRecord(request) ? request : {};
  const resultRecord = isRecord(result) ? result : undefined;
  const resource = typeof requestRecord.resource === "string"
    ? requestRecord.resource
    : operation.split(".")[0] ?? "application";
  const id = typeof resultRecord?.id === "string"
    ? resultRecord.id
    : isRecord(resultRecord?.webhook) && typeof resultRecord.webhook.id === "string"
      ? resultRecord.webhook.id
      : typeof requestRecord.id === "string"
      ? requestRecord.id
        : typeof requestRecord.credentialId === "string"
          ? requestRecord.credentialId
          : typeof requestRecord.webhookId === "string"
            ? requestRecord.webhookId
            : typeof requestRecord.deliveryId === "string"
              ? requestRecord.deliveryId
              : typeof requestRecord.scopeGrantId === "string"
          ? requestRecord.scopeGrantId
          : typeof requestRecord.subscriptionId === "string"
            ? requestRecord.subscriptionId
            : "unknown";
  return auditTargetForOperation(`${resource}.${operation.split(".")[1] ?? "write"}`, id);
}

function auditTargetForOperation(
  operation: string,
  id: string,
): { readonly type: OpenPlatformAuditResourceType; readonly id: string } {
  const resource = operation.split(".")[0] ?? "application";
  const type: OpenPlatformAuditResourceType = resource === "developerOrganization"
    ? "developer_organization"
    : resource === "applicationEnvironment"
      ? "application_environment"
      : resource === "apiProduct"
        ? "api_product"
        : resource === "apiVersion"
          ? "api_version"
          : resource === "scopeGrant"
            ? "scope_grant"
            : resource === "auditEvent"
              ? "audit_event"
              : resource === "tenant" ||
                  resource === "application" ||
                  resource === "subscription" ||
                  resource === "credential" ||
                  resource === "usage" ||
                  resource === "webhook"
                ? resource
                : "application";
  return { type, id: normalizeAuditTargetId(id) };
}

function isWriteAuditAction(action: OpenPlatformAuthorizationAction): boolean {
  return action !== "read";
}

function isDeniedAuditError(error: unknown): boolean {
  return isOpenPlatformDomainError(error) &&
    (error.code === "OPEN_PLATFORM_FORBIDDEN" || error.code === "OPEN_PLATFORM_TENANT_MISMATCH");
}

function auditErrorCode(error: unknown): string {
  if (isOpenPlatformDomainError(error)) return error.code;
  return "INTERNAL_ERROR";
}

function auditHash(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function normalizeAuditTargetId(value: unknown): string {
  if (typeof value !== "string") return "unknown";
  const normalized = value.trim();
  return normalized.length < 1 || normalized.length > 256 || /[\u0000-\u001f\u007f]/u.test(normalized)
    ? "unknown"
    : normalized;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function isRuntimeMode(value: unknown): value is OpenPlatformRuntimeMode {
  return value === "development" || value === "test" || value === "production";
}

function isContextAssurance(
  value: unknown,
): value is "development" | "authenticated" {
  return value === "development" || value === "authenticated";
}

function isPersistentDistributed(
  value: { storage: string; distributed: boolean } | undefined,
): boolean {
  return value?.storage === "persistent" && value.distributed;
}

async function safelyReady(
  readiness: { ready(): unknown } | undefined,
): Promise<boolean> {
  if (readiness === undefined || typeof readiness.ready !== "function") {
    return false;
  }
  try {
    return (await readiness.ready()) === true;
  } catch {
    return false;
  }
}

function projectWebhookRecord(result: OpenPlatformWebhook): OpenPlatformWebhook {
  return {
    ...structuredClone(result),
    signingSecretReference: "",
  };
}

function projectWebhookSecretResult(
  result: OpenPlatformWebhookSecretResult,
): OpenPlatformWebhookSecretResult {
  return {
    webhook: projectWebhookRecord(result.webhook),
    secret: "",
    secretVersion: result.secretVersion,
    replayed: false,
  };
}

function projectCredentialIssuance(
  result: CredentialIssuanceResult,
): CredentialIssuanceResult {
  return {
    credential: cloneCredentialDto(result.credential),
    secret: undefined,
    replayed: false,
  };
}

function projectCredentialRotation(
  result: CredentialRotationResult,
): CredentialRotationResult {
  return {
    credential: cloneCredentialDto(result.credential),
    previousCredential: cloneCredentialDto(result.previousCredential),
    secret: undefined,
    replayed: false,
  };
}
