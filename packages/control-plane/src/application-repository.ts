import { createHash, randomBytes, randomUUID } from "node:crypto";
import type {
  ApplicationClientCreateRequest,
  ApplicationClientListQuery,
  ApplicationClientRotateSecretRequest,
  ApplicationClientStatus,
  ApplicationClientUpdateRequest,
  ApplicationCreateRequest,
  ApplicationExternalIdentityListQuery,
  ApplicationListQuery,
  ApplicationPlatformCreateRequest,
  ApplicationPlatformListQuery,
  ApplicationPlatformUpdateRequest,
  ApplicationStatus,
  ApplicationUpdateRequest,
  OpaqueClientSessionIssueResult,
  OpaqueClientSessionRecord,
  WebviewTicketConsumeRequest,
  WebviewTicketIssueResult,
  WebviewTicketRecord,
} from "@getbrick/idaas-contracts";
import { externalIdentityCanonicalKey } from "./identity.js";
import type { SecretBindingRepository } from "./secret-binding.js";
import { conflict, invalidRequest, notFound } from "./errors.js";
import { sanitizeAuditDetail } from "./dto.js";
import {
  parseApplicationClientIdentifier,
  parseApplicationClientListQuery,
  parseApplicationExternalIdentityListQuery,
  parseApplicationIdentifier,
  parseApplicationListQuery,
  parseApplicationPlatformIdentifier,
  parseApplicationPlatformListQuery,
} from "./application-validation.js";
import type {
  ApplicationAuditEvent,
  ApplicationClientRecord,
  ApplicationClientMutationRequest,
  ApplicationPlatformMutationRequest,
  ApplicationExternalIdentityRecord,
  ApplicationExternalIdentityUpsertInput,
  ApplicationPage,
  ApplicationPlatformRecord,
  ApplicationRecord,
  ApplicationRepository,
  ApplicationRepositoryOptions,
  ApplicationWriteContext,
  NormalizedApplicationExternalIdentityQuery,
  NormalizedApplicationClientQuery,
  NormalizedApplicationPlatformQuery,
  NormalizedApplicationQuery,
  OpaqueClientSessionIssueInput,
  OpaqueClientSessionRepository,
  WebviewTicketIssueInput,
  WebviewTicketRepository,
} from "./application-types.js";

const DEFAULT_TENANT_ID = "default";
const CURSOR_VERSION = 1;

interface CursorPayload {
  version: number;
  kind: string;
  offset: number;
  scope: string;
}

type AnyRecord = Record<string, unknown>;

export interface InMemoryApplicationRepositoryOptions extends ApplicationRepositoryOptions {
  secretBindings?: SecretBindingRepository;
}

export class InMemoryApplicationRepository implements ApplicationRepository {
  readonly tenantId: string;
  private readonly applications = new Map<string, ApplicationRecord>();
  private readonly platforms = new Map<string, ApplicationPlatformRecord>();
  private readonly clients = new Map<string, ApplicationClientRecord>();
  private readonly auditEvents = new Map<string, ApplicationAuditEvent>();
  private readonly externalIdentities = new Map<string, ApplicationExternalIdentityRecord>();
  private readonly clientSessions = new Map<string, OpaqueClientSessionRecord>();
  private readonly webviewTickets = new Map<string, WebviewTicketRecord>();
  private readonly clientSessionRepository?: OpaqueClientSessionRepository;
  private readonly webviewTicketRepository?: WebviewTicketRepository;
  private readonly secretBindings?: SecretBindingRepository;
  private auditSequence = 0;

  constructor(options: InMemoryApplicationRepositoryOptions | readonly ApplicationRecord[] = {}) {
    const normalized: InMemoryApplicationRepositoryOptions = Array.isArray(options)
      ? { applications: options as readonly ApplicationRecord[] }
      : options as InMemoryApplicationRepositoryOptions;
    this.tenantId = normalizeTenantId(normalized.tenantId);
    this.clientSessionRepository = normalized.clientSessionRepository;
    this.webviewTicketRepository = normalized.webviewTicketRepository;
    this.secretBindings = normalized.secretBindings;
    this.seedApplications(normalized.applications ?? []);
    this.seedPlatforms(normalized.platforms ?? normalized.applicationPlatforms ?? []);
    this.seedClients(normalized.clients ?? normalized.applicationClients ?? []);
    this.seedExternalIdentities(normalized.externalIdentities ?? normalized.applicationExternalIdentities ?? []);
    this.seedClientSessions(normalized.clientSessions ?? normalized.opaqueClientSessions ?? []);
    this.seedWebviewTickets(normalized.webviewTickets ?? []);
    this.seedAuditEvents(normalized.auditEvents ?? normalized.applicationAuditEvents ?? []);
  }

  async listApplications(
    query: ApplicationListQuery | NormalizedApplicationQuery = {},
  ): Promise<ApplicationPage<ApplicationRecord>> {
    return this.listApplicationsSync(query);
  }

  listApplicationsSync(
    query: ApplicationListQuery | NormalizedApplicationQuery = {},
  ): ApplicationPage<ApplicationRecord> {
    const normalized = parseApplicationListQuery(query);
    const filtered = [...this.applications.values()].filter((application) => {
      if (!this.belongs(application)) return false;
      if (normalized.status !== undefined && lifecycleStatusOf(application) !== normalized.status) return false;
      if (normalized.applicationType !== undefined && normalizeApplicationType(application.applicationType) !== normalized.applicationType) return false;
      if (normalized.readiness !== undefined && readinessForRecord(application) !== normalized.readiness) return false;
      if (normalized.effectiveStatus !== undefined && effectiveStatusForRecord(application) !== normalized.effectiveStatus) return false;
      const search = normalized.search ?? normalized.q;
      if (search !== undefined && !matchesApplication(application, search)) return false;
      return true;
    });
    return paginate("applications", normalized, filtered, applicationScope(normalized));
  }

  async getApplication(id: string): Promise<ApplicationRecord | undefined> {
    return this.getApplicationSync(id);
  }

  getApplicationSync(id: string): ApplicationRecord | undefined {
    const application = this.applications.get(id);
    if (!application || !this.belongs(application)) return undefined;
    return cloneRecord(application);
  }

  async createApplication(
    input: ApplicationCreateRequest & { id?: string },
    context: ApplicationWriteContext = {},
  ): Promise<ApplicationRecord> {
    const id = input.id ?? randomUUID();
    validateGeneratedId(id);
    if (this.findApplicationBySlug(input.slug, undefined)) {
      throw conflict("Application slug already exists");
    }
    const now = new Date();
    const application: ApplicationRecord = {
      id,
      tenantId: this.tenantId,
      name: input.name,
      slug: input.slug,
      applicationType: input.applicationType ?? "web",
      ...(input.description === undefined ? {} : { description: input.description }),
      status: "active",
      lifecycleStatus: "active",
      readiness: "ready",
      effectiveStatus: "active",
      version: 1,
      etag: `application:${id}:1`,
      createdAt: now,
      updatedAt: now,
      enabledAt: now,
    };
    return this.auditedMutation(
      this.auditEvent("application.created", id, context, { fields: ["name", "slug", "description"].filter((field) => input[field as keyof typeof input] !== undefined) }),
      () => {
        this.assertApplicationIdAvailable(id);
        this.applications.set(id, application);
      },
      () => this.applications.delete(id),
      application,
    );
  }

  async updateApplication(
    id: string,
    input: ApplicationUpdateRequest & { id?: string },
    context: ApplicationWriteContext = {},
  ): Promise<ApplicationRecord> {
    const identifier = parseApplicationIdentifier(id);
    const current = this.requireApplication(identifier);
    if (input.slug !== undefined && input.slug !== current.slug && this.findApplicationBySlug(input.slug, identifier)) {
      throw conflict("Application slug already exists");
    }
    const updated = cloneRecord(current);
    if (input.name !== undefined) updated.name = input.name;
    if (input.slug !== undefined) updated.slug = input.slug;
    if (input.description !== undefined) updated.description = input.description;
    if (input.applicationType !== undefined) updated.applicationType = input.applicationType;
    updated.updatedAt = new Date();
    updated.version = nextVersion(current.version);
    updated.etag = `application:${identifier}:${String(updated.version)}`;
    updated.readiness = readinessForRecord(updated);
    updated.effectiveStatus = effectiveStatusForRecord(updated);
    const fields = ["name", "slug", "description"].filter((field) => input[field as keyof typeof input] !== undefined);
    return this.auditedMutation(
      this.auditEvent("application.updated", identifier, context, { fields }),
      () => this.applications.set(identifier, updated),
      () => this.applications.set(identifier, current),
      updated,
    );
  }

  async setApplicationStatus(
    id: string,
    status: ApplicationStatus,
    context: ApplicationWriteContext = {},
  ): Promise<ApplicationRecord> {
    const identifier = parseApplicationIdentifier(id);
    const current = this.requireApplication(identifier);
    if (status !== "active" && status !== "disabled") throw invalidRequest("Invalid application status");
     const currentStatus = lifecycleStatusOf(current);
     if (currentStatus !== "active" && currentStatus !== "disabled") {
       throw conflict("Application is archived or purged");
     }
     if (currentStatus === status) throw conflict("Application is already in the requested state");

    const now = new Date();
     const updated = cloneRecord(current);
     updated.status = status;
     updated.lifecycleStatus = status;
     updated.updatedAt = now;
     updated.version = nextVersion(current.version);
     updated.etag = `application:${identifier}:${String(updated.version)}`;
     updated.readiness = readinessForRecord(updated);
     updated.effectiveStatus = effectiveStatusForRecord(updated);
     if (status === "active") {

      updated.enabledAt = now;
      delete updated.disabledAt;
    } else {
      updated.disabledAt = now;
      delete updated.enabledAt;
    }
    return this.auditedMutation(
      this.auditEvent(status === "active" ? "application.enabled" : "application.disabled", identifier, context, { status }),
      () => this.applications.set(identifier, updated),
      () => this.applications.set(identifier, current),
      updated,
    );
  }

  async archiveApplication(id: string, context: ApplicationWriteContext = {}): Promise<ApplicationRecord> {
    const identifier = parseApplicationIdentifier(id);
    const current = this.requireApplication(identifier);
    const currentStatus = lifecycleStatusOf(current);
    if (currentStatus === "archived" || currentStatus === "purged") {
      throw conflict("Application is already archived or purged");
    }
    const now = new Date();
    const updated = cloneRecord(current);
    updated.previousStatus = currentStatus;
    updated.status = "archived";
    updated.lifecycleStatus = "archived";
    updated.readiness = "not_ready";
    updated.effectiveStatus = "archived";
    updated.archivedAt = now;
    delete updated.purgedAt;
    updated.updatedAt = now;
    updated.version = nextVersion(current.version);
    updated.etag = `application:${identifier}:${String(updated.version)}`;
    return this.auditedMutation(
      this.auditEvent("application.archived", identifier, context, { previousStatus: currentStatus }),
      () => this.applications.set(identifier, updated),
      () => this.applications.set(identifier, current),
      updated,
    );
  }

  async restoreApplication(id: string, context: ApplicationWriteContext = {}): Promise<ApplicationRecord> {
    const identifier = parseApplicationIdentifier(id);
    const current = this.requireApplication(identifier);
    if (lifecycleStatusOf(current) !== "archived") {
      throw conflict("Only archived applications can be restored");
    }
    const previousStatus = current.previousStatus === "disabled" ? "disabled" : "active";
    const restoredStatus = previousStatus;
    const now = new Date();
    const updated = cloneRecord(current);
    updated.status = restoredStatus;
    updated.lifecycleStatus = restoredStatus;
    updated.readiness = restoredStatus === "active" ? "ready" : "not_ready";
    updated.effectiveStatus = restoredStatus;
    updated.enabledAt = restoredStatus === "active" ? now : current.enabledAt;
    updated.disabledAt = restoredStatus === "disabled" ? now : undefined;
    delete updated.previousStatus;
    delete updated.archivedAt;
    updated.updatedAt = now;
    updated.version = nextVersion(current.version);
    updated.etag = `application:${identifier}:${String(updated.version)}`;
    return this.auditedMutation(
      this.auditEvent("application.restored", identifier, context, { status: restoredStatus }),
      () => this.applications.set(identifier, updated),
      () => this.applications.set(identifier, current),
      updated,
    );
  }

  async purgeApplication(id: string, context: ApplicationWriteContext = {}): Promise<ApplicationRecord> {
    const identifier = parseApplicationIdentifier(id);
    const current = this.requireApplication(identifier);
    if (lifecycleStatusOf(current) !== "archived") {
      throw conflict("Only archived applications can be purged");
    }
    const childPlatforms = [...this.platforms.values()].filter(
      (platform) => platform.applicationId === identifier && this.belongs(platform),
    );
    const childClients = [...this.clients.values()].filter(
      (client) => client.applicationId === identifier && this.belongs(client),
    );
    const childIdentities = [...this.externalIdentities.values()].filter(
      (identity) => identity.applicationId === identifier && this.belongs(identity),
    );
    const now = new Date();
    const result = cloneRecord({
      ...current,
      status: "purged",
      lifecycleStatus: "purged",
      readiness: "not_ready",
      effectiveStatus: "purged",
      purgedAt: now,
      updatedAt: now,
       version: nextVersion(current.version),
     } as ApplicationRecord);

    result.etag = `application:${identifier}:${String(result.version)}`;
    return this.auditedMutation(
      this.auditEvent("application.purged", identifier, context, {
        platformCount: childPlatforms.length,
        clientCount: childClients.length,
        externalIdentityCount: childIdentities.length,
      }),
      () => {
        this.applications.delete(identifier);
        for (const platform of childPlatforms) this.platforms.delete(platform.id);
        for (const client of childClients) this.clients.delete(client.id);
        for (const identity of childIdentities) this.externalIdentities.delete(identity.id);
      },
      () => {
        this.applications.set(identifier, current);
        for (const platform of childPlatforms) this.platforms.set(platform.id, platform);
        for (const client of childClients) this.clients.set(client.id, client);
        for (const identity of childIdentities) this.externalIdentities.set(identity.id, identity);
      },
      result,
    );
  }

  async deleteApplication(
    id: string,
    context: ApplicationWriteContext = {},
  ): Promise<ApplicationRecord> {
    const identifier = parseApplicationIdentifier(id);
    const current = this.requireApplication(identifier);
    const childPlatforms = [...this.platforms.values()].filter(
      (platform) => platform.applicationId === identifier && this.belongs(platform),
    );
    const childClients = [...this.clients.values()].filter(
      (client) => client.applicationId === identifier && this.belongs(client),
    );
    const childIdentities = [...this.externalIdentities.values()].filter(
      (identity) => identity.applicationId === identifier && this.belongs(identity),
    );
    return this.auditedMutation(
      this.auditEvent("application.deleted", identifier, context, {
        platformCount: childPlatforms.length,
        clientCount: childClients.length,
        externalIdentityCount: childIdentities.length,
      }),
      () => {
        this.applications.delete(identifier);
        for (const platform of childPlatforms) this.platforms.delete(platform.id);
        for (const client of childClients) this.clients.delete(client.id);
        for (const identity of childIdentities) this.externalIdentities.delete(identity.id);
      },
      () => {
        this.applications.set(identifier, current);
        for (const platform of childPlatforms) this.platforms.set(platform.id, platform);
        for (const client of childClients) this.clients.set(client.id, client);
        for (const identity of childIdentities) this.externalIdentities.set(identity.id, identity);
      },
      current,
    );
  }

  async listPlatforms(
    applicationId: string,
    query: ApplicationPlatformListQuery | NormalizedApplicationPlatformQuery = {},
  ): Promise<ApplicationPage<ApplicationPlatformRecord>> {
    const page = this.listPlatformsSync(applicationId, query);
    if (this.secretBindings === undefined) return page;
    const items = await Promise.all(page.items.map((item) => this.enrichPlatform(item)));
    return { ...page, items };
  }

  listPlatformsSync(
    applicationId: string,
    query: ApplicationPlatformListQuery | NormalizedApplicationPlatformQuery = {},
  ): ApplicationPage<ApplicationPlatformRecord> {
    const appId = parseApplicationIdentifier(applicationId);
    const normalized = parseApplicationPlatformListQuery(query);
    const filtered = [...this.platforms.values()].filter((platform) => {
      if (platform.applicationId !== appId || !this.belongs(platform)) return false;
      if (normalized.status !== undefined && lifecycleStatusOf(platform) !== normalized.status) return false;
      if (normalized.readiness !== undefined && readinessForRecord(platform) !== normalized.readiness) return false;
      if (normalized.effectiveStatus !== undefined && effectiveStatusForRecord(platform) !== normalized.effectiveStatus) return false;
      const search = normalized.search ?? normalized.q;
      if (search !== undefined && !matchesPlatform(platform, search)) return false;
      return true;
    });
    const page = paginate(`platforms:${appId}`, normalized, filtered, platformScope(appId, normalized));
    if (this.secretBindings !== undefined) {
      for (const item of page.items) stripPlatformComponentSecrets(item as unknown as Record<string, unknown>);
    }
    return page;
  }

  async getPlatform(applicationId: string, id: string): Promise<ApplicationPlatformRecord | undefined> {
    const platform = this.getPlatformSync(applicationId, id);
    return platform === undefined || this.secretBindings === undefined ? platform : this.enrichPlatform(platform);
  }

  getPlatformSync(applicationId: string, id: string): ApplicationPlatformRecord | undefined {
    const appId = parseApplicationIdentifier(applicationId);
    const platformId = parseApplicationPlatformIdentifier(id);
    const platform = this.platforms.get(platformId);
    if (!platform || platform.applicationId !== appId || !this.belongs(platform)) return undefined;
    const result = cloneRecord(platform);
    if (this.secretBindings !== undefined) stripPlatformComponentSecrets(result as unknown as Record<string, unknown>);
    return result;
  }

  async createPlatform(
    applicationId: string,
    input: ApplicationPlatformCreateRequest & { id?: string },
    context: ApplicationWriteContext = {},
  ): Promise<ApplicationPlatformRecord> {
    const appId = parseApplicationIdentifier(applicationId);
    this.requireApplication(appId);
    const id = input.id ?? randomUUID();
    validateGeneratedId(id);
    if (this.platforms.has(id)) throw conflict("Platform already exists");
    const now = new Date();
    const platform: ApplicationPlatformRecord = {
      id,
      applicationId: appId,
      tenantId: this.tenantId,
      type: input.type,
      ...(input.externalAppId === undefined ? {} : { externalAppId: input.externalAppId }),
      ...(input.displayName === undefined ? {} : { displayName: input.displayName }),
      ...(input.loginMode === undefined ? {} : { loginMode: input.loginMode }),
      ...(input.scope === undefined ? {} : { scope: input.scope }),
      redirectUris: [...(input.redirectUris ?? [])],
       ...(input.endpointUrl === undefined ? {} : { endpointUrl: input.endpointUrl }),
       ...platformComponentFields(input),
       ...(this.secretBindings === undefined && input.secretRef !== undefined ? { secretRef: input.secretRef } : {}),
       status: "active",
       lifecycleStatus: "active",
       readiness: input.secretRef === undefined ? "not_ready" : "ready",
       effectiveStatus: input.secretRef === undefined ? "not_ready" : "active",
       version: 1,
       etag: `application-platform:${id}:1`,
       secretVersion: input.secretRef === undefined ? 0 : 1,
       createdAt: now,

       updatedAt: now,
       enabledAt: now,
     };
     if (this.secretBindings !== undefined) stripPlatformComponentSecrets(platform);
     return this.auditedMutation(
       this.auditEvent("application-platform.created", id, context, { applicationId: appId, type: input.type }),

      () => this.platforms.set(id, platform),
      () => this.platforms.delete(id),
      platform,
    );
  }

  async updatePlatform(
    applicationId: string,
    id: string,
    input: ApplicationPlatformMutationRequest & { id?: string },
    context: ApplicationWriteContext = {},
  ): Promise<ApplicationPlatformRecord> {
    const appId = parseApplicationIdentifier(applicationId);
    const platformId = parseApplicationPlatformIdentifier(id);
    const current = this.requirePlatform(appId, platformId);
    const updated = cloneRecord(current);
    if (input.type !== undefined) updated.type = input.type;
    if (input.externalAppId !== undefined) updated.externalAppId = input.externalAppId;
    if (input.displayName !== undefined) updated.displayName = input.displayName;
    if (input.loginMode !== undefined) updated.loginMode = input.loginMode;
    if (input.scope !== undefined) updated.scope = input.scope;
    if (input.redirectUris !== undefined) updated.redirectUris = [...input.redirectUris];
     if (input.endpointUrl !== undefined) updated.endpointUrl = input.endpointUrl;
     if (input.secretRef !== undefined) {
       if (this.secretBindings === undefined) updated.secretRef = input.secretRef;
       else delete updated.secretRef;
     }
     Object.assign(updated, platformComponentFields(input));
     if (this.secretBindings !== undefined) stripPlatformComponentSecrets(updated);
     updated.updatedAt = new Date();
     updated.version = nextVersion(current.version);
     updated.etag = `application-platform:${platformId}:${String(updated.version)}`;
     updated.readiness = readinessForRecord(updated);
     updated.effectiveStatus = effectiveStatusForRecord(updated);
     if (input.secretRef !== undefined) updated.secretVersion = nextVersion(current.secretVersion);

    const fields = ["type", "externalAppId", "displayName", "loginMode", "scope", "redirectUris", "endpointUrl"]
      .filter((field) => input[field as keyof typeof input] !== undefined);
    return this.auditedMutation(
      this.auditEvent("application-platform.updated", platformId, context, { applicationId: appId, fields }),
      () => this.platforms.set(platformId, updated),
      () => this.platforms.set(platformId, current),
      updated,
    );
  }

  async setPlatformStatus(
    applicationId: string,
    id: string,
    status: ApplicationStatus,
    context: ApplicationWriteContext = {},
  ): Promise<ApplicationPlatformRecord> {
    const appId = parseApplicationIdentifier(applicationId);
    const platformId = parseApplicationPlatformIdentifier(id);
    const current = this.requirePlatform(appId, platformId);
    if (status !== "active" && status !== "disabled") throw invalidRequest("Invalid platform status");
     const currentStatus = lifecycleStatusOf(current);
     if (currentStatus === "archived" || currentStatus === "purged") throw conflict("Platform is archived or purged");
     if (currentStatus === status) throw conflict("Platform is already in the requested state");
     const now = new Date();
     const updated = cloneRecord(current);
     updated.status = status;
     updated.lifecycleStatus = status;
     updated.updatedAt = now;
     updated.version = nextVersion(current.version);
     updated.etag = `application-platform:${platformId}:${String(updated.version)}`;
     updated.readiness = readinessForRecord(updated);
     updated.effectiveStatus = effectiveStatusForRecord(updated);
     if (status === "active") {
       updated.enabledAt = now;
       delete updated.disabledAt;
     } else {
       updated.disabledAt = now;
       delete updated.enabledAt;
     }
     return this.auditedMutation(
       this.auditEvent(status === "active" ? "application-platform.enabled" : "application-platform.disabled", platformId, context, {

        applicationId: appId,
        status,
      }),
      () => this.platforms.set(platformId, updated),
      () => this.platforms.set(platformId, current),
      updated,
    );
  }

  async archivePlatform(
    applicationId: unknown,
    id: unknown,
    context: ApplicationWriteContext = {},
  ): Promise<ApplicationPlatformRecord> {
    const appId = parseApplicationIdentifier(applicationId);
    const platformId = parseApplicationPlatformIdentifier(id);
    const current = this.requirePlatform(appId, platformId);
    const currentStatus = lifecycleStatusOf(current);
    if (currentStatus === "archived" || currentStatus === "purged") throw conflict("Platform is already archived or purged");
    const now = new Date();
    const updated = cloneRecord(current);
    updated.previousStatus = currentStatus;
    updated.status = "archived";
    updated.lifecycleStatus = "archived";
    updated.readiness = "not_ready";
    updated.effectiveStatus = "archived";
    updated.archivedAt = now;
    updated.updatedAt = now;
    updated.version = nextVersion(current.version);
    updated.etag = `application-platform:${platformId}:${String(updated.version)}`;
    return this.auditedMutation(
      this.auditEvent("application-platform.archived", platformId, context, { applicationId: appId }),
      () => this.platforms.set(platformId, updated),
      () => this.platforms.set(platformId, current),
      updated,
    );
  }

  async restorePlatform(
    applicationId: unknown,
    id: unknown,
    context: ApplicationWriteContext = {},
  ): Promise<ApplicationPlatformRecord> {
    const appId = parseApplicationIdentifier(applicationId);
    const platformId = parseApplicationPlatformIdentifier(id);
    const current = this.requirePlatform(appId, platformId);
    if (lifecycleStatusOf(current) !== "archived") throw conflict("Only archived platforms can be restored");
    const restoredStatus = current.previousStatus === "disabled" ? "disabled" : "active";
    const now = new Date();
    const updated = cloneRecord(current);
    updated.status = restoredStatus;
    updated.lifecycleStatus = restoredStatus;
    updated.readiness = restoredStatus === "active" ? readinessForRecord(current) : "not_ready";
    updated.effectiveStatus = restoredStatus;
    delete updated.previousStatus;
    delete updated.archivedAt;
    updated.updatedAt = now;
    updated.version = nextVersion(current.version);
    updated.etag = `application-platform:${platformId}:${String(updated.version)}`;
    return this.auditedMutation(
      this.auditEvent("application-platform.restored", platformId, context, { applicationId: appId }),
      () => this.platforms.set(platformId, updated),
      () => this.platforms.set(platformId, current),
      updated,
    );
  }

  async purgePlatform(
    applicationId: unknown,
    id: unknown,
    context: ApplicationWriteContext = {},
  ): Promise<ApplicationPlatformRecord> {
    const appId = parseApplicationIdentifier(applicationId);
    const platformId = parseApplicationPlatformIdentifier(id);
    const current = this.requirePlatform(appId, platformId);
    if (lifecycleStatusOf(current) !== "archived") throw conflict("Only archived platforms can be purged");
    return this.auditedMutation(
      this.auditEvent("application-platform.purged", platformId, context, { applicationId: appId }),
      () => this.platforms.delete(platformId),
      () => this.platforms.set(platformId, current),
      { ...current, status: "purged", lifecycleStatus: "purged", effectiveStatus: "purged", readiness: "not_ready" },
    );
  }

  async deletePlatform(
    applicationId: string,
    id: string,
    context: ApplicationWriteContext = {},
  ): Promise<ApplicationPlatformRecord> {
    const appId = parseApplicationIdentifier(applicationId);
    const platformId = parseApplicationPlatformIdentifier(id);
    const current = this.requirePlatform(appId, platformId);
    return this.auditedMutation(
      this.auditEvent("application-platform.deleted", platformId, context, { applicationId: appId }),
      () => this.platforms.delete(platformId),
      () => this.platforms.set(platformId, current),
      current,
    );
  }

  async listClients(
    applicationId: string,
    query: ApplicationClientListQuery | { cursor?: string; limit: number; offset?: number; search?: string; q?: string; status?: ApplicationClientStatus } = {},
  ): Promise<ApplicationPage<ApplicationClientRecord>> {
    const page = this.listClientsSync(applicationId, query);
    if (this.secretBindings === undefined) return page;
    const items = await Promise.all(page.items.map((item) => this.enrichClient(item)));
    return { ...page, items };
  }

  listClientsSync(
    applicationId: string,
    query: ApplicationClientListQuery | { cursor?: string; limit: number; offset?: number; search?: string; q?: string; status?: ApplicationStatus } = {},
  ): ApplicationPage<ApplicationClientRecord> {
    const appId = parseApplicationIdentifier(applicationId);
    const normalized = parseApplicationClientListQuery(query);
    const filtered = [...this.clients.values()].filter((client) => {
      if (client.applicationId !== appId || !this.belongs(client)) return false;
      if (normalized.status !== undefined && lifecycleStatusOf(client) !== normalized.status) return false;
      if (normalized.readiness !== undefined && readinessForRecord(client) !== normalized.readiness) return false;
       if (normalized.effectiveStatus !== undefined && effectiveStatusForRecord(client) !== normalized.effectiveStatus) return false;
       const clientKind = (normalized as NormalizedApplicationClientQuery).clientKind;
       if (clientKind !== undefined && (client.clientKind ?? client.clientType ?? "web") !== clientKind) return false;
       const search = normalized.search ?? normalized.q;

      if (search !== undefined && !matchesClient(client, search)) return false;
      return true;
    });
    return paginate(`clients:${appId}`, normalized, filtered, clientScope(appId, normalized));
  }

  async getClient(applicationId: string, id: string): Promise<ApplicationClientRecord | undefined> {
    const client = this.getClientSync(applicationId, id);
    return client === undefined || this.secretBindings === undefined ? client : this.enrichClient(client);
  }

  getClientSync(applicationId: string, id: string): ApplicationClientRecord | undefined {
    const appId = parseApplicationIdentifier(applicationId);
    const clientId = parseApplicationClientIdentifier(id);
    const direct = this.clients.get(clientId);
    if (direct !== undefined) {
      if (direct.applicationId !== appId || !this.belongs(direct)) return undefined;
      return cloneRecord(direct);
    }
    const client = [...this.clients.values()].find(
      (item) => item.applicationId === appId && item.clientId === clientId && this.belongs(item),
    );
    if (!client) return undefined;
    return cloneRecord(client);
  }

  async findClientByClientId(clientId: string): Promise<ApplicationClientRecord | undefined> {
    const identifier = parseApplicationClientIdentifier(clientId, "oidcClientId");
    const client = this.findClientByClientIdInternal(identifier);
    return client === undefined || this.secretBindings === undefined ? client : this.enrichClient(client);
  }

  async createClient(
    applicationId: string,
    input: ApplicationClientCreateRequest & { id?: string },
    context: ApplicationWriteContext = {},
  ): Promise<ApplicationClientRecord> {
    const appId = parseApplicationIdentifier(applicationId);
    const application = this.requireApplication(appId);
    if (this.findClientByClientIdInternal(input.clientId)) throw conflict("OIDC clientId already exists");
    const defaultClientKind = application.applicationType === "native" ? "native" : "web";
    const id = input.id ?? randomUUID();
    validateGeneratedId(id);
    if (this.clients.has(id)) throw conflict("OIDC client already exists");
    const now = new Date();
    const clientIdScope = input.clientIdScope ?? "global";
    if (clientIdScope !== "global") throw invalidRequest("OIDC clientIdScope must be global");
    const client: ApplicationClientRecord = {
      id,
      applicationId: appId,
      tenantId: this.tenantId,
       clientId: input.clientId,
       clientIdScope,
       clientKind: input.clientKind ?? input.clientType ?? defaultClientKind,
       clientType: input.clientType ?? input.clientKind ?? defaultClientKind,
       ...(input.redirectUriPolicy === undefined ? {} : { redirectUriPolicy: input.redirectUriPolicy }),
       ...(input.pkceMethod === undefined ? {} : { pkceMethod: input.pkceMethod }),
       ...(input.consent === undefined ? {} : { consent: cloneValue(input.consent) as ApplicationClientRecord["consent"] }),
       ...(input.consentRequired === undefined ? {} : { consentRequired: input.consentRequired }),
       ...(input.requireExplicitConsent === undefined ? {} : { requireExplicitConsent: input.requireExplicitConsent }),
       ...(input.rpClient === undefined ? {} : { rpClient: cloneValue(input.rpClient) as ApplicationClientRecord["rpClient"] }),
       redirectUris: [...(input.redirectUris ?? [])],

      postLogoutRedirectUris: [...(input.postLogoutRedirectUris ?? [])],
      grantTypes: [...(input.grantTypes ?? ["authorization_code"])],
      responseTypes: [...(input.responseTypes ?? ["code"])],
      scopes: [...(input.scopes ?? ["openid", "profile", "email"])],
       tokenEndpointAuthMethod: input.tokenEndpointAuthMethod ?? "client_secret_basic",
       ...(input.tokenEndpointAuthSigningAlg === undefined ? {} : { tokenEndpointAuthSigningAlg: input.tokenEndpointAuthSigningAlg }),
       ...(input.jwksUri === undefined ? {} : { jwksUri: input.jwksUri }),
       ...(input.privateKeyRef === undefined ? {} : { privateKeyRef: input.privateKeyRef }),
       ...(input.keyId === undefined ? {} : { keyId: input.keyId }),
       requirePkce: input.requirePkce ?? true,
       ...(this.secretBindings === undefined && input.secretRef !== undefined ? { secretRef: input.secretRef } : {}),
       status: "active",
       lifecycleStatus: "active",
        readiness: input.secretRef === undefined && input.tokenEndpointAuthMethod !== "private_key_jwt" && input.tokenEndpointAuthMethod !== "none" ? "not_ready" : "ready",
        effectiveStatus: input.tokenEndpointAuthMethod === "private_key_jwt" || input.tokenEndpointAuthMethod === "none" || input.secretRef !== undefined ? "active" : "not_ready",
       version: 1,
       etag: `application-client:${id}:1`,
       secretVersion: input.secretRef === undefined ? 0 : 1,
       createdAt: now,

      updatedAt: now,
      enabledAt: now,
    };
    return this.auditedMutation(
      this.auditEvent("application-client.created", id, context, { applicationId: appId, clientId: input.clientId }),
      () => this.clients.set(id, client),
      () => this.clients.delete(id),
      client,
    );
  }

  async updateClient(
    applicationId: string,
    id: string,
    input: ApplicationClientMutationRequest & { id?: string },
    context: ApplicationWriteContext = {},
  ): Promise<ApplicationClientRecord> {
    const appId = parseApplicationIdentifier(applicationId);
    const clientRecordId = parseApplicationClientIdentifier(id);
    const current = this.requireClient(appId, clientRecordId);
    const storedId = current.id;
    if (input.clientId !== undefined && input.clientId !== current.clientId && this.findClientByClientIdInternal(input.clientId, storedId)) {
      throw conflict("OIDC clientId already exists");
    }
    const updated = cloneRecord(current);
     if (input.clientId !== undefined) updated.clientId = input.clientId;
     if (input.clientKind !== undefined) updated.clientKind = input.clientKind;
     if (input.clientType !== undefined) updated.clientType = input.clientType;
     if (input.redirectUriPolicy !== undefined) updated.redirectUriPolicy = input.redirectUriPolicy;
     if (input.pkceMethod !== undefined) updated.pkceMethod = input.pkceMethod;
     if (input.consent !== undefined) updated.consent = cloneValue(input.consent) as ApplicationClientRecord["consent"];
     if (input.consentRequired !== undefined) updated.consentRequired = input.consentRequired;
     if (input.requireExplicitConsent !== undefined) updated.requireExplicitConsent = input.requireExplicitConsent;
     if (input.rpClient !== undefined) updated.rpClient = cloneValue(input.rpClient) as ApplicationClientRecord["rpClient"];
     if (input.clientIdScope !== undefined) {
       if (input.clientIdScope !== "global") throw invalidRequest("OIDC clientIdScope must be global");
       updated.clientIdScope = "global";
     }
     if (input.redirectUris !== undefined) updated.redirectUris = [...input.redirectUris];
    if (input.postLogoutRedirectUris !== undefined) updated.postLogoutRedirectUris = [...input.postLogoutRedirectUris];
    if (input.grantTypes !== undefined) updated.grantTypes = [...input.grantTypes];
    if (input.responseTypes !== undefined) updated.responseTypes = [...input.responseTypes];
    if (input.scopes !== undefined) updated.scopes = [...input.scopes];
     if (input.tokenEndpointAuthMethod !== undefined) updated.tokenEndpointAuthMethod = input.tokenEndpointAuthMethod;
     if (input.tokenEndpointAuthSigningAlg !== undefined) updated.tokenEndpointAuthSigningAlg = input.tokenEndpointAuthSigningAlg;
     if (input.jwksUri !== undefined) updated.jwksUri = input.jwksUri;
     if (input.privateKeyRef !== undefined) updated.privateKeyRef = input.privateKeyRef;
     if (input.keyId !== undefined) updated.keyId = input.keyId;
     if (input.requirePkce !== undefined) updated.requirePkce = input.requirePkce;
     if (input.secretRef !== undefined) {
       if (this.secretBindings === undefined) updated.secretRef = input.secretRef;
       else delete updated.secretRef;
     }
     updated.updatedAt = new Date();
     updated.version = nextVersion(current.version);
     updated.etag = `application-client:${storedId}:${String(updated.version)}`;
     updated.readiness = readinessForRecord(updated);
     updated.effectiveStatus = effectiveStatusForRecord(updated);
     if (input.secretRef !== undefined) updated.secretVersion = nextVersion(current.secretVersion);

    const fields = ["clientId", "redirectUris", "postLogoutRedirectUris", "grantTypes", "responseTypes", "scopes", "tokenEndpointAuthMethod", "requirePkce"]
      .filter((field) => input[field as keyof typeof input] !== undefined);
    return this.auditedMutation(
      this.auditEvent("application-client.updated", storedId, context, { applicationId: appId, fields }),
      () => this.clients.set(storedId, updated),
      () => this.clients.set(storedId, current),
      updated,
    );
  }

  async rotateClientSecret(
    applicationId: string,
    id: string,
    input: ApplicationClientRotateSecretRequest,
    context: ApplicationWriteContext = {},
  ): Promise<ApplicationClientRecord> {
    const appId = parseApplicationIdentifier(applicationId);
    const clientRecordId = parseApplicationClientIdentifier(id);
    const current = this.requireClient(appId, clientRecordId);
    const storedId = current.id;
    if (input.secretRef === undefined) throw invalidRequest("A new secretRef is required");
    if (input.expectedVersion !== undefined && String(input.expectedVersion) !== String(current.version)) {
      throw conflict("OIDC client version changed");
    }
    const now = new Date();
    const updated = cloneRecord(current);
    if (input.secretRef !== undefined) {
      if (this.secretBindings === undefined) updated.secretRef = input.secretRef;
      else delete updated.secretRef;
    }
    updated.updatedAt = now;
    updated.secretVersion = nextVersion(current.secretVersion);
    updated.secretStatus = "configured";
    updated.version = nextVersion(current.version);
    updated.etag = `application-client:${storedId}:${String(updated.version)}`;
    updated.readiness = readinessForRecord(updated);
    updated.effectiveStatus = effectiveStatusForRecord(updated);
    return this.auditedMutation(
      this.auditEvent("application-client.secret-rotated", storedId, context, { applicationId: appId }),
      () => this.clients.set(storedId, updated),
      () => this.clients.set(storedId, current),
      updated,
    );
  }

  async setClientStatus(
    applicationId: string,
    id: string,
    status: ApplicationClientStatus,
    context: ApplicationWriteContext = {},
  ): Promise<ApplicationClientRecord> {
    const appId = parseApplicationIdentifier(applicationId);
    const clientRecordId = parseApplicationClientIdentifier(id);
    const current = this.requireClient(appId, clientRecordId);
    const storedId = current.id;
    if (status !== "active" && status !== "disabled") throw invalidRequest("Invalid OIDC client status");
     const currentStatus = lifecycleStatusOf(current);
     if (currentStatus === "archived" || currentStatus === "purged") throw conflict("OIDC client is archived or purged");
     if (currentStatus === status) throw conflict("OIDC client is already in the requested state");
     const now = new Date();
     const updated = cloneRecord(current);
     updated.status = status;
     updated.lifecycleStatus = status;
     updated.updatedAt = now;
     updated.version = nextVersion(current.version);
     updated.etag = `application-client:${storedId}:${String(updated.version)}`;
     updated.readiness = readinessForRecord(updated);
     updated.effectiveStatus = effectiveStatusForRecord(updated);
     if (status === "active") {
       updated.enabledAt = now;
       delete updated.disabledAt;
     } else {
       updated.disabledAt = now;
       delete updated.enabledAt;
     }
     return this.auditedMutation(
       this.auditEvent(status === "active" ? "application-client.enabled" : "application-client.disabled", storedId, context, {

        applicationId: appId,
        status,
      }),
      () => this.clients.set(storedId, updated),
      () => this.clients.set(storedId, current),
      updated,
    );
  }

  async archiveClient(
    applicationId: unknown,
    id: unknown,
    context: ApplicationWriteContext = {},
  ): Promise<ApplicationClientRecord> {
    const appId = parseApplicationIdentifier(applicationId);
    const clientId = parseApplicationClientIdentifier(id);
    const current = this.requireClient(appId, clientId);
    const currentStatus = lifecycleStatusOf(current);
    if (currentStatus === "archived" || currentStatus === "purged") throw conflict("OIDC client is already archived or purged");
    const now = new Date();
    const updated = cloneRecord(current);
    updated.previousStatus = currentStatus;
    updated.status = "archived";
    updated.lifecycleStatus = "archived";
    updated.readiness = "not_ready";
    updated.effectiveStatus = "archived";
    updated.archivedAt = now;
    updated.updatedAt = now;
    updated.version = nextVersion(current.version);
    updated.etag = `application-client:${current.id}:${String(updated.version)}`;
    return this.auditedMutation(
      this.auditEvent("application-client.archived", current.id, context, { applicationId: appId }),
      () => this.clients.set(current.id, updated),
      () => this.clients.set(current.id, current),
      updated,
    );
  }

  async restoreClient(
    applicationId: unknown,
    id: unknown,
    context: ApplicationWriteContext = {},
  ): Promise<ApplicationClientRecord> {
    const appId = parseApplicationIdentifier(applicationId);
    const clientId = parseApplicationClientIdentifier(id);
    const current = this.requireClient(appId, clientId);
    if (lifecycleStatusOf(current) !== "archived") throw conflict("Only archived OIDC clients can be restored");
    const restoredStatus = current.previousStatus === "disabled" ? "disabled" : "active";
    const now = new Date();
    const updated = cloneRecord(current);
    updated.status = restoredStatus;
    updated.lifecycleStatus = restoredStatus;
    updated.readiness = restoredStatus === "active" ? readinessForRecord(current) : "not_ready";
    updated.effectiveStatus = restoredStatus;
    delete updated.previousStatus;
    delete updated.archivedAt;
    updated.updatedAt = now;
    updated.version = nextVersion(current.version);
    updated.etag = `application-client:${current.id}:${String(updated.version)}`;
    return this.auditedMutation(
      this.auditEvent("application-client.restored", current.id, context, { applicationId: appId }),
      () => this.clients.set(current.id, updated),
      () => this.clients.set(current.id, current),
      updated,
    );
  }

  async purgeClient(
    applicationId: unknown,
    id: unknown,
    context: ApplicationWriteContext = {},
  ): Promise<ApplicationClientRecord> {
    const appId = parseApplicationIdentifier(applicationId);
    const clientId = parseApplicationClientIdentifier(id);
    const current = this.requireClient(appId, clientId);
    if (lifecycleStatusOf(current) !== "archived") throw conflict("Only archived OIDC clients can be purged");
    return this.auditedMutation(
      this.auditEvent("application-client.purged", current.id, context, { applicationId: appId }),
      () => this.clients.delete(current.id),
      () => this.clients.set(current.id, current),
      { ...current, status: "purged", lifecycleStatus: "purged", effectiveStatus: "purged", readiness: "not_ready" },
    );
  }

  async deleteClient(
    applicationId: string,
    id: string,
    context: ApplicationWriteContext = {},
  ): Promise<ApplicationClientRecord> {
    const appId = parseApplicationIdentifier(applicationId);
    const clientRecordId = parseApplicationClientIdentifier(id);
    const current = this.requireClient(appId, clientRecordId);
    return this.auditedMutation(
      this.auditEvent("application-client.deleted", current.id, context, { applicationId: appId, clientId: current.clientId }),
      () => this.clients.delete(current.id),
      () => this.clients.set(current.id, current),
      current,
    );
  }

  async enableApplication(id: string, context: ApplicationWriteContext = {}): Promise<ApplicationRecord> {
    return this.setApplicationStatus(id, "active", context);
  }

  async disableApplication(id: string, context: ApplicationWriteContext = {}): Promise<ApplicationRecord> {
    return this.setApplicationStatus(id, "disabled", context);
  }

  async enablePlatform(applicationId: string, id: string, context: ApplicationWriteContext = {}): Promise<ApplicationPlatformRecord> {
    return this.setPlatformStatus(applicationId, id, "active", context);
  }

  async disablePlatform(applicationId: string, id: string, context: ApplicationWriteContext = {}): Promise<ApplicationPlatformRecord> {
    return this.setPlatformStatus(applicationId, id, "disabled", context);
  }

  async enableClient(applicationId: string, id: string, context: ApplicationWriteContext = {}): Promise<ApplicationClientRecord> {
    return this.setClientStatus(applicationId, id, "active", context);
  }

  async disableClient(applicationId: string, id: string, context: ApplicationWriteContext = {}): Promise<ApplicationClientRecord> {
    return this.setClientStatus(applicationId, id, "disabled", context);
  }

  seedApplications(applications: readonly ApplicationRecord[]): void {
    for (const application of applications) {
      if (typeof application.id !== "string" || application.id.length === 0) continue;
      if (application.tenantId !== undefined && application.tenantId !== this.tenantId) continue;
      if (this.applications.has(application.id)) throw conflict("Application already exists");
      if (typeof application.slug === "string" && this.findApplicationBySlug(application.slug)) {
        throw conflict("Application slug already exists");
      }
      const now = new Date();
      const status = normalizeStatus(application.status);
      const stored = cloneRecord({
        ...application,
        tenantId: this.tenantId,
        applicationType: application.applicationType ?? "web",
        status,
        lifecycleStatus: application.lifecycleStatus ?? status,
        readiness: application.readiness ?? (status === "active" ? "ready" : "not_ready"),
        effectiveStatus: application.effectiveStatus ?? (status === "active" ? "active" : "not_ready"),
        version: application.version ?? 1,
        etag: application.etag ?? `application:${application.id}:${String(application.version ?? 1)}`,
        createdAt: application.createdAt ?? now,
        updatedAt: application.updatedAt ?? now,
        enabledAt: status === "disabled" ? application.enabledAt : application.enabledAt ?? now,
      });
      stored.readiness = readinessForRecord(stored);
      stored.effectiveStatus = effectiveStatusForRecord(stored);
      this.applications.set(application.id, stored);
    }
  }

  seedPlatforms(platforms: readonly ApplicationPlatformRecord[]): void {
    for (const platform of platforms) {
      if (typeof platform.id !== "string" || platform.id.length === 0) continue;
      if (platform.tenantId !== undefined && platform.tenantId !== this.tenantId) continue;
      if (!this.applications.has(platform.applicationId)) continue;
      if (this.platforms.has(platform.id)) throw conflict("Platform already exists");
      const now = new Date();
      const status = normalizeStatus(platform.status);
      const stored = cloneRecord({
        ...platform,
        tenantId: this.tenantId,
        redirectUris: Array.isArray(platform.redirectUris) ? [...platform.redirectUris] : [],
        status,
        lifecycleStatus: platform.lifecycleStatus ?? status,
        readiness: platform.readiness ?? (platform.secretRef !== undefined && platform.secretRef !== null ? "ready" : "not_ready"),
        effectiveStatus: platform.effectiveStatus ?? (status === "active" && platform.secretRef !== undefined && platform.secretRef !== null ? "active" : "not_ready"),
        version: platform.version ?? 1,
        etag: platform.etag ?? `application-platform:${platform.id}:${String(platform.version ?? 1)}`,
        secretVersion: platform.secretVersion ?? (platform.secretRef ? 1 : 0),
        createdAt: platform.createdAt ?? now,
        updatedAt: platform.updatedAt ?? now,
         enabledAt: status === "disabled" ? platform.enabledAt : platform.enabledAt ?? now,
       });
       if (this.secretBindings !== undefined) {
         delete stored.secretRef;
         stripPlatformComponentSecrets(stored);
       }
       stored.readiness = readinessForRecord(stored);

       stored.effectiveStatus = effectiveStatusForRecord(stored);
       this.platforms.set(platform.id, stored);
    }
  }

  seedClients(clients: readonly ApplicationClientRecord[]): void {
    for (const client of clients) {
      if (typeof client.id !== "string" || client.id.length === 0) continue;
      if (client.tenantId !== undefined && client.tenantId !== this.tenantId) continue;
      if (!this.applications.has(client.applicationId)) continue;
      if (this.clients.has(client.id)) throw conflict("OIDC client already exists");
      if (typeof client.clientId === "string" && this.findClientByClientIdInternal(client.clientId)) {
        throw conflict("OIDC clientId already exists");
      }
      const now = new Date();
      const status = normalizeStatus(client.status);
      const stored = cloneRecord({
         ...client,
         tenantId: this.tenantId,
         clientIdScope: client.clientIdScope ?? "global",
         clientKind: client.clientKind ?? client.clientType ?? "web",
         clientType: client.clientType ?? client.clientKind ?? "web",

        redirectUris: Array.isArray(client.redirectUris) ? [...client.redirectUris] : [],
        postLogoutRedirectUris: Array.isArray(client.postLogoutRedirectUris) ? [...client.postLogoutRedirectUris] : [],
        grantTypes: Array.isArray(client.grantTypes) ? [...client.grantTypes] : [],
        responseTypes: Array.isArray(client.responseTypes) ? [...client.responseTypes] : [],
        scopes: Array.isArray(client.scopes) ? [...client.scopes] : [],
        status,
        lifecycleStatus: client.lifecycleStatus ?? status,
        readiness: client.readiness ?? (client.secretRef !== undefined && client.secretRef !== null || client.tokenEndpointAuthMethod === "private_key_jwt" ? "ready" : "not_ready"),
        effectiveStatus: client.effectiveStatus ?? (status === "active" && (client.secretRef !== undefined && client.secretRef !== null || client.tokenEndpointAuthMethod === "private_key_jwt") ? "active" : "not_ready"),
        version: client.version ?? 1,
        etag: client.etag ?? `application-client:${client.id}:${String(client.version ?? 1)}`,
        secretVersion: client.secretVersion ?? (client.secretRef ? 1 : 0),
        createdAt: client.createdAt ?? now,
        updatedAt: client.updatedAt ?? now,
        enabledAt: status === "disabled" ? client.enabledAt : client.enabledAt ?? now,
      });
       if (this.secretBindings !== undefined) delete stored.secretRef;
       stored.readiness = readinessForRecord(stored);
       stored.effectiveStatus = effectiveStatusForRecord(stored);
       this.clients.set(client.id, stored);
    }
  }

  seedExternalIdentities(identities: readonly ApplicationExternalIdentityRecord[]): void {
    for (const identity of identities) {
      if (typeof identity.id !== "string" || identity.id.length === 0) continue;
      if (identity.tenantId !== undefined && identity.tenantId !== this.tenantId) continue;
      if (!this.applications.has(identity.applicationId)) continue;
      if (this.externalIdentities.has(identity.id)) throw conflict("External identity already exists");
      const platform = typeof identity.platform === "string" ? identity.platform : typeof identity.platformId === "string" ? identity.platformId : "";
      const providerAppId = typeof identity.providerAppId === "string" ? identity.providerAppId : typeof identity.appId === "string" ? identity.appId : typeof identity.externalAppId === "string" ? identity.externalAppId : "";
      const canonical = externalIdentityCanonicalKey({ tenantId: this.tenantId, applicationId: identity.applicationId, provider: identity.provider, platform, providerAppId, subject: identity.subject });
      if ([...this.externalIdentities.values()].some((item) => this.sameExternalIdentity(item, canonical))) throw conflict("External identity already exists");
       const linkedAt = (identity.firstLinkedAt ?? identity.linkedAt ?? identity.createdAt ?? new Date()) as string | number | Date;
      this.externalIdentities.set(identity.id, cloneRecord({ ...identity, tenantId: this.tenantId, platform, providerAppId, firstLinkedAt: linkedAt, linkedAt: identity.linkedAt ?? linkedAt }));
    }
  }

  seedClientSessions(records: readonly OpaqueClientSessionRecord[]): void {
    for (const record of records) {
      if (record.tenantId !== this.tenantId) continue;
      const normalized = cloneOpaqueRecord(record);
      if (!this.clientSessions.has(normalized.sessionHash)) this.clientSessions.set(normalized.sessionHash, normalized);
    }
  }

  seedWebviewTickets(records: readonly WebviewTicketRecord[]): void {
    for (const record of records) {
      if (record.tenantId !== this.tenantId) continue;
      const normalized = cloneWebviewRecord(record);
      if (!this.webviewTickets.has(normalized.ticketHash)) this.webviewTickets.set(normalized.ticketHash, normalized);
    }
  }

  seedAuditEvents(events: readonly ApplicationAuditEvent[]): void {
    for (const event of events) {
      if (event.tenantId !== undefined && event.tenantId !== this.tenantId) continue;
      const id = this.auditId(event);
      this.auditEvents.set(id, cloneRecord({ ...event, id, tenantId: this.tenantId, detail: sanitizeAuditDetail(event.detail ?? {}) ?? {} }));
    }
  }

  addApplication(application: ApplicationRecord): ApplicationRecord {
    if (typeof application.id !== "string" || application.id.length === 0) throw invalidRequest("Invalid application");
    if (application.tenantId !== undefined && application.tenantId !== this.tenantId) throw notFound("Application not found");
    if (this.applications.has(application.id) || this.findApplicationBySlug(application.slug)) throw conflict("Application already exists");
    const stored = cloneRecord({ ...application, tenantId: this.tenantId });
    stored.readiness = readinessForRecord(stored);
    stored.effectiveStatus = effectiveStatusForRecord(stored);
    this.applications.set(application.id, stored);
    return cloneRecord(application);
  }

  addPlatform(platform: ApplicationPlatformRecord): ApplicationPlatformRecord {
    if (typeof platform.id !== "string" || platform.id.length === 0) throw invalidRequest("Invalid platform");
    if (platform.tenantId !== undefined && platform.tenantId !== this.tenantId) throw notFound("Application platform not found");
    if (!this.applications.has(platform.applicationId)) throw notFound("Application not found");
    const stored = cloneRecord({ ...platform, tenantId: this.tenantId });
    if (this.secretBindings !== undefined) delete stored.secretRef;
    stored.readiness = readinessForRecord(stored);
    stored.effectiveStatus = effectiveStatusForRecord(stored);
    this.platforms.set(platform.id, stored);
    return cloneRecord(platform);
  }

  addClient(client: ApplicationClientRecord): ApplicationClientRecord {
    if (typeof client.id !== "string" || client.id.length === 0) throw invalidRequest("Invalid OIDC client");
    if (client.tenantId !== undefined && client.tenantId !== this.tenantId) throw notFound("OIDC client not found");
    if (!this.applications.has(client.applicationId)) throw notFound("Application not found");
    if (this.clients.has(client.id) || this.findClientByClientIdInternal(client.clientId)) throw conflict("OIDC client already exists");
    const stored = cloneRecord({ ...client, tenantId: this.tenantId, clientIdScope: client.clientIdScope ?? "global" });
    if (this.secretBindings !== undefined) delete stored.secretRef;
    stored.readiness = readinessForRecord(stored);
    stored.effectiveStatus = effectiveStatusForRecord(stored);
    this.clients.set(client.id, stored);
    return cloneRecord(client);
  }

  addAuditEvent(event: ApplicationAuditEvent): ApplicationAuditEvent {
    if (event.tenantId !== undefined && event.tenantId !== this.tenantId) throw notFound("Audit event not found");
    const id = this.auditId(event);
    const stored = cloneRecord({ ...event, id, tenantId: this.tenantId, detail: sanitizeAuditDetail(event.detail ?? {}) ?? {} });
    this.auditEvents.set(id, stored);
    return cloneRecord(stored);
  }

  appendAuditEvent(event: ApplicationAuditEvent): ApplicationAuditEvent {
    return this.addAuditEvent(event);
  }

  async issueOpaqueClientSession(input: OpaqueClientSessionIssueInput): Promise<OpaqueClientSessionIssueResult> {
    const applicationId = parseApplicationIdentifier(input.applicationId);
    this.requireApplication(applicationId);
    const clientKind = input.clientKind;
    if (clientKind !== "mp_weixin" && clientKind !== "native") throw invalidRequest("Opaque client session kind is invalid");
    if (this.clientSessionRepository !== undefined) {
      const result = await this.clientSessionRepository.issue({ ...input, applicationId, ...(input.deviceId === undefined ? {} : { deviceId: input.deviceId }) });
      if (result.record.tenantId !== this.tenantId || result.record.applicationId !== applicationId || result.record.clientKind !== clientKind || result.record.userId !== input.userId || result.record.clientId !== input.clientId) throw notFound("Opaque client session not found");
      return result;
    }
    const sessionReference = input.sessionReference === undefined ? randomBytes(32).toString("base64url") : normalizeOpaqueReference(input.sessionReference);
    const sessionHash = hashOpaqueReference(sessionReference);
    if (this.clientSessions.has(sessionHash)) throw conflict("Opaque client session already exists");
    const now = new Date();
    const expiresAt = new Date(now.getTime() + opaqueSessionTtlMilliseconds(input.expiresInSeconds));
    const record: OpaqueClientSessionRecord = {
      id: randomUUID(),
      tenantId: this.tenantId,
      applicationId,
      clientId: input.clientId,
      clientKind,
      sessionHash,
      userId: input.userId,
      status: "active",
      ...(input.deviceId === undefined ? {} : { deviceId: input.deviceId }),
      ...(input.binding === undefined ? {} : { bindingHash: hashOpaqueReference(normalizeOpaqueReference(input.binding)) }),
      createdAt: now.toISOString(),
      updatedAt: now.toISOString(),
      expiresAt: expiresAt.toISOString(),
    };
    this.clientSessions.set(sessionHash, record);
    return {
      session: {
        sessionReference,
        clientKind,
        expiresAt: record.expiresAt,
        tokenType: "Bearer",
      },
      record: cloneOpaqueRecord(record),
    };
  }

  async findOpaqueClientSession(sessionReference: string): Promise<OpaqueClientSessionRecord | undefined> {
    if (this.clientSessionRepository !== undefined) {
      const record = await this.clientSessionRepository.find(sessionReference);
      if (record?.tenantId !== this.tenantId || record.status !== "active" || record.expiresAt <= new Date().toISOString()) return undefined;
      return record;
    }
    const record = this.clientSessions.get(hashOpaqueReference(normalizeOpaqueReference(sessionReference)));
    if (record === undefined || record.status !== "active" || record.expiresAt <= new Date().toISOString()) return undefined;
    return cloneOpaqueRecord(record);
  }

  async issueWebviewTicket(input: WebviewTicketIssueInput): Promise<WebviewTicketIssueResult> {
    const applicationId = parseApplicationIdentifier(input.applicationId);
    const platformId = parseApplicationPlatformIdentifier(input.platformId);
    this.requireApplication(applicationId);
    this.requirePlatform(applicationId, platformId);
    const redirectUri = normalizeRedirectUriForRecord(input.redirectUri);
    if (this.webviewTicketRepository !== undefined) {
      const result = await this.webviewTicketRepository.issue({ ...input, applicationId, platformId, redirectUri });
      if (result.record.tenantId !== this.tenantId || result.record.applicationId !== applicationId || result.record.platformId !== platformId) throw notFound("Webview ticket not found");
      return result;
    }
    const ticketReference = input.ticketReference === undefined && input.ticket === undefined ? randomBytes(32).toString("base64url") : normalizeOpaqueReference(input.ticketReference ?? input.ticket);
    const ticketHash = hashOpaqueReference(ticketReference);
    if (this.webviewTickets.has(ticketHash)) throw conflict("Webview ticket already exists");
    const now = new Date();
    const expiresAt = new Date(now.getTime() + webviewTicketTtlMilliseconds(input.expiresInSeconds));
    const record: WebviewTicketRecord = {
      id: randomUUID(),
      tenantId: this.tenantId,
      applicationId,
      platformId,
      ...(input.clientId === undefined ? {} : { clientId: input.clientId }),
      ticketHash,
      ...(input.sessionReference === undefined ? {} : { sessionHash: hashOpaqueReference(input.sessionReference) }),
      ...(input.binding === undefined ? {} : { bindingHash: hashOpaqueReference(normalizeOpaqueReference(input.binding)) }),
      redirectUri,
      status: "issued",
      createdAt: now.toISOString(),
      updatedAt: now.toISOString(),
      expiresAt: expiresAt.toISOString(),
    };
    this.webviewTickets.set(ticketHash, record);
    return {
      ticket: {
        ticketReference,
        ticket: ticketReference,
        clientKind: "webview",
        redirectUri,
        expiresAt: record.expiresAt,
        ...(input.applicationId === undefined ? {} : { applicationId: input.applicationId }),
        ...(input.platformId === undefined ? {} : { platformId: input.platformId }),
      },
      record: cloneWebviewRecord(record),
    };
  }

  async consumeWebviewTicket(input: WebviewTicketConsumeRequest): Promise<WebviewTicketRecord | undefined> {
    if (this.webviewTicketRepository !== undefined) {
      const record = await this.webviewTicketRepository.consume(input);
      return record?.tenantId === this.tenantId ? record : undefined;
    }
    const ticketHash = hashOpaqueReference(input.ticketReference);
    const current = this.webviewTickets.get(ticketHash);
    if (current === undefined || current.status !== "issued") return undefined;
    const now = new Date().toISOString();
    if (current.expiresAt <= now) {
      this.webviewTickets.set(ticketHash, { ...current, status: "expired", updatedAt: now });
      return undefined;
    }
    if (input.clientId !== undefined && current.clientId !== input.clientId) return undefined;
    if (input.sessionReference !== undefined && current.sessionHash !== hashOpaqueReference(normalizeOpaqueReference(input.sessionReference))) return undefined;
    if (input.binding !== undefined && current.bindingHash !== hashOpaqueReference(normalizeOpaqueReference(input.binding))) return undefined;
    const consumed = { ...current, status: "consumed" as const, consumedAt: now, updatedAt: now };
    this.webviewTickets.set(ticketHash, consumed);
    return cloneWebviewRecord(consumed);
  }

  async issueOpaqueSession(input: OpaqueClientSessionIssueInput): Promise<OpaqueClientSessionIssueResult> {
    return this.issueOpaqueClientSession(input);
  }

  async findOpaqueSession(sessionReference: string): Promise<OpaqueClientSessionRecord | undefined> {
    return this.findOpaqueClientSession(sessionReference);
  }

  async exchangeWebviewTicket(input: WebviewTicketConsumeRequest): Promise<WebviewTicketRecord | undefined> {
    return this.consumeWebviewTicket(input);
  }

  async issueClientSession(input: OpaqueClientSessionIssueInput): Promise<OpaqueClientSessionIssueResult> {
    return this.issueOpaqueClientSession(input);
  }

  async findClientSession(sessionReference: string): Promise<OpaqueClientSessionRecord | undefined> {
    return this.findOpaqueClientSession(sessionReference);
  }

  async createWebviewTicket(input: WebviewTicketIssueInput): Promise<WebviewTicketIssueResult> {
    return this.issueWebviewTicket(input);
  }

  async redeemWebviewTicket(input: WebviewTicketConsumeRequest): Promise<WebviewTicketRecord | undefined> {
    return this.consumeWebviewTicket(input);
  }

  async isReady(): Promise<boolean> {
    for (const repository of [this.clientSessionRepository, this.webviewTicketRepository]) {
      if (repository === undefined) continue;
      const candidate = repository as { isReady?: () => boolean | Promise<boolean>; ready?: () => boolean | Promise<boolean> };
      const check = candidate.isReady ?? candidate.ready;
      if (typeof check === "function" && !(await check.call(repository))) return false;
    }
    return true;
  }

  async withTransaction<T>(operation: () => Promise<T>): Promise<T> {
    const state = this.rawSnapshot();
    const sequence = this.auditSequence;
    try {
      return await operation();
    } catch (error) {
      this.applications.clear();
      this.platforms.clear();
      this.clients.clear();
      this.externalIdentities.clear();
      this.clientSessions.clear();
      this.webviewTickets.clear();
      this.auditEvents.clear();
      for (const application of state.applications) this.applications.set(application.id, application);
      for (const platform of state.platforms) this.platforms.set(platform.id, platform);
      for (const client of state.clients) this.clients.set(client.id, client);
      for (const identity of state.externalIdentities) this.externalIdentities.set(identity.id, identity);
      for (const session of state.clientSessions) this.clientSessions.set(session.sessionHash, session);
      for (const ticket of state.webviewTickets) this.webviewTickets.set(ticket.ticketHash, ticket);
      for (const event of state.auditEvents) {
        if (typeof event.id === "string") this.auditEvents.set(event.id, event);
      }
      this.auditSequence = sequence;
      throw error;
    }
  }

  clear(): void {
    this.applications.clear();
    this.platforms.clear();
     this.clients.clear();
     this.externalIdentities.clear();
     this.clientSessions.clear();
     this.webviewTickets.clear();
     this.auditEvents.clear();

    this.auditSequence = 0;
  }

  snapshot(): {
    applications: ApplicationRecord[];
    platforms: ApplicationPlatformRecord[];
     clients: ApplicationClientRecord[];
    auditEvents: ApplicationAuditEvent[];
    externalIdentities: ApplicationExternalIdentityRecord[];
    clientSessions: OpaqueClientSessionRecord[];
    webviewTickets: WebviewTicketRecord[];
  } {
    return {
      applications: [...this.applications.values()].map((item) => cloneRecord(item)),
      platforms: [...this.platforms.values()].map((item) => {
        const result = cloneRecord(item);
        if (this.secretBindings !== undefined) stripPlatformComponentSecrets(result as unknown as Record<string, unknown>);
        return result;
      }),
      clients: [...this.clients.values()].map((item) => cloneRecord(item)),
      auditEvents: [...this.auditEvents.values()].map((item) => cloneRecord(item)),
      externalIdentities: [...this.externalIdentities.values()].map((item) => cloneRecord(item)),
      clientSessions: this.clientSessionRepository === undefined
        ? [...this.clientSessions.values()].map((item) => cloneOpaqueRecord(item))
        : snapshotOpaqueSessions(this.clientSessionRepository),
      webviewTickets: this.webviewTicketRepository === undefined
        ? [...this.webviewTickets.values()].map((item) => cloneWebviewRecord(item))
        : snapshotWebviewTickets(this.webviewTicketRepository),
    };
  }

  private rawSnapshot(): {
    applications: ApplicationRecord[];
    platforms: ApplicationPlatformRecord[];
    clients: ApplicationClientRecord[];
    auditEvents: ApplicationAuditEvent[];
    externalIdentities: ApplicationExternalIdentityRecord[];
    clientSessions: OpaqueClientSessionRecord[];
    webviewTickets: WebviewTicketRecord[];
  } {
    return {
      applications: [...this.applications.values()].map((item) => cloneRecord(item)),
      platforms: [...this.platforms.values()].map((item) => cloneRecord(item)),
      clients: [...this.clients.values()].map((item) => cloneRecord(item)),
      auditEvents: [...this.auditEvents.values()].map((item) => cloneRecord(item)),
      externalIdentities: [...this.externalIdentities.values()].map((item) => cloneRecord(item)),
      clientSessions: [...this.clientSessions.values()].map((item) => cloneOpaqueRecord(item)),
      webviewTickets: [...this.webviewTickets.values()].map((item) => cloneWebviewRecord(item)),
    };
  }

  listExternalIdentities(
    applicationId: string,
    query: ApplicationExternalIdentityListQuery | NormalizedApplicationExternalIdentityQuery = {},
  ): ApplicationPage<ApplicationExternalIdentityRecord> {
    const appId = parseApplicationIdentifier(applicationId);
    const normalized = parseApplicationExternalIdentityListQuery(query);
    const search = normalized.search ?? normalized.q;
    const filtered = [...this.externalIdentities.values()].filter((identity) => {
      if (identity.applicationId !== appId || !this.belongs(identity)) return false;
      if (normalized.provider !== undefined && identity.provider !== normalizeExternalText(normalized.provider, "provider", 128)) return false;
      if (normalized.platformId !== undefined && identity.platformId !== normalizeExternalText(normalized.platformId, "platform id", 512)) return false;
      if (search !== undefined) {
        const value = search.toLowerCase();
        if (![identity.id, identity.provider, identity.subject, identity.externalAppId, identity.openid, identity.unionid, identity.email]
          .some((item) => typeof item === "string" && item.toLowerCase().includes(value))) return false;
      }
      return true;
    });
    return paginate(`external-identities:${appId}`, normalized, filtered, JSON.stringify([appId, search ?? "", normalized.provider ?? "", normalized.platformId ?? ""]));
  }

  async upsertExternalIdentity(
    applicationId: string,
    input: ApplicationExternalIdentityUpsertInput,
    context: ApplicationWriteContext = {},
  ): Promise<ApplicationExternalIdentityRecord> {
    const appId = parseApplicationIdentifier(applicationId);
    this.requireApplication(appId);
    const provider = normalizeExternalText(input.provider, "provider", 128);
    const subject = normalizeExternalText(input.subject, "subject", 1024);
    const requestedPlatform = normalizeOptionalExternalText(input.platform ?? input.platformId, "platform", 128) ?? "";
    const requestedProviderAppId = normalizeOptionalExternalText(input.appId ?? input.externalAppId, "provider app id", 512) ?? "";
    const existing = [...this.externalIdentities.values()].find((item) => {
      if (item.tenantId !== this.tenantId || item.applicationId !== appId || item.provider !== provider || item.subject !== subject) return false;
      const itemPlatform = typeof item.platform === "string" ? item.platform : typeof item.platformId === "string" ? item.platformId : "";
      const itemProviderAppId = typeof item.providerAppId === "string" ? item.providerAppId : typeof item.appId === "string" ? item.appId : typeof item.externalAppId === "string" ? item.externalAppId : "";
      return itemPlatform === requestedPlatform && itemProviderAppId === requestedProviderAppId;
    });
    const platform = requestedPlatform || (typeof existing?.platform === "string" ? existing.platform : typeof existing?.platformId === "string" ? existing.platformId : "");
    const providerAppId = requestedProviderAppId || (typeof existing?.providerAppId === "string" ? existing.providerAppId : typeof existing?.appId === "string" ? existing.appId : typeof existing?.externalAppId === "string" ? existing.externalAppId : "");
    const canonical = externalIdentityCanonicalKey({ tenantId: this.tenantId, applicationId: appId, provider, platform, providerAppId, subject });
    const now = new Date();
    const firstLinkedAt = (existing?.firstLinkedAt ?? existing?.linkedAt ?? now) as string | number | Date;
    const record: ApplicationExternalIdentityRecord = {
      ...(existing ?? {
        id: randomUUID(),
        applicationId: appId,
        provider,
        subject,
        version: 0,
        createdAt: now,
      }),
      platformId: input.platformId ?? existing?.platformId ?? null,
      platform,
      providerAppId,
      appId: input.appId ?? existing?.appId ?? null,
      externalAppId: input.externalAppId ?? input.appId ?? existing?.externalAppId ?? null,
      openid: input.openid ?? existing?.openid ?? null,
      unionid: input.unionid ?? existing?.unionid ?? null,
      nickname: input.nickname ?? existing?.nickname ?? null,
      displayName: input.displayName ?? existing?.displayName ?? null,
      email: input.email ?? existing?.email ?? null,
       avatarUrl: input.avatarUrl ?? existing?.avatarUrl ?? null,
       scopes: [...(input.scopes ?? existing?.scopes ?? [])],
       canonicalUserId: input.canonicalUserId ?? existing?.canonicalUserId,
       linkStatus: input.linkStatus ?? existing?.linkStatus ?? "linked",
       emailVerified: input.emailVerified ?? existing?.emailVerified ?? false,
       version: nextVersion(existing?.version ?? 0),
      firstLinkedAt,
      linkedAt: (existing?.linkedAt ?? firstLinkedAt) as string | number | Date,
      lastAuthenticatedAt: now,
      updatedAt: now,
      tenantId: this.tenantId,
    };
    const audit = this.auditEvent("application.external_identity.upserted", appId, context, {
      provider,
      platform,
      providerAppId,
      subject,
      canonicalKey: canonical.key,
    });
    return this.auditedMutation(
      audit,
      () => this.externalIdentities.set(record.id, record),
      () => {
        if (existing === undefined) this.externalIdentities.delete(record.id);
        else this.externalIdentities.set(existing.id, existing);
      },
      record,
    );
  }

  listApplicationPlatforms(
    applicationId: string,
    query?: ApplicationPlatformListQuery | NormalizedApplicationPlatformQuery,
  ): Promise<ApplicationPage<ApplicationPlatformRecord>> {
    return this.listPlatforms(applicationId, query);
  }

  listApplicationClients(
    applicationId: string,
    query?: ApplicationClientListQuery | { cursor?: string; limit: number; offset?: number; search?: string; q?: string; status?: ApplicationClientStatus },
  ): Promise<ApplicationPage<ApplicationClientRecord>> {
    return this.listClients(applicationId, query);
  }

  listOidcClients(
    applicationId: string,
    query?: ApplicationClientListQuery | { cursor?: string; limit: number; offset?: number; search?: string; q?: string; status?: ApplicationClientStatus },
  ): Promise<ApplicationPage<ApplicationClientRecord>> {
    return this.listClients(applicationId, query);
  }

  private async auditedMutation<T>(
    event: ApplicationAuditEvent,
    apply: () => void,
    rollback: () => void,
    result: T,
  ): Promise<T> {
    const previousAudit = new Map(this.auditEvents);
    const previousSequence = this.auditSequence;
    try {
      apply();
      await this.addAuditEvent(event);
      const output = cloneRecord(result as AnyRecord) as T & Record<string, unknown>;
      if (this.secretBindings !== undefined && typeof output?.id === "string") {
        if (typeof output.type === "string" && typeof output.applicationId === "string") return await this.enrichPlatform(output as unknown as ApplicationPlatformRecord) as T;
        if (typeof output.clientId === "string" && typeof output.applicationId === "string") return await this.enrichClient(output as unknown as ApplicationClientRecord) as T;
      }
      return output as T;
    } catch (error) {
      rollback();
      this.auditEvents.clear();
      for (const [eventId, value] of previousAudit) this.auditEvents.set(eventId, value);
      this.auditSequence = previousSequence;
      throw error;
    }
  }

  private requireApplication(id: string): ApplicationRecord {
    const application = this.applications.get(id);
    if (!application || !this.belongs(application)) throw notFound("Application not found");
    return application;
  }

  private requirePlatform(applicationId: string, id: string): ApplicationPlatformRecord {
    const platform = this.platforms.get(id);
    if (!platform || platform.applicationId !== applicationId || !this.belongs(platform)) {
      throw notFound("Application platform not found");
    }
    return platform;
  }

  private requireClient(applicationId: string, id: string): ApplicationClientRecord {
    const client = this.clients.get(id);
    if (!client || client.applicationId !== applicationId || !this.belongs(client)) {
      throw notFound("OIDC client not found");
    }
    return client;
  }

  private async enrichPlatform(platform: ApplicationPlatformRecord): Promise<ApplicationPlatformRecord> {
    const resolution = await this.secretBindings?.resolve("application-platform", platform.id, "platform-secret");
    const result = cloneRecord(platform);
     if (this.secretBindings !== undefined) {
       delete result.secretRef;
       stripPlatformComponentSecrets(result as unknown as Record<string, unknown>);
       result.credentialConfigured = resolution !== undefined;

      result.secretStatus = resolution?.binding.status ?? "not_configured";
      result.secretVersion = resolution?.binding.version ?? 0;
      const status = lifecycleStatusOf(result);
      result.readiness = status === "active" && resolution !== undefined ? "ready" : "not_ready";
      result.effectiveStatus = status === "archived" || status === "purged" ? status : status === "active" && resolution !== undefined ? "active" : "not_ready";
    }
    return result;
  }

  private async enrichClient(client: ApplicationClientRecord): Promise<ApplicationClientRecord> {
    const resolution = await this.secretBindings?.resolve("application-client", client.id, "oidc-client-secret");
    const result = cloneRecord(client);
    if (this.secretBindings !== undefined) {
      delete result.secretRef;
      const privateKey = client.tokenEndpointAuthMethod === "private_key_jwt";
      const publicClient = client.tokenEndpointAuthMethod === "none";
      result.hasSecret = resolution !== undefined && !publicClient && !privateKey;
      result.secretStatus = privateKey || publicClient ? "not_required" : resolution?.binding.status ?? "not_configured";
      result.secretVersion = resolution?.binding.version ?? 0;
      result.readiness = normalizeStatus(result.status) === "active" && (resolution !== undefined || privateKey || publicClient) ? "ready" : normalizeStatus(result.status) === "archived" || normalizeStatus(result.status) === "purged" ? "not_ready" : "not_ready";
      result.effectiveStatus = result.readiness === "ready" ? "active" : normalizeStatus(result.status) === "archived" || normalizeStatus(result.status) === "purged" ? normalizeStatus(result.status) : "not_ready";
    }
    return result;
  }

  private sameExternalIdentity(
    record: ApplicationExternalIdentityRecord,
    canonical: ReturnType<typeof externalIdentityCanonicalKey>,
  ): boolean {
    if (record.tenantId !== canonical.tenantId || record.applicationId !== canonical.applicationId || record.provider !== canonical.provider || record.subject !== canonical.subject) return false;
    const platform = typeof record.platform === "string" ? record.platform : typeof record.platformId === "string" ? record.platformId : "";
    const providerAppId = typeof record.providerAppId === "string" ? record.providerAppId : typeof record.appId === "string" ? record.appId : typeof record.externalAppId === "string" ? record.externalAppId : "";
    return platform === canonical.platform && providerAppId === canonical.providerAppId;
  }

  private assertApplicationIdAvailable(id: string): void {
    if (this.applications.has(id)) throw conflict("Application already exists");
  }

  private findApplicationBySlug(slug: string, exceptId?: string): ApplicationRecord | undefined {
    const normalized = slug.toLowerCase();
    return [...this.applications.values()].find(
      (application) => application.id !== exceptId && this.belongs(application) && application.slug.toLowerCase() === normalized,
    );
  }

  private findClientByClientIdInternal(clientId: string, exceptId?: string): ApplicationClientRecord | undefined {
    const normalized = clientId.toLowerCase();
    return [...this.clients.values()].find(
      (client) => client.id !== exceptId && this.belongs(client) && client.clientId.toLowerCase() === normalized,
    );
  }

  private belongs(record: { tenantId?: string }): boolean {
    return record.tenantId === this.tenantId;
  }

  private auditId(event: ApplicationAuditEvent): string {
    if (typeof event.id === "string" && event.id.length > 0) return event.id;
    let id: string;
    do {
      this.auditSequence += 1;
      id = `application-audit-${this.auditSequence}`;
    } while (this.auditEvents.has(id));
    return id;
  }

  private auditEvent(
    event: string,
    targetId: string,
    context: ApplicationWriteContext,
    detail: Record<string, unknown>,
  ): ApplicationAuditEvent {
    const now = new Date();
    return {
      tenantId: this.tenantId,
      event,
      action: event,
      actorId: contextValue(context.actorId),
      targetId,
      requestId: contextValue(context.requestId),
      ipAddress: contextValue(context.ipAddress),
      userAgent: contextValue(context.userAgent),
      outcome: "success",
      detail: sanitizeAuditDetail(detail) ?? {},
      occurredAt: now,
      createdAt: now,
    };
  }
}

export class InMemoryApplicationManagementRepository extends InMemoryApplicationRepository {}

export function encodeApplicationCursor(payload: CursorPayload): string {
  return Buffer.from(JSON.stringify(payload), "utf8").toString("base64url");
}

export function decodeApplicationCursor(cursor: string, kind: string, scope: string): number {
  try {
    const parsed = JSON.parse(Buffer.from(cursor, "base64url").toString("utf8")) as Partial<CursorPayload>;
    if (
      parsed.version !== CURSOR_VERSION ||
      parsed.kind !== kind ||
      parsed.scope !== scope ||
      !Number.isSafeInteger(parsed.offset) ||
      (parsed.offset ?? -1) < 0
    ) {
      throw new Error("invalid cursor");
    }
    return parsed.offset as number;
  } catch {
    throw invalidRequest("Invalid pagination cursor", { field: "cursor" });
  }
}

function paginate<T>(
  kind: string,
  query: { cursor?: string; limit: number; offset?: number },
  records: T[],
  scope: string,
): ApplicationPage<T> {
  const offset = query.cursor === undefined ? query.offset ?? 0 : decodeApplicationCursor(query.cursor, kind, scope);
  const items = records.slice(offset, offset + query.limit).map((item) => cloneValue(item) as T);
  const nextOffset = offset + items.length;
  const hasMore = nextOffset < records.length;
  return {
    items,
    hasMore,
    total: records.length,
    ...(hasMore
      ? { nextCursor: encodeApplicationCursor({ version: CURSOR_VERSION, kind, offset: nextOffset, scope }) }
      : {}),
  };
}

function applicationScope(query: { search?: string; q?: string; status?: string; applicationType?: string; readiness?: string; effectiveStatus?: string }): string {
  return JSON.stringify([
    query.search ?? query.q ?? "",
    query.status ?? "",
    query.applicationType ?? "",
    query.readiness ?? "",
    query.effectiveStatus ?? "",
  ]);
}

function platformScope(applicationId: string, query: { search?: string; q?: string; status?: string; readiness?: string; effectiveStatus?: string }): string {
  return JSON.stringify([applicationId, query.search ?? query.q ?? "", query.status ?? "", query.readiness ?? "", query.effectiveStatus ?? ""]);
}

function clientScope(applicationId: string, query: { search?: string; q?: string; status?: string; readiness?: string; effectiveStatus?: string; clientKind?: string }): string {
  return JSON.stringify([applicationId, query.search ?? query.q ?? "", query.status ?? "", query.readiness ?? "", query.effectiveStatus ?? "", query.clientKind ?? ""]);
}

function matchesApplication(application: ApplicationRecord, value: string): boolean {
  const normalized = value.toLowerCase();
  return [application.id, application.name, application.slug, application.description]
    .some((item) => typeof item === "string" && item.toLowerCase().includes(normalized));
}

function matchesPlatform(platform: ApplicationPlatformRecord, value: string): boolean {
  const normalized = value.toLowerCase();
  return [platform.id, platform.type, platform.externalAppId, platform.displayName, platform.loginMode, platform.scope, platform.componentAppId, platform.authorizedAppId, platform.authorizerAppId]
    .some((item) => typeof item === "string" && item.toLowerCase().includes(normalized));
}

function matchesClient(client: ApplicationClientRecord, value: string): boolean {
  const normalized = value.toLowerCase();
  return [client.id, client.clientId, client.clientKind, client.clientType, client.tokenEndpointAuthMethod]
    .some((item) => typeof item === "string" && item.toLowerCase().includes(normalized));
}

function normalizeStatus(value: unknown): ApplicationStatus {
  if (value === undefined || value === null || value === "") return "active";
  if (value === "active" || value === "disabled" || value === "archived" || value === "purged") return value;
  return "unknown" as ApplicationStatus;
}

function lifecycleStatusOf(record: { status?: unknown; lifecycleStatus?: unknown }): ApplicationStatus {
  const lifecycle = record.lifecycleStatus;
  if (lifecycle === "active" || lifecycle === "disabled" || lifecycle === "archived" || lifecycle === "purged") {
    return lifecycle;
  }
  return normalizeStatus(record.status);
}

function normalizeApplicationType(value: unknown): "web" | "native" {
  return value === "native" ? "native" : "web";
}

function readinessForRecord(record: { readiness?: unknown; status?: unknown; lifecycleStatus?: unknown; name?: unknown; slug?: unknown; type?: unknown; clientId?: unknown; secretRef?: unknown; componentAppId?: unknown; componentAppSecretRef?: unknown; componentBinding?: unknown; credentialConfigured?: unknown; hasSecret?: unknown; tokenEndpointAuthMethod?: unknown }): "ready" | "not_ready" {
  const status = lifecycleStatusOf(record);
  if (status !== "active") return "not_ready";
  if ("name" in record || "slug" in record) {
    return typeof record.name === "string" && record.name.trim().length > 0 && typeof record.slug === "string" && record.slug.trim().length > 0 ? "ready" : "not_ready";
  }
  if (record.tokenEndpointAuthMethod === "private_key_jwt" || record.tokenEndpointAuthMethod === "none") return "ready";
  if ("componentAppId" in record || "componentAppSecretRef" in record || "componentBinding" in record) {
    return record.credentialConfigured === true || record.hasSecret === true || (typeof record.componentAppSecretRef === "string" && record.componentAppSecretRef.trim().length > 0) || record.componentBinding !== undefined ? "ready" : "not_ready";
  }
  if ("type" in record || "clientId" in record) {
    return record.credentialConfigured === true || record.hasSecret === true || (typeof record.secretRef === "string" && record.secretRef.trim().length > 0) ? "ready" : "not_ready";
  }
  return "ready";
}

function effectiveStatusForRecord(record: { status?: unknown; lifecycleStatus?: unknown; readiness?: unknown; effectiveStatus?: unknown; name?: unknown; slug?: unknown; type?: unknown; clientId?: unknown; secretRef?: unknown; credentialConfigured?: unknown; hasSecret?: unknown; tokenEndpointAuthMethod?: unknown }): string {
  const status = lifecycleStatusOf(record);
  if (status === "archived" || status === "purged") return status;
  return readinessForRecord(record) === "ready" ? status : "not_ready";
}

function nextVersion(value: unknown): number {
  if (typeof value === "number" && Number.isSafeInteger(value) && value >= 0) return value + 1;
  if (typeof value === "string" && /^\d+$/u.test(value)) {
    const parsed = Number(value);
    if (Number.isSafeInteger(parsed) && parsed >= 0) return parsed + 1;
  }
  return 1;
}

function platformComponentFields(input: {
  componentAppId?: string | null;
  componentAppSecretRef?: string | null;
  componentVerifyTicketRef?: string | null;
  componentAccessTokenRef?: string | null;
  authorizedAppId?: string | null;
  authorizerAppId?: string | null;
  authorizerRefreshTokenRef?: string | null;
  authorizerAccessTokenRef?: string | null;
  componentTicketRef?: string | null;
  componentTicketExpiresAt?: string | null;
  componentBindingStatus?: string | null;
  componentBindingVersion?: string | number | null;
  componentScope?: string | null;
  componentBinding?: unknown;
}): Record<string, unknown> {
  return Object.fromEntries(Object.entries(input).filter(([key]) => key.startsWith("component") || key === "authorizedAppId" || key === "authorizerAppId" || key === "authorizerRefreshTokenRef" || key === "authorizerAccessTokenRef").filter(([, value]) => value !== undefined));
}

function stripPlatformComponentSecrets(platform: Record<string, unknown>): void {
  for (const key of ["componentAppSecretRef", "componentVerifyTicketRef", "componentAccessTokenRef", "authorizerRefreshTokenRef", "authorizerAccessTokenRef", "componentTicketRef"]) delete platform[key];
  const binding = platform.componentBinding;
  if (binding !== null && typeof binding === "object" && !Array.isArray(binding)) {
    for (const key of ["componentAppSecretRef", "componentVerifyTicketRef", "componentAccessTokenRef", "authorizerRefreshTokenRef", "authorizerAccessTokenRef", "componentTicketRef"]) delete (binding as Record<string, unknown>)[key];
  }
}

function snapshotOpaqueSessions(repository: OpaqueClientSessionRepository): OpaqueClientSessionRecord[] {
  const snapshot = (repository as OpaqueClientSessionRepository & { snapshot?: () => OpaqueClientSessionRecord[] }).snapshot;
  return typeof snapshot === "function" ? snapshot.call(repository).map((item) => cloneOpaqueRecord(item)) : [];
}

function snapshotWebviewTickets(repository: WebviewTicketRepository): WebviewTicketRecord[] {
  const snapshot = (repository as WebviewTicketRepository & { snapshot?: () => WebviewTicketRecord[] }).snapshot;
  return typeof snapshot === "function" ? snapshot.call(repository).map((item) => cloneWebviewRecord(item)) : [];
}

function cloneOpaqueRecord(record: OpaqueClientSessionRecord): OpaqueClientSessionRecord {
  return cloneValue(record) as OpaqueClientSessionRecord;
}

function cloneWebviewRecord(record: WebviewTicketRecord): WebviewTicketRecord {
  return cloneValue(record) as WebviewTicketRecord;
}

function normalizeOpaqueReference(value: unknown): string {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]{16,512}$/u.test(value)) throw invalidRequest("Opaque reference is invalid");
  return value;
}

function opaqueSessionTtlMilliseconds(value: number | undefined): number {
  const seconds = value ?? 60 * 60 * 24 * 30;
  if (!Number.isSafeInteger(seconds) || seconds < 60 || seconds > 60 * 60 * 24 * 365) throw invalidRequest("Opaque client session lifetime is invalid");
  return seconds * 1000;
}

function webviewTicketTtlMilliseconds(value: number | undefined): number {
  const seconds = value ?? 5 * 60;
  if (!Number.isSafeInteger(seconds) || seconds < 30 || seconds > 15 * 60) throw invalidRequest("Webview ticket lifetime is invalid");
  return seconds * 1000;
}

function hashOpaqueReference(value: unknown): string {
  if (typeof value !== "string" || value.length < 16 || value.length > 512 || /[\u0000-\u001f\u007f]/u.test(value)) throw invalidRequest("Opaque reference is invalid");
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function isApplicationLoopbackHost(hostname: string): boolean {
  return hostname === "localhost" || hostname === "127.0.0.1" || hostname === "[::1]";
}

function normalizeRedirectUriForRecord(value: unknown): string {
  if (typeof value !== "string" || value.length === 0 || value.length > 2048 || value !== value.trim() || /[\u0000-\u001f\u007f\s\\]/u.test(value)) throw invalidRequest("Invalid webview ticket redirect URI");
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw invalidRequest("Invalid webview ticket redirect URI");
  }
  if (
    (parsed.protocol !== "https:" && parsed.protocol !== "http:") ||
    (parsed.protocol !== "https:" && !isApplicationLoopbackHost(parsed.hostname)) ||
    parsed.username !== "" ||
    parsed.password !== "" ||
    parsed.hash !== "" ||
    parsed.hostname.length === 0
  ) throw invalidRequest("Invalid webview ticket redirect URI");
  return value;
}

function normalizeTenantId(value: unknown): string {
  if (value === undefined) return DEFAULT_TENANT_ID;
  if (typeof value !== "string") throw new TypeError("tenantId must be a string");
  const normalized = value.trim();
  if (normalized.length === 0 || normalized.length > 256 || /[\u0000-\u001f\u007f]/u.test(normalized)) {
    throw new TypeError("Invalid tenantId");
  }
  return normalized;
}

function normalizeOptionalExternalText(value: unknown, field: string, maxLength: number): string | undefined {
  if (value === undefined || value === null || value === "") return undefined;
  return normalizeExternalText(value, field, maxLength);
}

function normalizeExternalText(value: unknown, field: string, maxLength: number): string {
  if (typeof value !== "string") throw invalidRequest(`Invalid external identity ${field}`);
  const normalized = value.trim();
  if (normalized.length === 0 || normalized.length > maxLength || /[\u0000-\u001f\u007f]/u.test(normalized)) {
    throw invalidRequest(`Invalid external identity ${field}`);
  }
  return normalized;
}

function validateGeneratedId(value: string): void {
  if (value.length === 0 || value.length > 256 || /[\u0000-\u001f\u007f]/u.test(value)) {
    throw invalidRequest("Invalid resource identifier");
  }
}

function contextValue(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  const normalized = value.trim();
  return normalized.length > 0 && normalized.length <= 512 && !/[\u0000-\u001f\u007f]/u.test(normalized)
    ? normalized
    : undefined;
}

function cloneRecord<T extends AnyRecord>(value: T): T {
  return cloneValue(value) as T;
}

function cloneValue(value: unknown, ancestors: Set<object> = new Set()): unknown {
  if (value === null || typeof value !== "object") return value;
  if (value instanceof Date) return new Date(value.getTime());
  if (ancestors.has(value)) return undefined;
  ancestors.add(value);
  try {
    if (Array.isArray(value)) {
      return value.map((item) => cloneValue(item, ancestors)).filter((item) => item !== undefined);
    }
    const output: AnyRecord = {};
    for (const key of Object.keys(value)) {
      if (key === "__proto__" || key === "prototype" || key === "constructor") continue;
      const item = cloneValue((value as AnyRecord)[key], ancestors);
      if (item !== undefined) output[key] = item;
    }
    return output;
  } finally {
    ancestors.delete(value);
  }
}
