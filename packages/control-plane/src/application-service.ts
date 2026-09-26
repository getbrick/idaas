import { randomUUID } from "node:crypto";
import { hasPermission } from "@getbrick/idaas-core";
import type {
  ApplicationClientRotateSecretRequest,
  ApplicationClientStatus,
  ApplicationClientUpdateRequest,
  ApplicationClientSummary,
  ApplicationExternalIdentitySummary,
  ApplicationPlatformSummary,
  ApplicationPlatformUpdateRequest,
  ApplicationStatus,
  ApplicationSummary,
  ApplicationValidationIssue,
  ApplicationValidationResult,
  ApplicationVersion,
} from "@getbrick/idaas-contracts";
import {
  forbidden,
  internalError,
  invalidRequest,
  conflict,
  notFound,
  unauthenticated,
  ControlPlaneError,
} from "./errors.js";
import {
  parseApplicationClientCreateRequest,
  parseApplicationClientIdentifier,
  parseApplicationClientListQuery,
  parseApplicationClientRotateSecretRequest,
  parseApplicationPlatformRotateSecretRequest,
  parseApplicationClientUpdateRequest,
  parseApplicationCreateRequest,
  parseApplicationExternalIdentityListQuery,
  parseApplicationIdentifier,
  parseApplicationLifecycleActionRequest,
  parseApplicationListQuery,
  parseApplicationPlatformCreateRequest,
  parseApplicationPlatformIdentifier,
  parseApplicationPlatformListQuery,
  parseApplicationPlatformUpdateRequest,
  parseApplicationUpdateRequest,
  validateApplicationPlatformSemantics,
  validateApplicationClientAuthentication,
  validateManagedClientMetadata,
  validateNativeRedirectUris,
} from "./application-validation.js";
import {
  toApplicationClientSummary,
  toApplicationExternalIdentitySummary,
  toApplicationPlatformSummary,
  toApplicationSummary,
} from "./application-dto.js";
import type { SecretBindingRepository } from "./secret-binding.js";
import {
  APPLICATION_MANAGEMENT_PERMISSIONS,
  type ApplicationActor,
  type ApplicationClientRecord,
  type ApplicationExternalIdentityRecord,
  type ApplicationPlatformRecord,
  type ApplicationRecord,
  type ApplicationPage,
  type ApplicationPurgeJob,
  type ApplicationRepository,
  type ApplicationServiceOptions,
  type ApplicationWriteContext,
  type ApplicationMutationRequestContext,
  type ApplicationMutationTransaction,
} from "./application-types.js";

const DEFAULT_PAGE_OPTIONS = { defaultLimit: 20, maxLimit: 100 };
type AnyRecord = Record<string, unknown>;
type ApplicationClientRecordLike = ApplicationClientRecord;
type ApplicationRecordLike = ApplicationRecord;
type ApplicationChildren = {
  platforms: ApplicationPlatformRecord[];
  clients: ApplicationClientRecord[];
  externalIdentities: ApplicationExternalIdentityRecord[];
  total: number;
};

export const APPLICATION_PERMISSIONS = APPLICATION_MANAGEMENT_PERMISSIONS;
export { APPLICATION_MANAGEMENT_PERMISSIONS };

export class ApplicationService {
  private readonly repository: ApplicationRepository;
  private readonly secretBindings?: SecretBindingRepository;
  private readonly requireSecretBindings: boolean;
  private readonly mutationTransaction?: ApplicationMutationTransaction;
  private readonly options: Required<Omit<ApplicationServiceOptions, "secretBindings" | "requireSecretBindings" | "mutationTransaction" | "transaction">>;
  private readonly purgeJobs = new Map<string, ApplicationPurgeJob>();

  constructor(repository: ApplicationRepository, options: ApplicationServiceOptions = {}) {
    this.repository = repository;
    this.secretBindings = options.secretBindings;
    this.requireSecretBindings = options.requireSecretBindings === true;
    this.mutationTransaction = options.mutationTransaction ?? options.transaction;
    this.options = {
      requireActor: options.requireActor ?? true,
      adminRoles: options.adminRoles ?? ["admin"],
      defaultLimit: options.defaultLimit ?? DEFAULT_PAGE_OPTIONS.defaultLimit,
       maxLimit: options.maxLimit ?? DEFAULT_PAGE_OPTIONS.maxLimit,
       allowedClientScopes: options.allowedClientScopes ?? ["openid", "profile", "email", "offline_access"],
       readiness: options.readiness ?? (() => true),
    };
  }

  async listApplications(
    queryOrActor: unknown = {},
    maybeActor?: ApplicationActor,
  ) {
    const invocation = resolveInvocation(queryOrActor, maybeActor);
    this.authorize(APPLICATION_MANAGEMENT_PERMISSIONS.applicationsRead, invocation.actor);
    const query = parseApplicationListQuery(invocation.query, this.pageOptions());
    return this.execute(async () => {
       const page = await this.repository.listApplications(query);
      return filterMappedPage(mapPage(page, toApplicationSummary), query);
    });
  }

  async getApplications(queryOrActor: unknown = {}, maybeActor?: ApplicationActor) {
    return this.listApplications(queryOrActor, maybeActor);
  }

  async getApplication(id: unknown, actor?: ApplicationActor): Promise<ApplicationSummary> {
    const invocation = resolveIdentifierInvocation(id, actor);
    this.authorize(APPLICATION_MANAGEMENT_PERMISSIONS.applicationsRead, invocation.actor);
    const identifier = parseApplicationIdentifier(invocation.id);
    return this.execute(async () => {
      const result = await this.repository.getApplication(identifier);
      if (result === undefined || result === null) throw notFound("Application not found");
      return toApplicationSummary(result);
    });
  }

  async createApplication(
    bodyOrActor: unknown = {},
    actorOrRequest?: unknown,
    request?: ApplicationMutationRequestContext,
  ): Promise<ApplicationSummary> {
    const invocation = resolveWriteInvocation(bodyOrActor, actorOrRequest, request);
    this.authorize(APPLICATION_MANAGEMENT_PERMISSIONS.applicationsWrite, invocation.actor);
    const input = parseApplicationCreateRequest(invocation.body);
    return this.execute(async () => {
      const result = await this.repository.createApplication(input, writeContext(invocation.actor, invocation.request));
      return toApplicationSummary(result);
    });
  }

  async updateApplication(
    id: unknown,
    bodyOrActor: unknown = {},
    actorOrRequest?: unknown,
    request?: ApplicationMutationRequestContext,
  ): Promise<ApplicationSummary> {
    const invocation = resolveWriteInvocation(bodyOrActor, actorOrRequest, request);
    this.authorize(APPLICATION_MANAGEMENT_PERMISSIONS.applicationsWrite, invocation.actor);
    const identifier = parseApplicationIdentifier(id);
    rejectSecretMutation(invocation.body, "application");
    const input = parseApplicationUpdateRequest(invocation.body);
    return this.execute(async () => {
      await this.assertApplicationConfigurable(identifier);
      const current = await this.repository.getApplication(identifier);
      if (current === undefined || current === null) throw notFound("Application not found");
      if (input.applicationType !== undefined && input.applicationType !== normalizeApplicationType(current.applicationType)) {
        const children = await this.applicationChildren(identifier);
        if (children.total > 0) {
          throw conflictWithDetails("Application type cannot be changed while child resources exist", { field: "applicationType" });
        }
      }
      const result = await this.repository.updateApplication(identifier, input, writeContext(invocation.actor, invocation.request));
      return toApplicationSummary(result);
    });
  }

  async enableApplication(
    id: unknown,
    bodyOrActor: unknown = {},
    actorOrRequest?: unknown,
    request?: ApplicationMutationRequestContext,
  ): Promise<ApplicationSummary> {
    return this.changeApplicationStatus("active", id, bodyOrActor, actorOrRequest, request);
  }

  async disableApplication(
    id: unknown,
    bodyOrActor: unknown = {},
    actorOrRequest?: unknown,
    request?: ApplicationMutationRequestContext,
  ): Promise<ApplicationSummary> {
    return this.changeApplicationStatus("disabled", id, bodyOrActor, actorOrRequest, request);
  }

  async archiveApplication(
    id: unknown,
    bodyOrActor: unknown = {},
    actorOrRequest?: unknown,
    request?: ApplicationMutationRequestContext,
  ): Promise<ApplicationSummary> {
    return this.changeApplicationLifecycle("archive", id, bodyOrActor, actorOrRequest, request);
  }

  async restoreApplication(
    id: unknown,
    bodyOrActor: unknown = {},
    actorOrRequest?: unknown,
    request?: ApplicationMutationRequestContext,
  ): Promise<ApplicationSummary> {
    return this.changeApplicationLifecycle("restore", id, bodyOrActor, actorOrRequest, request);
  }

  async purgeApplication(
    id: unknown,
    bodyOrActor: unknown = {},
    actorOrRequest?: unknown,
    request?: ApplicationMutationRequestContext,
  ): Promise<ApplicationPurgeJob> {
    return this.queueApplicationPurge(id, bodyOrActor, actorOrRequest, request);
  }

  async archive(
    id: unknown,
    bodyOrActor: unknown = {},
    actorOrRequest?: unknown,
    request?: ApplicationMutationRequestContext,
  ): Promise<ApplicationSummary> {
    return this.archiveApplication(id, bodyOrActor, actorOrRequest, request);
  }

  async restore(
    id: unknown,
    bodyOrActor: unknown = {},
    actorOrRequest?: unknown,
    request?: ApplicationMutationRequestContext,
  ): Promise<ApplicationSummary> {
    return this.restoreApplication(id, bodyOrActor, actorOrRequest, request);
  }

  async purge(
    id: unknown,
    bodyOrActor: unknown = {},
    actorOrRequest?: unknown,
    request?: ApplicationMutationRequestContext,
  ): Promise<ApplicationPurgeJob> {
    return this.purgeApplication(id, bodyOrActor, actorOrRequest, request);
  }

  async validateApplication(
    id: unknown,
    bodyOrActor: unknown = {},
    actorOrRequest?: unknown,
    request?: ApplicationMutationRequestContext,
  ): Promise<ApplicationValidationResult> {
    const invocation = resolveWriteInvocation(bodyOrActor, actorOrRequest, request);
    this.authorize(APPLICATION_MANAGEMENT_PERMISSIONS.applicationsValidate, invocation.actor);
    const identifier = parseApplicationIdentifier(id);
    const input = parseApplicationLifecycleActionRequest(invocation.body);
    return this.execute(async () => {
      const application = await this.repository.getApplication(identifier);
      if (application === undefined || application === null) throw notFound("Application not found");
       this.assertExpectedVersion(application.version, input.expectedVersion, application.etag);
      const dto = toApplicationSummary(application);
      const issues: ApplicationValidationIssue[] = [];
      if (dto.applicationType !== "web" && dto.applicationType !== "native") {
        issues.push({ code: "invalid_application_type", field: "applicationType", message: "Application type is invalid", severity: "error" });
      }
      if (dto.lifecycleStatus === "purged") {
        issues.push({ code: "application_purged", field: "status", message: "Purged applications cannot be validated for activation", severity: "error" });
      } else if (dto.lifecycleStatus === "archived") {
        issues.push({ code: "application_archived", field: "status", message: "Archived applications must be restored before validation", severity: "error" });
      }
      const children = await this.applicationChildren(identifier);
      for (const value of children.platforms) {
        const platform = toApplicationPlatformSummary(value);
        if (platform.effectiveStatus === "not_ready") {
          issues.push({ code: "platform_not_ready", field: `platforms.${platform.id}`, message: "Application platform is not ready", severity: "warning" });
        }
      }
      for (const value of children.clients) {
        const client = toApplicationClientSummary(value);
        if (client.tokenEndpointAuthMethod === "private_key_jwt" && client.tokenEndpointAuthSigningAlg === undefined) {
          issues.push({ code: "missing_signing_algorithm", field: `clients.${client.id}.tokenEndpointAuthSigningAlg`, message: "private_key_jwt requires a signing algorithm", severity: "error" });
        }
        if (client.tokenEndpointAuthMethod !== "none" && client.tokenEndpointAuthMethod !== "private_key_jwt" && client.secretStatus !== "configured") {
          issues.push({ code: "missing_secret", field: `clients.${client.id}.secretRef`, message: "Client secret is not configured", severity: "error" });
        }
      }
      return validationResult({
        applicationId: identifier,
        applicationType: dto.applicationType,
        readiness: dto.readiness,

        effectiveStatus: dto.effectiveStatus,
        version: dto.version,
        etag: dto.etag,
      }, issues);
    });
  }

  async validateApplicationConfiguration(
    id: unknown,
    bodyOrActor: unknown = {},
    actorOrRequest?: unknown,
    request?: ApplicationMutationRequestContext,
  ): Promise<ApplicationValidationResult> {
    return this.validateApplication(id, bodyOrActor, actorOrRequest, request);
  }

  async setApplicationStatus(
    id: unknown,
    status: unknown,
    bodyOrActor: unknown = {},
    actorOrRequest?: unknown,
    request?: ApplicationMutationRequestContext,
  ): Promise<ApplicationSummary> {
    const normalizedStatus = parseStatus(status);
    if (normalizedStatus === "active") return this.changeApplicationStatus("active", id, bodyOrActor, actorOrRequest, request);
    return this.changeApplicationStatus("disabled", id, bodyOrActor, actorOrRequest, request);
  }

  async deleteApplication(
    id: unknown,
    bodyOrActor: unknown = {},
    actorOrRequest?: unknown,
    request?: ApplicationMutationRequestContext,
  ): Promise<ApplicationSummary> {
    return this.changeApplicationLifecycle("archive", id, bodyOrActor, actorOrRequest, request);
  }

  async listPlatforms(
    applicationId: unknown,
    queryOrActor: unknown = {},
    maybeActor?: ApplicationActor,
  ) {
    const invocation = resolveInvocation(queryOrActor, maybeActor);
    this.authorize(APPLICATION_MANAGEMENT_PERMISSIONS.platformsRead, invocation.actor);
    const identifier = parseApplicationIdentifier(applicationId);
    const query = parseApplicationPlatformListQuery(invocation.query, this.pageOptions());
    return this.execute(async () => {
      await this.assertApplicationExists(identifier);
       const page = await this.repository.listPlatforms(identifier, query);
      return filterMappedPage(mapPage(page, toApplicationPlatformSummary), query);
    });
  }

  async listApplicationPlatforms(
    applicationId: unknown,
    queryOrActor: unknown = {},
    maybeActor?: ApplicationActor,
  ) {
    return this.listPlatforms(applicationId, queryOrActor, maybeActor);
  }

  async getPlatform(
    applicationId: unknown,
    id: unknown,
    actor?: ApplicationActor,
  ): Promise<ApplicationPlatformSummary> {
    const normalizedActor = normalizeActor(actor);
    this.authorize(APPLICATION_MANAGEMENT_PERMISSIONS.platformsRead, normalizedActor);
    const appId = parseApplicationIdentifier(applicationId);
    const platformId = parseApplicationPlatformIdentifier(id);
    return this.execute(async () => {
      await this.assertApplicationExists(appId);
      const result = await this.repository.getPlatform(appId, platformId);
      if (result === undefined || result === null) throw notFound("Application platform not found");
      return toApplicationPlatformSummary(result);
    });
  }

  async validatePlatform(
    applicationId: unknown,
    id: unknown,
    bodyOrActor: unknown = {},
    actorOrRequest?: unknown,
    request?: ApplicationMutationRequestContext,
  ): Promise<ApplicationValidationResult> {
    const invocation = resolveWriteInvocation(bodyOrActor, actorOrRequest, request);
    this.authorize(APPLICATION_MANAGEMENT_PERMISSIONS.platformsValidate, invocation.actor);
    const appId = parseApplicationIdentifier(applicationId);
    const platformId = parseApplicationPlatformIdentifier(id);
    const input = parseApplicationLifecycleActionRequest(invocation.body);
    return this.execute(async () => {
      await this.assertApplicationExists(appId);
      const platform = await this.repository.getPlatform(appId, platformId);
      if (platform === undefined || platform === null) throw notFound("Application platform not found");
       this.assertExpectedVersion(platform.version, input.expectedVersion, platform.etag);
      const dto = toApplicationPlatformSummary(platform);
      const issues: ApplicationValidationIssue[] = [];
      if (dto.lifecycleStatus === "purged") {
        issues.push({ code: "platform_purged", field: "status", message: "Purged platforms cannot be validated", severity: "error" });
      } else if (dto.lifecycleStatus === "archived") {
        issues.push({ code: "platform_archived", field: "status", message: "Archived platforms must be restored before validation", severity: "error" });
      }
      if (dto.type === "web" && dto.redirectUris.length === 0) {
        issues.push({ code: "missing_redirect_uri", field: "redirectUris", message: "Web platform requires at least one redirect URI", severity: "warning" });
      }
      return validationResult({ applicationId: appId, readiness: dto.readiness, effectiveStatus: dto.effectiveStatus, version: dto.version, etag: dto.etag }, issues);
    });
  }

  async rotatePlatformSecret(
    applicationId: unknown,
    id: unknown,
    bodyOrActor: unknown = {},
    actorOrRequest?: unknown,
    request?: ApplicationMutationRequestContext,
  ): Promise<ApplicationPlatformSummary> {
    const invocation = resolveWriteInvocation(bodyOrActor, actorOrRequest, request);
    this.authorize(APPLICATION_MANAGEMENT_PERMISSIONS.platformsRotateSecret, invocation.actor);
    const appId = parseApplicationIdentifier(applicationId);
    const platformId = parseApplicationPlatformIdentifier(id);
    const input = parseApplicationPlatformRotateSecretRequest(invocation.body);
    return this.execute(() => this.runAtomic(async () => {
      await this.assertApplicationConfigurable(appId);
       const current = await this.repository.getPlatform(appId, platformId);
       if (current === undefined || current === null) throw notFound("Application platform not found");
       if (lifecycleStatusOf(current) === "archived" || lifecycleStatusOf(current) === "purged") {
         throw conflict("Archived application platforms cannot be modified");
       }
       const expectedVersion = this.requiredExpectedVersion(
        input.expectedVersion,
        invocation.request,
        current.version,
        current.etag,
        "platform",
      );
      if (input.secretRef === undefined) throw conflict("A new secretRef is required to rotate a platform secret");
       let result = await this.repository.updatePlatform(
         appId,
         platformId,
         { secretRef: input.secretRef },
         writeContext(invocation.actor, invocation.request),
       );
       try {
         await this.syncSecretBinding(
           "application-platform",
           platformId,
           "platform-secret",
           input.secretRef,
           current.secretVersion,
           expectedVersion,
         );
       } catch (error) {
         if (!this.hasAtomicTransaction()) {
           await this.restorePlatformSecretReference(appId, platformId, current.secretRef, writeContext(invocation.actor, invocation.request));
         }
         throw error;
       }
       if (this.secretBindings !== undefined) {
         result = (await this.repository.getPlatform(appId, platformId)) ?? result;
       }
       return toApplicationPlatformSummary(result);
     }));
  }

  async rotateApplicationPlatformSecret(
    applicationId: unknown,
    id: unknown,
    bodyOrActor: unknown = {},
    actorOrRequest?: unknown,
    request?: ApplicationMutationRequestContext,
  ): Promise<ApplicationPlatformSummary> {
    return this.rotatePlatformSecret(applicationId, id, bodyOrActor, actorOrRequest, request);
  }

  async revokePlatformSecret(
    applicationId: unknown,
    id: unknown,
    bodyOrActor: unknown = {},
    actorOrRequest?: unknown,
    request?: ApplicationMutationRequestContext,
  ): Promise<ApplicationPlatformSummary> {
    const invocation = resolveWriteInvocation(bodyOrActor, actorOrRequest, request);
    this.authorize(APPLICATION_MANAGEMENT_PERMISSIONS.platformsRevokeSecret, invocation.actor);
    const appId = parseApplicationIdentifier(applicationId);
    const platformId = parseApplicationPlatformIdentifier(id);
    const input = parseApplicationLifecycleActionRequest(invocation.body);
    return this.execute(() => this.runAtomic(async () => {
      await this.assertApplicationConfigurable(appId);
       const current = await this.repository.getPlatform(appId, platformId);
       if (current === undefined || current === null) throw notFound("Application platform not found");
       if (lifecycleStatusOf(current) === "archived" || lifecycleStatusOf(current) === "purged") {
         throw conflict("Archived application platforms cannot be modified");
       }
       this.requiredExpectedVersion(input.expectedVersion, invocation.request, current.version, current.etag, "platform");
      const updated = await this.repository.updatePlatform(
        appId,
        platformId,
        { secretRef: null } as unknown as ApplicationPlatformUpdateRequest,
        writeContext(invocation.actor, invocation.request),
      );
       const binding = await this.findSecretBinding("application-platform", current.id, "platform-secret");
       if (binding) {
         try {
              await this.revokeSecretBindings("application-platform", current.id, "platform-secret");
         } catch (error) {
           if (!this.hasAtomicTransaction()) {
             await this.restorePlatformSecretReference(appId, platformId, current.secretRef, writeContext(invocation.actor, invocation.request));
           }
           throw error;
         }
       }
       return toApplicationPlatformSummary({
        ...updated,
        credentialConfigured: false,
        secretStatus: "revoked",
        secretVersion: nextSecretVersion(current.secretVersion),
        readiness: "not_ready",
        effectiveStatus: "not_ready",
      });
    }));
  }

  async revokeApplicationPlatformSecret(
    applicationId: unknown,
    id: unknown,
    bodyOrActor: unknown = {},
    actorOrRequest?: unknown,
    request?: ApplicationMutationRequestContext,
  ): Promise<ApplicationPlatformSummary> {
    return this.revokePlatformSecret(applicationId, id, bodyOrActor, actorOrRequest, request);
  }

  async validateApplicationPlatform(
    applicationId: unknown,
    id: unknown,
    bodyOrActor: unknown = {},
    actorOrRequest?: unknown,
    request?: ApplicationMutationRequestContext,
  ): Promise<ApplicationValidationResult> {
    return this.validatePlatform(applicationId, id, bodyOrActor, actorOrRequest, request);
  }

  async createPlatform(
    applicationId: unknown,
    bodyOrActor: unknown = {},
    actorOrRequest?: unknown,
    request?: ApplicationMutationRequestContext,
  ): Promise<ApplicationPlatformSummary> {
    const invocation = resolveWriteInvocation(bodyOrActor, actorOrRequest, request);
    this.authorize(APPLICATION_MANAGEMENT_PERMISSIONS.platformsWrite, invocation.actor);
    const appId = parseApplicationIdentifier(applicationId);
    const application = await this.repository.getApplication(appId);
    if (application === undefined || application === null) throw notFound("Application not found");
    const applicationType = application.applicationType === "native" || application.applicationType === "web" ? application.applicationType : undefined;
    const input = parseApplicationPlatformCreateRequest(invocation.body, { applicationType });
    return this.execute(async () => {
      await this.assertApplicationConfigurable(appId);
       let result = await this.runAtomic(async () => {
         const created = await this.repository.createPlatform(appId, input, writeContext(invocation.actor, invocation.request));
         try {
           if (input.secretRef !== undefined) {
             await this.syncSecretBinding("application-platform", created.id, "platform-secret", input.secretRef);
           }
           return created;
         } catch (error) {
           if (!this.hasAtomicTransaction()) {
             try {
               await this.repository.deletePlatform(appId, created.id, writeContext(invocation.actor, invocation.request));
             } catch {
               throw internalError();
             }
           }
           throw error;
         }
       });
       if (this.secretBindings !== undefined) {
         result = (await this.repository.getPlatform(appId, result.id)) ?? result;
       }
       return toApplicationPlatformSummary(result);

    });
  }

  async createApplicationPlatform(
    applicationId: unknown,
    bodyOrActor: unknown = {},
    actorOrRequest?: unknown,
    request?: ApplicationMutationRequestContext,
  ): Promise<ApplicationPlatformSummary> {
    return this.createPlatform(applicationId, bodyOrActor, actorOrRequest, request);
  }

  async updatePlatform(
    applicationId: unknown,
    id: unknown,
    bodyOrActor: unknown = {},
    actorOrRequest?: unknown,
    request?: ApplicationMutationRequestContext,
  ): Promise<ApplicationPlatformSummary> {
    const invocation = resolveWriteInvocation(bodyOrActor, actorOrRequest, request);
    this.authorize(APPLICATION_MANAGEMENT_PERMISSIONS.platformsWrite, invocation.actor);
    const appId = parseApplicationIdentifier(applicationId);
    const platformId = parseApplicationPlatformIdentifier(id);
    rejectSecretMutation(invocation.body, "platform");
    return this.execute(async () => {
      await this.assertApplicationConfigurable(appId);
      const current = await this.repository.getPlatform(appId, platformId);
      if (current === undefined || current === null) throw notFound("Application platform not found");
      const application = await this.repository.getApplication(appId);
      if (application === undefined || application === null) throw notFound("Application not found");
      const applicationType = application.applicationType === "native" || application.applicationType === "web" ? application.applicationType : undefined;
      const input = parseApplicationPlatformUpdateRequest(invocation.body, { applicationType });
      validateApplicationPlatformSemantics({
        type: input.type ?? current.type,
        externalAppId: input.externalAppId ?? current.externalAppId,
        loginMode: input.loginMode ?? current.loginMode,
        scope: input.scope ?? current.scope,
      }, true);
      const result = await this.repository.updatePlatform(appId, platformId, input, writeContext(invocation.actor, invocation.request));
      return toApplicationPlatformSummary(result);
    });
  }

  async updateApplicationPlatform(
    applicationId: unknown,
    id: unknown,
    bodyOrActor: unknown = {},
    actorOrRequest?: unknown,
    request?: ApplicationMutationRequestContext,
  ): Promise<ApplicationPlatformSummary> {
    return this.updatePlatform(applicationId, id, bodyOrActor, actorOrRequest, request);
  }

  async archivePlatform(
    applicationId: unknown,
    id: unknown,
    bodyOrActor: unknown = {},
    actorOrRequest?: unknown,
    request?: ApplicationMutationRequestContext,
  ): Promise<ApplicationPlatformSummary> {
    return this.changePlatformLifecycle("archive", applicationId, id, bodyOrActor, actorOrRequest, request);
  }

  async restorePlatform(
    applicationId: unknown,
    id: unknown,
    bodyOrActor: unknown = {},
    actorOrRequest?: unknown,
    request?: ApplicationMutationRequestContext,
  ): Promise<ApplicationPlatformSummary> {
    return this.changePlatformLifecycle("restore", applicationId, id, bodyOrActor, actorOrRequest, request);
  }

  async purgePlatform(
    applicationId: unknown,
    id: unknown,
    bodyOrActor: unknown = {},
    actorOrRequest?: unknown,
    request?: ApplicationMutationRequestContext,
  ): Promise<ApplicationPurgeJob> {
    return this.queueChildPurge("application-platform", applicationId, id, bodyOrActor, actorOrRequest, request);
  }

  async enablePlatform(
    applicationId: unknown,
    id: unknown,
    bodyOrActor: unknown = {},
    actorOrRequest?: unknown,
    request?: ApplicationMutationRequestContext,
  ): Promise<ApplicationPlatformSummary> {
    return this.changePlatformStatus("active", applicationId, id, bodyOrActor, actorOrRequest, request);
  }

  async disablePlatform(
    applicationId: unknown,
    id: unknown,
    bodyOrActor: unknown = {},
    actorOrRequest?: unknown,
    request?: ApplicationMutationRequestContext,
  ): Promise<ApplicationPlatformSummary> {
    return this.changePlatformStatus("disabled", applicationId, id, bodyOrActor, actorOrRequest, request);
  }

  async deletePlatform(
    applicationId: unknown,
    id: unknown,
    bodyOrActor: unknown = {},
    actorOrRequest?: unknown,
    request?: ApplicationMutationRequestContext,
  ): Promise<ApplicationPlatformSummary> {
    return this.changePlatformLifecycle("archive", applicationId, id, bodyOrActor, actorOrRequest, request);
  }

  async listExternalIdentities(
    applicationId: unknown,
    queryOrActor: unknown = {},
    maybeActor?: ApplicationActor,
  ): Promise<ApplicationPage<ApplicationExternalIdentitySummary>> {
    const invocation = resolveInvocation(queryOrActor, maybeActor);
    this.authorize(APPLICATION_MANAGEMENT_PERMISSIONS.externalIdentitiesRead, invocation.actor);
    const appId = parseApplicationIdentifier(applicationId);
    const query = parseApplicationExternalIdentityListQuery(invocation.query, this.pageOptions());
    return this.execute(async () => {
      await this.assertApplicationExists(appId);
      const list = this.repository.listExternalIdentities;
      if (typeof list !== "function") throw conflict("External identity storage is not supported");
      const page = await list.call(this.repository, appId, query);
      return mapPage(page, toApplicationExternalIdentitySummary);
    });
  }

  async listApplicationExternalIdentities(
    applicationId: unknown,
    queryOrActor: unknown = {},
    maybeActor?: ApplicationActor,
  ): Promise<ApplicationPage<ApplicationExternalIdentitySummary>> {
    return this.listExternalIdentities(applicationId, queryOrActor, maybeActor);
  }

  async listClients(
    applicationId: unknown,
    queryOrActor: unknown = {},
    maybeActor?: ApplicationActor,
  ) {
    const invocation = resolveInvocation(queryOrActor, maybeActor);
    this.authorize(APPLICATION_MANAGEMENT_PERMISSIONS.clientsRead, invocation.actor);
    const identifier = parseApplicationIdentifier(applicationId);
    const query = parseApplicationClientListQuery(invocation.query, this.pageOptions());
    return this.execute(async () => {
      await this.assertApplicationExists(identifier);
       const page = await this.repository.listClients(identifier, query);
      return filterMappedPage(mapPage(page, toApplicationClientSummary), query);
    });
  }

  async listApplicationClients(
    applicationId: unknown,
    queryOrActor: unknown = {},
    maybeActor?: ApplicationActor,
  ) {
    return this.listClients(applicationId, queryOrActor, maybeActor);
  }

  async listOidcClients(
    applicationId: unknown,
    queryOrActor: unknown = {},
    maybeActor?: ApplicationActor,
  ) {
    return this.listClients(applicationId, queryOrActor, maybeActor);
  }

  async listOIDCClients(
    applicationId: unknown,
    queryOrActor: unknown = {},
    maybeActor?: ApplicationActor,
  ) {
    return this.listClients(applicationId, queryOrActor, maybeActor);
  }

  async getClient(
    applicationId: unknown,
    id: unknown,
    actor?: ApplicationActor,
  ): Promise<ApplicationClientSummary> {
    const normalizedActor = normalizeActor(actor);
    this.authorize(APPLICATION_MANAGEMENT_PERMISSIONS.clientsRead, normalizedActor);
    const appId = parseApplicationIdentifier(applicationId);
    const clientRecordId = parseApplicationClientIdentifier(id);
    return this.execute(async () => {
      await this.assertApplicationExists(appId);
      const result = await this.repository.getClient(appId, clientRecordId);
      if (result === undefined || result === null) throw notFound("OIDC client not found");
      return toApplicationClientSummary(result);
    });
  }

  async getOidcClient(
    applicationId: unknown,
    id: unknown,
    actor?: ApplicationActor,
  ): Promise<ApplicationClientSummary> {
    return this.getClient(applicationId, id, actor);
  }

  async getOIDCClient(
    applicationId: unknown,
    id: unknown,
    actor?: ApplicationActor,
  ): Promise<ApplicationClientSummary> {
    return this.getClient(applicationId, id, actor);
  }

  async validateClient(
    applicationId: unknown,
    id: unknown,
    bodyOrActor: unknown = {},
    actorOrRequest?: unknown,
    request?: ApplicationMutationRequestContext,
  ): Promise<ApplicationValidationResult> {
    const invocation = resolveWriteInvocation(bodyOrActor, actorOrRequest, request);
    this.authorize(APPLICATION_MANAGEMENT_PERMISSIONS.clientsValidate, invocation.actor);
    const appId = parseApplicationIdentifier(applicationId);
    const clientId = parseApplicationClientIdentifier(id);
    const input = parseApplicationLifecycleActionRequest(invocation.body);
    return this.execute(async () => {
      await this.assertApplicationExists(appId);
      const client = await this.repository.getClient(appId, clientId);
      if (client === undefined || client === null) throw notFound("OIDC client not found");
       this.assertExpectedVersion(client.version, input.expectedVersion, client.etag);
      const dto = toApplicationClientSummary(client);
      const issues: ApplicationValidationIssue[] = [];
      if (dto.tokenEndpointAuthMethod === "private_key_jwt") {
        if (dto.tokenEndpointAuthSigningAlg === undefined) {
          issues.push({ code: "missing_signing_algorithm", field: "tokenEndpointAuthSigningAlg", message: "private_key_jwt requires a signing algorithm", severity: "error" });
        }
        if (dto.jwksUri === undefined && dto.keyId === undefined && (client.privateKeyRef === undefined || client.privateKeyRef === null)) {
          issues.push({ code: "missing_public_key", field: "jwksUri", message: "private_key_jwt requires a public key reference", severity: "error" });
        }
      }
      if (dto.tokenEndpointAuthMethod !== "none" && dto.tokenEndpointAuthMethod !== "private_key_jwt" && dto.secretStatus !== "configured") {
        issues.push({ code: "missing_secret", field: "secretRef", message: "Client secret is not configured", severity: "error" });
      }
      if (dto.requirePkce !== true) {
        issues.push({ code: "pkce_required", field: "requirePkce", message: "Managed OIDC clients require PKCE", severity: "error" });
      }
      return validationResult({ ...dto, applicationId: appId }, issues);
    });
  }

  async validateOidcClient(
    applicationId: unknown,
    id: unknown,
    bodyOrActor: unknown = {},
    actorOrRequest?: unknown,
    request?: ApplicationMutationRequestContext,
  ): Promise<ApplicationValidationResult> {
    return this.validateClient(applicationId, id, bodyOrActor, actorOrRequest, request);
  }

  async validateOIDCClient(
    applicationId: unknown,
    id: unknown,
    bodyOrActor: unknown = {},
    actorOrRequest?: unknown,
    request?: ApplicationMutationRequestContext,
  ): Promise<ApplicationValidationResult> {
    return this.validateClient(applicationId, id, bodyOrActor, actorOrRequest, request);
  }

  async rotateClientSecret(
    applicationId: unknown,
    id: unknown,
    bodyOrActor: unknown = {},
    actorOrRequest?: unknown,
    request?: ApplicationMutationRequestContext,
  ): Promise<ApplicationClientSummary> {
    const invocation = resolveWriteInvocation(bodyOrActor, actorOrRequest, request);
    this.authorize(APPLICATION_MANAGEMENT_PERMISSIONS.clientsRotateSecret, invocation.actor);
    const appId = parseApplicationIdentifier(applicationId);
    const clientId = parseApplicationClientIdentifier(id);
    const input = parseApplicationClientRotateSecretRequest(invocation.body);
    return this.execute(() => this.runAtomic(async () => {
      await this.assertApplicationConfigurable(appId);
      const current = await this.repository.getClient(appId, clientId);
      if (current === undefined || current === null) throw notFound("OIDC client not found");
      if (lifecycleStatusOf(current) === "archived" || lifecycleStatusOf(current) === "purged") {
        throw conflict("Archived OIDC clients cannot be modified");
      }
      const expectedVersion = this.requiredExpectedVersion(
        input.expectedVersion,
        invocation.request,
        current.version,
        current.etag,
        "client",
      );
      const authMethod = current.tokenEndpointAuthMethod ?? clientAuthMethod(current);
      if (authMethod === "none" || authMethod === "private_key_jwt") {
        throw conflict("This client does not use a rotatable shared secret");
      }
      const rotate = this.repository.rotateClientSecret ?? this.repository.rotateApplicationClientSecret ?? this.repository.rotateSecret;
      let result: ApplicationClientRecordLike | undefined;
      if (typeof rotate === "function") {
        result = await rotate.call(
          this.repository,
          appId,
          clientId,
          { ...input, expectedVersion },
          writeContext(invocation.actor, invocation.request),
        );
      } else {
        result = await this.repository.updateClient(
          appId,
          clientId,
          { secretRef: input.secretRef },
          writeContext(invocation.actor, invocation.request),
        );
      }
      if (result === undefined || result === null) throw internalError();
       try {
         await this.syncSecretBinding(
           "application-client",
           result.id,
           "oidc-client-secret",
           input.secretRef,
           current.secretVersion,
           expectedVersion,
         );
       } catch (error) {
         if (!this.hasAtomicTransaction()) {
           await this.restoreClientSecretReference(appId, clientId, current.secretRef, writeContext(invocation.actor, invocation.request));
         }
         throw error;
       }
       if (this.secretBindings !== undefined) {
         result = (await this.repository.getClient(appId, clientId)) ?? result;
       }
       return toApplicationClientSummary(result as ApplicationClientRecordLike);
     }));
  }

  async rotateApplicationClientSecret(
    applicationId: unknown,
    id: unknown,
    bodyOrActor: unknown = {},
    actorOrRequest?: unknown,
    request?: ApplicationMutationRequestContext,
  ): Promise<ApplicationClientSummary> {
    return this.rotateClientSecret(applicationId, id, bodyOrActor, actorOrRequest, request);
  }

  async rotateOidcClientSecret(
    applicationId: unknown,
    id: unknown,
    bodyOrActor: unknown = {},
    actorOrRequest?: unknown,
    request?: ApplicationMutationRequestContext,
  ): Promise<ApplicationClientSummary> {
    return this.rotateClientSecret(applicationId, id, bodyOrActor, actorOrRequest, request);
  }

  async revokeClientSecret(
    applicationId: unknown,
    id: unknown,
    bodyOrActor: unknown = {},
    actorOrRequest?: unknown,
    request?: ApplicationMutationRequestContext,
  ): Promise<ApplicationClientSummary> {
    const invocation = resolveWriteInvocation(bodyOrActor, actorOrRequest, request);
    this.authorize(APPLICATION_MANAGEMENT_PERMISSIONS.clientsRevokeSecret, invocation.actor);
    const appId = parseApplicationIdentifier(applicationId);
    const clientId = parseApplicationClientIdentifier(id);
    const input = parseApplicationLifecycleActionRequest(invocation.body);
    return this.execute(() => this.runAtomic(async () => {
      await this.assertApplicationConfigurable(appId);
      const current = await this.repository.getClient(appId, clientId);
      if (current === undefined || current === null) throw notFound("OIDC client not found");
      if (lifecycleStatusOf(current) === "archived" || lifecycleStatusOf(current) === "purged") {
        throw conflict("Archived OIDC clients cannot be modified");
      }
      const expectedVersion = this.requiredExpectedVersion(
        input.expectedVersion,
        invocation.request,
        current.version,
        current.etag,
        "client",
      );
      const authMethod = current.tokenEndpointAuthMethod ?? clientAuthMethod(current);
      if (authMethod === "none" || authMethod === "private_key_jwt") {
        throw conflict("This client does not use a revocable shared secret");
      }
      const updated = await this.repository.updateClient(
        appId,
        clientId,
        { secretRef: null } as unknown as ApplicationClientUpdateRequest,
        writeContext(invocation.actor, invocation.request),
      );
        const binding = await this.findSecretBinding("application-client", current.id, "oidc-client-secret");
        if (binding) {
          try {
              await this.revokeSecretBindings("application-client", current.id, "oidc-client-secret");
         } catch (error) {
           if (!this.hasAtomicTransaction()) {
             await this.restoreClientSecretReference(appId, clientId, current.secretRef, writeContext(invocation.actor, invocation.request));
           }
           throw error;
         }
       }
       return toApplicationClientSummary({
        ...updated,
        secretStatus: "revoked",
        hasSecret: false,
        secretVersion: nextSecretVersion(current.secretVersion),
        readiness: "not_ready",
        effectiveStatus: "not_ready",
        version: updated.version ?? expectedVersion,
      });
    }));
  }

  async revokeApplicationClientSecret(
    applicationId: unknown,
    id: unknown,
    bodyOrActor: unknown = {},
    actorOrRequest?: unknown,
    request?: ApplicationMutationRequestContext,
  ): Promise<ApplicationClientSummary> {
    return this.revokeClientSecret(applicationId, id, bodyOrActor, actorOrRequest, request);
  }

  async revokeOidcClientSecret(
    applicationId: unknown,
    id: unknown,
    bodyOrActor: unknown = {},
    actorOrRequest?: unknown,
    request?: ApplicationMutationRequestContext,
  ): Promise<ApplicationClientSummary> {
    return this.revokeClientSecret(applicationId, id, bodyOrActor, actorOrRequest, request);
  }

  async createClient(
    applicationId: unknown,
    bodyOrActor: unknown = {},
    actorOrRequest?: unknown,
    request?: ApplicationMutationRequestContext,
  ): Promise<ApplicationClientSummary> {
    const invocation = resolveWriteInvocation(bodyOrActor, actorOrRequest, request);
    this.authorize(APPLICATION_MANAGEMENT_PERMISSIONS.clientsWrite, invocation.actor);
    const appId = parseApplicationIdentifier(applicationId);
    return this.execute(async () => {
      const application = await this.repository.getApplication(appId);
      if (application === undefined || application === null) throw notFound("Application not found");
      if (lifecycleStatusOf(application) === "archived" || lifecycleStatusOf(application) === "purged") throw conflict("Archived applications cannot be modified");
      const applicationType = application.applicationType === "native" ? "native" : "web";
      const input = parseApplicationClientCreateRequest(invocation.body, { applicationType });
      validateApplicationClientAuthentication(input, true);
      const unsupportedScope = (input.scopes ?? ["openid", "profile", "email"]).find(
        (scope) => !this.options.allowedClientScopes.includes(scope),
      );
      if (unsupportedScope !== undefined) {
        throw invalidRequest("Unsupported OIDC client scope", { field: "scopes" });
      }
        let result = await this.runAtomic(async () => {
          const created = await this.repository.createClient(appId, input, writeContext(invocation.actor, invocation.request));
          try {
            if (input.secretRef !== undefined && input.tokenEndpointAuthMethod !== "private_key_jwt" && input.tokenEndpointAuthMethod !== "none") {
              await this.syncSecretBinding("application-client", created.id, "oidc-client-secret", input.secretRef);
            }
            return created;
          } catch (error) {
            if (!this.hasAtomicTransaction()) {
              try {
                await this.repository.deleteClient(appId, created.id, writeContext(invocation.actor, invocation.request));
              } catch {
                throw internalError();
              }
            }
            throw error;
          }
        });
        if (this.secretBindings !== undefined) {
          result = (await this.repository.getClient(appId, result.id)) ?? result;
        }
        return toApplicationClientSummary(result);

    });
  }

  async createApplicationClient(
    applicationId: unknown,
    bodyOrActor: unknown = {},
    actorOrRequest?: unknown,
    request?: ApplicationMutationRequestContext,
  ): Promise<ApplicationClientSummary> {
    return this.createClient(applicationId, bodyOrActor, actorOrRequest, request);
  }

  async createOidcClient(
    applicationId: unknown,
    bodyOrActor: unknown = {},
    actorOrRequest?: unknown,
    request?: ApplicationMutationRequestContext,
  ): Promise<ApplicationClientSummary> {
    return this.createClient(applicationId, bodyOrActor, actorOrRequest, request);
  }

  async updateClient(
    applicationId: unknown,
    id: unknown,
    bodyOrActor: unknown = {},
    actorOrRequest?: unknown,
    request?: ApplicationMutationRequestContext,
  ): Promise<ApplicationClientSummary> {
    const invocation = resolveWriteInvocation(bodyOrActor, actorOrRequest, request);
    this.authorize(APPLICATION_MANAGEMENT_PERMISSIONS.clientsWrite, invocation.actor);
    const appId = parseApplicationIdentifier(applicationId);
    const clientRecordId = parseApplicationClientIdentifier(id);
    rejectSecretMutation(invocation.body, "client");
    if (hasOwnProperty(invocation.body, "clientId")) {
      throw invalidRequest("clientId is immutable", { field: "clientId" });
    }
    return this.execute(async () => {
      const application = await this.repository.getApplication(appId);
      if (application === undefined || application === null) throw notFound("Application not found");
       await this.assertApplicationConfigurable(appId);
       const applicationType: "web" | "native" = application.applicationType === "native" ? "native" : "web";
       const input = parseApplicationClientUpdateRequest(invocation.body, { applicationType });
      const current = await this.repository.getClient(appId, clientRecordId);
      if (current === undefined || current === null) throw notFound("OIDC client not found");
      this.assertExpectedVersion(current.version, expectedVersionFromRequest(invocation.request), current.etag);
      const authMethod = input.tokenEndpointAuthMethod ?? current.tokenEndpointAuthMethod ?? clientAuthMethod(current);
      const requirePkce = input.requirePkce ?? current.requirePkce ?? true;
      if (requirePkce === false) {
        throw invalidRequest("Managed OIDC clients require PKCE", { field: "requirePkce" });
      }
       const inputRecord = input as unknown as Record<string, unknown>;
       const currentRecord = current as unknown as Record<string, unknown>;
       const redirectPolicy = inputRecord.redirectPolicy ?? currentRecord.redirectPolicy;
       const pkce = inputRecord.pkce ?? currentRecord.pkce;
       const authInput = {
         applicationType,
         clientKind: input.clientKind ?? current.clientKind ?? current.clientType,
         clientType: input.clientType ?? current.clientType ?? current.clientKind,
         tokenEndpointAuthMethod: authMethod,
         tokenEndpointAuthSigningAlg: input.tokenEndpointAuthSigningAlg ?? current.tokenEndpointAuthSigningAlg ?? undefined,
         jwksUri: input.jwksUri ?? current.jwksUri ?? undefined,
         privateKeyRef: input.privateKeyRef ?? current.privateKeyRef ?? undefined,
         keyId: input.keyId ?? current.keyId ?? undefined,
         secretRef: current.secretRef ?? undefined,
         hasSecret: current.hasSecret,
         secretStatus: current.secretStatus,
         redirectUriPolicy: input.redirectUriPolicy ?? current.redirectUriPolicy,
         redirectPolicy: redirectPolicy as { mode: "exact"; exact: true } | undefined,
         pkce: pkce as { required: true; method: "S256" } | undefined,
         pkceMethod: input.pkceMethod ?? current.pkceMethod,
         consent: input.consent ?? current.consent,
         consentRequired: input.consentRequired ?? current.consentRequired,
         requireExplicitConsent: input.requireExplicitConsent ?? current.requireExplicitConsent,
         rpClient: input.rpClient ?? current.rpClient,
       };
      validateApplicationClientAuthentication(authInput, authMethod !== "private_key_jwt");
      const grantTypes = input.grantTypes ?? current.grantTypes ?? ["authorization_code"];
      const responseTypes = input.responseTypes ?? current.responseTypes ?? ["code"];
      const scopes = input.scopes ?? current.scopes ?? ["openid", "profile", "email"];
      validateManagedClientMetadata({ grantTypes, responseTypes, scopes });
      const unsupportedScope = scopes.find((scope) => !this.options.allowedClientScopes.includes(scope));
      if (unsupportedScope !== undefined) {
        throw invalidRequest("Unsupported OIDC client scope", { field: "scopes" });
      }
      const redirectUris = input.redirectUris ?? current.redirectUris ?? [];
      const postLogoutRedirectUris = input.postLogoutRedirectUris ?? current.postLogoutRedirectUris ?? [];
      validateNativeRedirectUris(redirectUris, authMethod, applicationType);
      validateNativeRedirectUris(postLogoutRedirectUris, authMethod, applicationType);
      if (redirectUris.length === 0) {
        throw invalidRequest("Authorization-code clients require at least one redirect URI", { field: "redirectUris" });
      }
      const result = await this.repository.updateClient(appId, clientRecordId, input, writeContext(invocation.actor, invocation.request));
      return toApplicationClientSummary(result);
    });
  }

  async updateApplicationClient(
    applicationId: unknown,
    id: unknown,
    bodyOrActor: unknown = {},
    actorOrRequest?: unknown,
    request?: ApplicationMutationRequestContext,
  ): Promise<ApplicationClientSummary> {
    return this.updateClient(applicationId, id, bodyOrActor, actorOrRequest, request);
  }

  async updateOidcClient(
    applicationId: unknown,
    id: unknown,
    bodyOrActor: unknown = {},
    actorOrRequest?: unknown,
    request?: ApplicationMutationRequestContext,
  ): Promise<ApplicationClientSummary> {
    return this.updateClient(applicationId, id, bodyOrActor, actorOrRequest, request);
  }

  async updateOIDCClient(
    applicationId: unknown,
    id: unknown,
    bodyOrActor: unknown = {},
    actorOrRequest?: unknown,
    request?: ApplicationMutationRequestContext,
  ): Promise<ApplicationClientSummary> {
    return this.updateClient(applicationId, id, bodyOrActor, actorOrRequest, request);
  }

  async archiveClient(
    applicationId: unknown,
    id: unknown,
    bodyOrActor: unknown = {},
    actorOrRequest?: unknown,
    request?: ApplicationMutationRequestContext,
  ): Promise<ApplicationClientSummary> {
    return this.changeClientLifecycle("archive", applicationId, id, bodyOrActor, actorOrRequest, request);
  }

  async restoreClient(
    applicationId: unknown,
    id: unknown,
    bodyOrActor: unknown = {},
    actorOrRequest?: unknown,
    request?: ApplicationMutationRequestContext,
  ): Promise<ApplicationClientSummary> {
    return this.changeClientLifecycle("restore", applicationId, id, bodyOrActor, actorOrRequest, request);
  }

  async purgeClient(
    applicationId: unknown,
    id: unknown,
    bodyOrActor: unknown = {},
    actorOrRequest?: unknown,
    request?: ApplicationMutationRequestContext,
  ): Promise<ApplicationPurgeJob> {
    return this.queueChildPurge("application-client", applicationId, id, bodyOrActor, actorOrRequest, request);
  }

  async enableClient(
    applicationId: unknown,
    id: unknown,
    bodyOrActor: unknown = {},
    actorOrRequest?: unknown,
    request?: ApplicationMutationRequestContext,
  ): Promise<ApplicationClientSummary> {
    return this.changeClientStatus("active", applicationId, id, bodyOrActor, actorOrRequest, request);
  }

  async disableClient(
    applicationId: unknown,
    id: unknown,
    bodyOrActor: unknown = {},
    actorOrRequest?: unknown,
    request?: ApplicationMutationRequestContext,
  ): Promise<ApplicationClientSummary> {
    return this.changeClientStatus("disabled", applicationId, id, bodyOrActor, actorOrRequest, request);
  }

  async enableOidcClient(
    applicationId: unknown,
    id: unknown,
    bodyOrActor: unknown = {},
    actorOrRequest?: unknown,
    request?: ApplicationMutationRequestContext,
  ): Promise<ApplicationClientSummary> {
    return this.enableClient(applicationId, id, bodyOrActor, actorOrRequest, request);
  }

  async disableOidcClient(
    applicationId: unknown,
    id: unknown,
    bodyOrActor: unknown = {},
    actorOrRequest?: unknown,
    request?: ApplicationMutationRequestContext,
  ): Promise<ApplicationClientSummary> {
    return this.disableClient(applicationId, id, bodyOrActor, actorOrRequest, request);
  }

  async deleteClient(
    applicationId: unknown,
    id: unknown,
    bodyOrActor: unknown = {},
    actorOrRequest?: unknown,
    request?: ApplicationMutationRequestContext,
  ): Promise<ApplicationClientSummary> {
    return this.changeClientLifecycle("archive", applicationId, id, bodyOrActor, actorOrRequest, request);
  }

  private async changeApplicationStatus(
    status: ApplicationStatus,
    id: unknown,
    bodyOrActor: unknown,
    actorOrRequest?: unknown,
    request?: ApplicationMutationRequestContext,
  ): Promise<ApplicationSummary> {
    const invocation = resolveWriteInvocation(bodyOrActor, actorOrRequest, request);
    const permission = status === "active"
      ? APPLICATION_MANAGEMENT_PERMISSIONS.applicationsEnable
      : APPLICATION_MANAGEMENT_PERMISSIONS.applicationsDisable;
    this.authorize(permission, invocation.actor);
    const identifier = parseApplicationIdentifier(id);
    const input = parseApplicationLifecycleActionRequest(invocation.body);
    return this.execute(async () => {
      const current = await this.repository.getApplication(identifier);
      if (current === undefined || current === null) throw notFound("Application not found");
      this.assertExpectedVersion(current.version, input.expectedVersion, current.etag);
      if (lifecycleStatusOf(current) === "archived" || lifecycleStatusOf(current) === "purged") {
        throw conflict("Archived applications must be restored before changing status");
      }
      const result = await this.repository.setApplicationStatus(identifier, status, writeContext(invocation.actor, invocation.request));
      return toApplicationSummary(result);
    });
  }

  private async changePlatformStatus(
    status: ApplicationStatus,
    applicationId: unknown,
    id: unknown,
    bodyOrActor: unknown,
    actorOrRequest?: unknown,
    request?: ApplicationMutationRequestContext,
  ): Promise<ApplicationPlatformSummary> {
    const invocation = resolveWriteInvocation(bodyOrActor, actorOrRequest, request);
    const permission = status === "active"
      ? APPLICATION_MANAGEMENT_PERMISSIONS.platformsEnable
      : APPLICATION_MANAGEMENT_PERMISSIONS.platformsDisable;
    this.authorize(permission, invocation.actor);
    const appId = parseApplicationIdentifier(applicationId);
    const platformId = parseApplicationPlatformIdentifier(id);
    const input = parseApplicationLifecycleActionRequest(invocation.body);
    return this.execute(async () => {
      await this.assertApplicationConfigurable(appId);
      const current = await this.repository.getPlatform(appId, platformId);
      if (current === undefined || current === null) throw notFound("Application platform not found");
      if (lifecycleStatusOf(current) === "archived" || lifecycleStatusOf(current) === "purged") {
        throw conflict("Archived application platforms must be restored before changing status");
      }
      this.assertExpectedVersion(current.version, input.expectedVersion, current.etag);
      const result = await this.repository.setPlatformStatus(appId, platformId, status, writeContext(invocation.actor, invocation.request));
      return toApplicationPlatformSummary(result);
    });
  }

  private async changeClientStatus(
    status: ApplicationClientStatus,
    applicationId: unknown,
    id: unknown,
    bodyOrActor: unknown,
    actorOrRequest?: unknown,
    request?: ApplicationMutationRequestContext,
  ): Promise<ApplicationClientSummary> {
    const invocation = resolveWriteInvocation(bodyOrActor, actorOrRequest, request);
    const permission = status === "active"
      ? APPLICATION_MANAGEMENT_PERMISSIONS.clientsEnable
      : APPLICATION_MANAGEMENT_PERMISSIONS.clientsDisable;
    this.authorize(permission, invocation.actor);
    const appId = parseApplicationIdentifier(applicationId);
    const clientRecordId = parseApplicationClientIdentifier(id);
    const input = parseApplicationLifecycleActionRequest(invocation.body);
    return this.execute(async () => {
      await this.assertApplicationConfigurable(appId);
      const current = await this.repository.getClient(appId, clientRecordId);
      if (current === undefined || current === null) throw notFound("OIDC client not found");
      if (lifecycleStatusOf(current) === "archived" || lifecycleStatusOf(current) === "purged") {
        throw conflict("Archived OIDC clients must be restored before changing status");
      }
      this.assertExpectedVersion(current.version, input.expectedVersion, current.etag);
      const result = await this.repository.setClientStatus(appId, clientRecordId, status, writeContext(invocation.actor, invocation.request));
      return toApplicationClientSummary(result);
    });
  }

  private async changeApplicationLifecycle(
    action: "archive" | "restore",
    id: unknown,
    bodyOrActor: unknown,
    actorOrRequest?: unknown,
    request?: ApplicationMutationRequestContext,
  ): Promise<ApplicationSummary> {
    const invocation = resolveWriteInvocation(bodyOrActor, actorOrRequest, request);
    const permission = action === "archive"
      ? APPLICATION_MANAGEMENT_PERMISSIONS.applicationsArchive
      : APPLICATION_MANAGEMENT_PERMISSIONS.applicationsRestore;
    this.authorize(permission, invocation.actor);
    const identifier = parseApplicationIdentifier(id);
    const input = parseApplicationLifecycleActionRequest(invocation.body);
    return this.execute(async () => {
      const current = await this.repository.getApplication(identifier);
      if (current === undefined || current === null) throw notFound("Application not found");
      this.assertExpectedVersion(current.version, input.expectedVersion, current.etag);
      const children = await this.applicationChildren(identifier);
      const lifecycleStatus = lifecycleStatusOf(current);
      if (action === "archive" && (lifecycleStatus === "archived" || lifecycleStatus === "purged")) {
        throw conflict("Application is already archived or purged");
      }
      if (action === "restore" && lifecycleStatus !== "archived") {
        throw conflict("Only archived applications can be restored");
      }
      const context = writeContext(invocation.actor, invocation.request);
      const result = await this.runAtomic(async () => {
        if (action === "archive") {
          await this.cascadeApplicationChildren(identifier, children, "archive", invocation.actor, context);
        } else {
          await this.cascadeApplicationChildren(identifier, children, "restore", invocation.actor, context);
        }
        const changed = action === "archive"
          ? await this.callApplicationArchive(identifier, context)
          : await this.callApplicationRestore(identifier, context);
        if (changed === undefined || changed === null) throw internalError();
        return changed;
      });
      return toApplicationSummary(result);
    });
  }

  private async queueApplicationPurge(
    id: unknown,
    bodyOrActor: unknown,
    actorOrRequest?: unknown,
    request?: ApplicationMutationRequestContext,
  ): Promise<ApplicationPurgeJob> {
    const invocation = resolveWriteInvocation(bodyOrActor, actorOrRequest, request);
    this.authorize(APPLICATION_MANAGEMENT_PERMISSIONS.applicationsPurge, invocation.actor);
    const identifier = parseApplicationIdentifier(id);
    const input = parsePurgeRequest(invocation.body);
    return this.execute(async () => {
      const current = await this.repository.getApplication(identifier);
      if (current === undefined || current === null) throw notFound("Application not found");
      const idempotencyKey = input.idempotencyKey ?? idempotencyKeyFromRequest(invocation.request);
      if (idempotencyKey !== undefined) {
        const existing = this.purgeJobs.get(`${identifier}:${idempotencyKey}`);
        if (existing) return { ...existing };
      }
      const children = await this.applicationChildren(identifier);
      if (children.platforms.length > 0) this.authorize(APPLICATION_MANAGEMENT_PERMISSIONS.platformsPurge, invocation.actor);
      if (children.clients.length > 0) this.authorize(APPLICATION_MANAGEMENT_PERMISSIONS.clientsPurge, invocation.actor);
      if (lifecycleStatusOf(current) !== "archived") throw conflict("Only archived applications can be purged");
      const requestedVersion = input.expectedVersion ?? expectedVersionFromRequest(invocation.request);
      this.assertExpectedVersion(current.version, requestedVersion, current.etag);
      const expectedVersion = current.version ?? 1;
      const key = `${identifier}:${idempotencyKey ?? expectedVersion}`;
      const existing = this.purgeJobs.get(key);
      if (existing) return { ...existing };
      const job: ApplicationPurgeJob = {
        id: randomUUID(),
        jobId: "",
        applicationId: identifier,
        resourceType: "application",
        resourceId: identifier,
        operation: "purge",
        status: "queued",
        expectedVersion,
        createdAt: new Date().toISOString(),
        ...(idempotencyKey === undefined ? {} : { idempotencyKey }),
      };
      job.jobId = job.id;
      const enqueue = this.repository.enqueuePurgeApplication;
      const queued = await this.runAtomic(async () => typeof enqueue === "function"
        ? enqueue.call(this.repository, identifier, job, writeContext(invocation.actor, invocation.request))
        : job);
      const normalized = normalizePurgeJob(queued, job);
      this.purgeJobs.set(key, normalized);
      if (idempotencyKey !== undefined) this.purgeJobs.set(`${identifier}:${idempotencyKey}`, normalized);
      return { ...normalized };
    });
  }

  private async queueChildPurge(
    resourceType: "application-platform" | "application-client",
    applicationId: unknown,
    id: unknown,
    bodyOrActor: unknown,
    actorOrRequest?: unknown,
    request?: ApplicationMutationRequestContext,
  ): Promise<ApplicationPurgeJob> {
    const invocation = resolveWriteInvocation(bodyOrActor, actorOrRequest, request);
    const permission = resourceType === "application-platform"
      ? APPLICATION_MANAGEMENT_PERMISSIONS.platformsPurge
      : APPLICATION_MANAGEMENT_PERMISSIONS.clientsPurge;
    this.authorize(permission, invocation.actor);
    const appId = parseApplicationIdentifier(applicationId);
    const resourceId = resourceType === "application-platform"
      ? parseApplicationPlatformIdentifier(id)
      : parseApplicationClientIdentifier(id);
    const input = parsePurgeRequest(invocation.body);
    return this.execute(async () => {
      await this.assertApplicationConfigurable(appId);
      const current = resourceType === "application-platform"
        ? await this.repository.getPlatform(appId, resourceId)
        : await this.repository.getClient(appId, resourceId);
      if (current === undefined || current === null) {
        throw notFound(resourceType === "application-platform" ? "Application platform not found" : "OIDC client not found");
      }
      if (lifecycleStatusOf(current) !== "archived") {
        throw conflict(`Only archived ${resourceType === "application-platform" ? "platforms" : "clients"} can be purged`);
      }
      const idempotencyKey = input.idempotencyKey ?? idempotencyKeyFromRequest(invocation.request);
      const key = `${appId}:${resourceType}:${resourceId}:${idempotencyKey ?? current.version ?? 1}`;
      const existing = this.purgeJobs.get(key);
      if (existing) return { ...existing };
      const requestedVersion = input.expectedVersion ?? expectedVersionFromRequest(invocation.request);
      this.assertExpectedVersion(current.version, requestedVersion, current.etag);
      const expectedVersion = current.version ?? 1;
      const job: ApplicationPurgeJob = {
        id: randomUUID(),
        jobId: "",
        applicationId: appId,
        resourceType,
        resourceId,
        operation: "purge",
        status: "queued",
        expectedVersion,
        createdAt: new Date().toISOString(),
        ...(idempotencyKey === undefined ? {} : { idempotencyKey }),
      };
      job.jobId = job.id;
      const enqueue = this.repository.enqueuePurgeResource;
      const queued = await this.runAtomic(async () => typeof enqueue === "function"
        ? enqueue.call(this.repository, appId, resourceType, resourceId, job, writeContext(invocation.actor, invocation.request))
        : job);
      const normalized = normalizePurgeJob(queued, job);
      this.purgeJobs.set(key, normalized);
      if (idempotencyKey !== undefined) this.purgeJobs.set(`${appId}:${resourceType}:${resourceId}:${idempotencyKey}`, normalized);
      return { ...normalized };
    });
  }

  private async changePlatformLifecycle(
    action: "archive" | "restore" | "purge",
    applicationId: unknown,
    id: unknown,
    bodyOrActor: unknown,
    actorOrRequest?: unknown,
    request?: ApplicationMutationRequestContext,
  ): Promise<ApplicationPlatformSummary> {
    const invocation = resolveWriteInvocation(bodyOrActor, actorOrRequest, request);
    const permission = action === "archive"
      ? APPLICATION_MANAGEMENT_PERMISSIONS.platformsArchive
      : action === "restore"
        ? APPLICATION_MANAGEMENT_PERMISSIONS.platformsRestore
        : APPLICATION_MANAGEMENT_PERMISSIONS.platformsPurge;
    this.authorize(permission, invocation.actor);
    const appId = parseApplicationIdentifier(applicationId);
    const platformId = parseApplicationPlatformIdentifier(id);
    const input = parseApplicationLifecycleActionRequest(invocation.body);
    return this.execute(async () => {
      await this.assertApplicationConfigurable(appId);
       const current = await this.repository.getPlatform(appId, platformId);
       if (current === undefined || current === null) throw notFound("Application platform not found");
       const lifecycleStatus = lifecycleStatusOf(current);
       if (action === "archive" && (lifecycleStatus === "archived" || lifecycleStatus === "purged")) {
         throw conflict("Application platform is already archived or purged");
       }
       if (action === "restore" && lifecycleStatus !== "archived") {
         throw conflict("Only archived application platforms can be restored");
       }
       if (action === "purge" && lifecycleStatus !== "archived") {
         throw conflict("Only archived application platforms can be purged");
       }
       this.assertExpectedVersion(current.version, input.expectedVersion, current.etag);
       const context = writeContext(invocation.actor, invocation.request);
       const operation = action === "archive"
        ? this.repository.archivePlatform
        : action === "restore"
          ? this.repository.restorePlatform
          : this.repository.purgePlatform;
      if (typeof operation !== "function") {
        throw conflict(`Application repository does not support platform ${action}`);
      }
      const result = await operation.call(this.repository, appId, platformId, context);
      return toApplicationPlatformSummary(result);
    });
  }

  private async changeClientLifecycle(
    action: "archive" | "restore" | "purge",
    applicationId: unknown,
    id: unknown,
    bodyOrActor: unknown,
    actorOrRequest?: unknown,
    request?: ApplicationMutationRequestContext,
  ): Promise<ApplicationClientSummary> {
    const invocation = resolveWriteInvocation(bodyOrActor, actorOrRequest, request);
    const permission = action === "archive"
      ? APPLICATION_MANAGEMENT_PERMISSIONS.clientsArchive
      : action === "restore"
        ? APPLICATION_MANAGEMENT_PERMISSIONS.clientsRestore
        : APPLICATION_MANAGEMENT_PERMISSIONS.clientsPurge;
    this.authorize(permission, invocation.actor);
    const appId = parseApplicationIdentifier(applicationId);
    const clientId = parseApplicationClientIdentifier(id);
    const input = parseApplicationLifecycleActionRequest(invocation.body);
    return this.execute(async () => {
      await this.assertApplicationConfigurable(appId);
       const current = await this.repository.getClient(appId, clientId);
       if (current === undefined || current === null) throw notFound("OIDC client not found");
       const lifecycleStatus = lifecycleStatusOf(current);
       if (action === "archive" && (lifecycleStatus === "archived" || lifecycleStatus === "purged")) {
         throw conflict("OIDC client is already archived or purged");
       }
       if (action === "restore" && lifecycleStatus !== "archived") {
         throw conflict("Only archived OIDC clients can be restored");
       }
       if (action === "purge" && lifecycleStatus !== "archived") {
         throw conflict("Only archived OIDC clients can be purged");
       }
       this.assertExpectedVersion(current.version, input.expectedVersion, current.etag);
       const context = writeContext(invocation.actor, invocation.request);
       const operation = action === "archive"
        ? this.repository.archiveClient
        : action === "restore"
          ? this.repository.restoreClient
          : this.repository.purgeClient;
      if (typeof operation !== "function") {
        throw conflict(`Application repository does not support client ${action}`);
      }
      const result = await operation.call(this.repository, appId, clientId, context);
      return toApplicationClientSummary(result);
    });
  }

  private async callApplicationArchive(id: string, context: ApplicationWriteContext): Promise<ApplicationRecordLike | undefined> {
    if (typeof this.repository.archiveApplication === "function") return this.repository.archiveApplication(id, context);
    if (typeof this.repository.archive === "function") return this.repository.archive(id, context);
    return undefined;
  }

  private async callApplicationRestore(id: string, context: ApplicationWriteContext): Promise<ApplicationRecordLike | undefined> {
    if (typeof this.repository.restoreApplication === "function") return this.repository.restoreApplication(id, context);
    if (typeof this.repository.restore === "function") return this.repository.restore(id, context);
    return undefined;
  }

  private async cascadeApplicationChildren(
    applicationId: string,
    children: ApplicationChildren,
    action: "archive" | "restore",
    actor: ApplicationActor | undefined,
    context: ApplicationWriteContext,
  ): Promise<void> {
    const platforms = children.platforms.filter((platform) => {
      const status = lifecycleStatusOf(platform);
      return action === "archive" ? status !== "archived" && status !== "purged" : status === "archived";
    });
    const clients = children.clients.filter((client) => {
      const status = lifecycleStatusOf(client);
      return action === "archive" ? status !== "archived" && status !== "purged" : status === "archived";
    });
    if (platforms.length === 0 && clients.length === 0) return;
    if (platforms.length > 0) {
      const operation = action === "archive" ? this.repository.archivePlatform : this.repository.restorePlatform;
      this.authorize(
        action === "archive" ? APPLICATION_MANAGEMENT_PERMISSIONS.platformsArchive : APPLICATION_MANAGEMENT_PERMISSIONS.platformsRestore,
        actor,
      );
      if (typeof operation !== "function") {
        throw conflict("Application repository does not support platform lifecycle cascade");
      }
    }
    if (clients.length > 0) {
      const operation = action === "archive" ? this.repository.archiveClient : this.repository.restoreClient;
      this.authorize(
        action === "archive" ? APPLICATION_MANAGEMENT_PERMISSIONS.clientsArchive : APPLICATION_MANAGEMENT_PERMISSIONS.clientsRestore,
        actor,
      );
      if (typeof operation !== "function") {
        throw conflict("Application repository does not support client lifecycle cascade");
      }
    }
    if (!this.hasAtomicTransaction()) {
      throw conflict("Application lifecycle cascade requires an atomic repository transaction");
    }
    const platformOperation = action === "archive" ? this.repository.archivePlatform : this.repository.restorePlatform;
    if (platforms.length > 0 && typeof platformOperation === "function") {
      for (const platform of platforms) {
        await platformOperation.call(this.repository, applicationId, platform.id, context);
      }
    }
    const clientOperation = action === "archive" ? this.repository.archiveClient : this.repository.restoreClient;
    if (clients.length > 0 && typeof clientOperation === "function") {
      for (const client of clients) {
        await clientOperation.call(this.repository, applicationId, client.id, context);
      }
    }
  }

  private hasAtomicTransaction(): boolean {
    return this.mutationTransaction !== undefined || typeof this.repository.withTransaction === "function";
  }

  private async runAtomic<T>(operation: () => Promise<T>): Promise<T> {
    if (this.mutationTransaction) return this.mutationTransaction(operation);
    if (typeof this.repository.withTransaction === "function") return this.repository.withTransaction(operation);
    return operation();
  }

  private async applicationChildren(applicationId: string): Promise<ApplicationChildren> {
    const [platforms, clients, externalIdentities] = await Promise.all([
      this.listAllPlatforms(applicationId),
      this.listAllClients(applicationId),
      this.listAllExternalIdentities(applicationId),
    ]);
    return {
      platforms,
      clients,
      externalIdentities,
      total: platforms.length + clients.length + externalIdentities.length,
    };
  }

  private async listAllPlatforms(applicationId: string): Promise<ApplicationPlatformRecord[]> {
    return this.listAll((query) => this.repository.listPlatforms(applicationId, query), "platforms");
  }

  private async listAllClients(applicationId: string): Promise<ApplicationClientRecord[]> {
    return this.listAll((query) => this.repository.listClients(applicationId, query), "clients");
  }

  private async listAllExternalIdentities(applicationId: string): Promise<ApplicationExternalIdentityRecord[]> {
    if (typeof this.repository.listExternalIdentities !== "function") return [];
    return this.listAll((query) => this.repository.listExternalIdentities?.(applicationId, query) ?? { items: [], total: 0, hasMore: false }, "external identities");
  }

  private async listAll<T extends { id?: string }>(
    load: (query: { limit: number; offset?: number; cursor?: string }) => ApplicationPage<T> | Promise<ApplicationPage<T>>,
    label: string,
  ): Promise<T[]> {
    const output: T[] = [];
    const seenCursors = new Set<string>();
    let cursor: string | undefined;
    let offset = 0;
    for (let pageIndex = 0; pageIndex < 1000; pageIndex += 1) {
      const page = await load(cursor === undefined ? { limit: this.options.maxLimit, offset } : { limit: this.options.maxLimit, cursor });
      if (!isRecord(page) || !Array.isArray(page.items)) throw internalError();
      output.push(...page.items);
      const total = isFiniteNumber(page.total) && page.total >= 0 ? Math.floor(page.total) : output.length;
      if (page.hasMore !== true) {
        if (total > output.length && page.items.length > 0) throw internalError();
        return output;
      }
      if (typeof page.nextCursor === "string" && page.nextCursor.length > 0) {
        if (seenCursors.has(page.nextCursor)) throw internalError();
        seenCursors.add(page.nextCursor);
        cursor = page.nextCursor;
        continue;
      }
      if (page.items.length === 0) throw internalError();
      offset += page.items.length;
    }
    throw conflict(`${label} exceed the supported page count`);
  }

  private async restorePlatformSecretReference(
    applicationId: string,
    platformId: string,
    secretRef: string | null | undefined,
    context: ApplicationWriteContext,
  ): Promise<void> {
    try {
      await this.repository.updatePlatform(
        applicationId,
        platformId,
        { secretRef: secretRef ?? null } as unknown as ApplicationPlatformUpdateRequest,
        context,
      );
    } catch {
      throw internalError();
    }
  }

  private async restoreClientSecretReference(
    applicationId: string,
    clientId: string,
    secretRef: string | null | undefined,
    context: ApplicationWriteContext,
  ): Promise<void> {
    try {
      await this.repository.updateClient(
        applicationId,
        clientId,
        { secretRef: secretRef ?? null } as unknown as ApplicationClientUpdateRequest,
        context,
      );
    } catch {
      throw internalError();
    }
  }

  private async findSecretBinding(subjectType: "application-platform" | "application-client", subjectId: string, purpose: string) {
    return this.secretBindings?.findActive(subjectType, subjectId, purpose);
  }

  private async revokeSecretBindings(
    subjectType: "application-platform" | "application-client",
    subjectId: string,
    purpose: string,
  ): Promise<void> {
    const bindings = this.secretBindings;
    if (bindings === undefined) return;
    if (typeof bindings.revokeSubject === "function") {
      await bindings.revokeSubject(subjectType, subjectId, purpose);
      return;
    }
    let cursor: string | undefined;
    do {
      const page = await bindings.list({ subjectType, subjectId, purpose, limit: 100, cursor });
      for (const binding of page.items) {
        if (binding.status !== "revoked") await bindings.revoke(binding.id, binding.version);
      }
      cursor = page.hasMore ? page.nextCursor : undefined;
    } while (cursor !== undefined);
  }

  private requiredExpectedVersion(
    bodyExpected: ApplicationVersion | undefined,
    request: ApplicationMutationRequestContext | ApplicationWriteContext | undefined,
    actual: ApplicationVersion | undefined,
    etag: string | undefined,
    resource: string,
  ): ApplicationVersion {
    const headerExpected = parseIfMatch((request as ApplicationMutationRequestContext | undefined)?.ifMatch);
    if (bodyExpected === undefined && headerExpected === undefined) {
      throw invalidRequest(`${resource} expectedVersion or If-Match is required`, { field: "expectedVersion" });
    }
    if (
      bodyExpected !== undefined &&
      headerExpected !== undefined &&
      (!sameVersion(actual, bodyExpected, actual, etag) || !sameVersion(actual, headerExpected, actual, etag))
    ) {
      throw conflict("Optimistic lock headers do not match");
    }
    const expected = bodyExpected ?? headerExpected;
    this.assertExpectedVersion(actual, expected, etag);
    return actual ?? 1;
  }

  private assertExpectedVersion(
    actual: ApplicationVersion | undefined,
    expected: ApplicationVersion | undefined,
    etag?: string,
  ): void {
    if (expected !== undefined && !sameVersion(actual, expected, actual, etag)) {
      throw conflict("Application resource version changed");
    }
  }

  private async syncSecretBinding(
    subjectType: "application-platform" | "application-client",
    subjectId: string,
    purpose: string,
    secretRef: string,
    currentVersion?: number | string,
    _resourceVersion?: ApplicationVersion,
  ): Promise<void> {
    const bindings = this.secretBindings;
    if (!bindings) {
      if (this.requireSecretBindings) {
        throw internalError();
      }
      return;
    }
    const current = await bindings.findActive(subjectType, subjectId, purpose);
    if (current?.secretRef === secretRef) return;
    if (current === undefined) {
      await bindings.create({ subjectType, subjectId, purpose, secretRef });
      return;
    }
    const normalizedVersion = typeof currentVersion === "number"
      ? currentVersion
      : typeof currentVersion === "string" && /^\d+$/u.test(currentVersion)
        ? Number(currentVersion)
        : current.version;
    const expected = normalizedVersion <= 0 ? current.version : normalizedVersion;
    if (expected !== current.version) throw conflict("Secret binding version changed");
    await bindings.rotate(subjectType, subjectId, purpose, { secretRef, expectedVersion: current.version });
  }

  private async assertApplicationExists(id: string): Promise<void> {
    const application = await this.repository.getApplication(id);
    if (application === undefined || application === null) throw notFound("Application not found");
  }

  private async assertApplicationConfigurable(id: string): Promise<void> {
    const application = await this.repository.getApplication(id);
    if (application === undefined || application === null) throw notFound("Application not found");
    const status = lifecycleStatusOf(application);
    if (status === "archived" || status === "purged") {
      throw conflict("Archived applications cannot be modified");
    }
  }

  private pageOptions(): { defaultLimit: number; maxLimit: number } {
    return { defaultLimit: this.options.defaultLimit, maxLimit: this.options.maxLimit };
  }

  private authorize(permission: string, actor: ApplicationActor | undefined): void {
    this.authenticate(actor);
    if (!this.options.requireActor) return;
    const permissions = Array.isArray(actor?.permissions)
      ? actor.permissions.filter((value): value is string => typeof value === "string")
      : [];
    if (hasPermission(permissions, permission)) return;
    const roles = actor?.roles ?? (actor?.user ? rolesFromUser(actor.user) : []);
    if (roles.some((role) => this.options.adminRoles.some((adminRole) => adminRole.trim().toLowerCase() === role.trim().toLowerCase()))) return;
    throw forbidden();
  }

  private authenticate(actor: ApplicationActor | undefined): void {
    if (this.options.requireActor && (!actor || !isRecord(actor.user))) throw unauthenticated();
  }

  private async execute<T>(operation: () => Promise<T>): Promise<T> {
    try {
      return await operation();
    } catch (error) {
      if (error instanceof ControlPlaneError) throw error;
      throw internalError();
    }
  }
}

export { ApplicationService as ApplicationManagementService };

function mapPage<T>(
  page: ApplicationPage<unknown>,
  mapper: (value: unknown) => T,
): ApplicationPage<T> {
  if (!isRecord(page) || !Array.isArray(page.items)) throw internalError();
  const items = page.items.map((item) => mapper(item));
  const output: ApplicationPage<T> = {
    items,
    hasMore: page.hasMore === true,
    total: isFiniteNumber(page.total) && page.total >= 0 ? Math.floor(page.total) : items.length,
  };
  if (typeof page.nextCursor === "string" && page.nextCursor.length > 0 && page.nextCursor.length <= 1024 && !/[\u0000-\u001f\u007f]/u.test(page.nextCursor)) {
    output.nextCursor = page.nextCursor;
  }
  return output;
}

function filterMappedPage<T extends { readiness?: unknown; effectiveStatus?: unknown }>(
  page: ApplicationPage<T>,
  query: { readiness?: unknown; effectiveStatus?: unknown },
): ApplicationPage<T> {
  if (query.readiness === undefined && query.effectiveStatus === undefined) return page;
  const items = page.items.filter((item) => {
    if (query.readiness !== undefined && readinessStatus(item.readiness) !== query.readiness) return false;
    if (query.effectiveStatus !== undefined && item.effectiveStatus !== query.effectiveStatus) return false;
    return true;
  });
  return {
    ...page,
    items,
  };
}

function readinessStatus(value: unknown): string {
  if (typeof value === "string") return value;
  if (typeof value === "object" && value !== null && "status" in value) {
    const status = (value as { status?: unknown }).status;
    if (typeof status === "string") return status;
  }
  return "unknown";
}

function resolveInvocation(
  queryOrActor: unknown,
  maybeActor?: ApplicationActor,
): { query: unknown; actor?: ApplicationActor } {
  if (maybeActor !== undefined) return { query: queryOrActor, actor: normalizeActor(maybeActor) };
  if (isActorLike(queryOrActor)) return { query: {}, actor: normalizeActor(queryOrActor) };
  return { query: queryOrActor, actor: undefined };
}

function resolveIdentifierInvocation(
  idOrActor: unknown,
  actor?: ApplicationActor,
): { id: unknown; actor?: ApplicationActor } {
  if (actor === undefined && isActorLike(idOrActor)) {
    return { id: undefined, actor: normalizeActor(idOrActor) };
  }
  return { id: idOrActor, actor: normalizeActor(actor) };
}

function resolveWriteInvocation(
  bodyOrActor: unknown,
  actorOrRequest?: unknown,
  request?: ApplicationMutationRequestContext,
): { body: unknown; actor?: ApplicationActor; request?: ApplicationMutationRequestContext } {
  if (isActorLike(bodyOrActor)) {
    return {
      body: {},
      actor: normalizeActor(bodyOrActor),
      request: isWriteRequest(actorOrRequest)
        ? actorOrRequest
        : typeof actorOrRequest === "string"
          ? { requestId: actorOrRequest }
          : request,
    };
  }
  return {
    body: bodyOrActor,
    actor: isActorLike(actorOrRequest) ? normalizeActor(actorOrRequest) : undefined,
    request: isWriteRequest(actorOrRequest)
      ? actorOrRequest
      : typeof actorOrRequest === "string"
        ? { requestId: actorOrRequest }
        : request,
  };
}

function normalizeActor(value: unknown): ApplicationActor | undefined {
  if (!isRecord(value)) return undefined;
  if (isRecord(value.user) || value.user === undefined) {
    const user = isRecord(value.user) ? value.user : undefined;
    const roles = roleValues(value.roles);
    return {
      user,
      permissions: stringArray(value.permissions),
      roles: roles.length > 0 ? roles : user === undefined ? [] : rolesFromUser(user),
    };
  }
  return { user: value, permissions: [], roles: rolesFromUser(value) };
}

function isActorLike(value: unknown): boolean {
  if (!isRecord(value)) return false;
  return isRecord(value.user) || Array.isArray(value.permissions) || Array.isArray(value.roles);
}

function isWriteRequest(value: unknown): value is ApplicationMutationRequestContext {
  return isRecord(value) && (
    "requestId" in value ||
    "ipAddress" in value ||
    "userAgent" in value ||
    "actorId" in value ||
    "ifMatch" in value ||
    "idempotencyKey" in value
  );
}

function writeContext(actor: ApplicationActor | undefined, request: ApplicationWriteContext | undefined): ApplicationWriteContext {
  return {
    actorId: safeContextValue(actor?.user?.id),
    requestId: safeContextValue(request?.requestId),
    ipAddress: safeContextValue(request?.ipAddress),
    userAgent: safeContextValue(request?.userAgent),
  };
}

function safeContextValue(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  const normalized = value.trim();
  return normalized.length > 0 && normalized.length <= 512 && !/[\u0000-\u001f\u007f]/u.test(normalized) && !/(?:secret|token|password|private[-_]?key|credential|authorization|cookie|vault:\/\/)/iu.test(normalized)
    ? normalized
    : undefined;
}

function rolesFromUser(user: AnyRecord): string[] {
  return [...roleValues(user.roles), ...roleValues(user.role)].filter((role, index, values) => values.indexOf(role) === index);
}

function roleValues(value: unknown): string[] {
  const values = typeof value === "string" ? [value] : stringArray(value);
  return values
    .map((role) => role.trim())
    .filter((role) => role.length > 0);
}

function stringArray(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value.filter((item): item is string => typeof item === "string" && item.length > 0);
}

function conflictWithDetails(message: string, details: Record<string, unknown>): ControlPlaneError {
  return new ControlPlaneError("CONFLICT", message, { statusCode: 409, details });
}

function rejectSecretMutation(input: unknown, resource: string): void {
  if (!isRecord(input)) return;
  for (const key of Object.keys(input)) {
    const normalized = key.replace(/[-_]/g, "").toLowerCase();
    if (
      normalized === "secretref" ||
      normalized === "privatekeyref" ||
      normalized === "secretbinding" ||
      normalized === "secretversion" ||
      normalized === "secretstatus" ||
      normalized === "credential"
    ) {
      throw invalidRequest(`${resource} secret fields require a dedicated rotation or revocation endpoint`, { field: key });
    }
  }
}

function hasOwnProperty(input: unknown, key: string): boolean {
  return isRecord(input) && Object.prototype.hasOwnProperty.call(input, key);
}

function clientAuthMethod(record: ApplicationClientRecordLike): string {
  if (record.hasSecret === true || record.secretRef !== undefined && record.secretRef !== null) return "client_secret_basic";
  return "private_key_jwt";
}

function normalizeApplicationType(value: unknown): "web" | "native" {
  return value === "native" ? "native" : "web";
}

function expectedVersionFromRequest(request: ApplicationMutationRequestContext | ApplicationWriteContext | undefined): ApplicationVersion | undefined {
  return parseIfMatch((request as ApplicationMutationRequestContext | undefined)?.ifMatch);
}

function parsePurgeRequest(input: unknown): { expectedVersion?: ApplicationVersion; idempotencyKey?: string } {
  if (input === undefined || input === null) return {};
  if (!isRecord(input)) throw invalidRequest("Request body must be an object");
  for (const key of Object.keys(input)) {
    if (key !== "expectedVersion" && key !== "idempotencyKey") {
      throw invalidRequest("Unsupported request field", { field: key });
    }
  }
  const body = { ...input };
  const idempotencyKey = body.idempotencyKey;
  delete body.idempotencyKey;
  const expected = parseApplicationLifecycleActionRequest(body).expectedVersion;
  if (idempotencyKey === undefined) return expected === undefined ? {} : { expectedVersion: expected };
  if (typeof idempotencyKey !== "string") throw invalidRequest("Invalid idempotencyKey", { field: "idempotencyKey" });
  const normalized = idempotencyKey.trim();
  if (normalized.length === 0 || normalized.length > 256 || /[\u0000-\u001f\u007f]/u.test(normalized) || /(?:secret|token|password|private[-_]?key|credential|vault:\/\/)/iu.test(normalized)) {
    throw invalidRequest("Invalid idempotencyKey", { field: "idempotencyKey" });
  }
  return {
    ...(expected === undefined ? {} : { expectedVersion: expected }),
    idempotencyKey: normalized,
  };
}

function idempotencyKeyFromRequest(request: ApplicationMutationRequestContext | undefined): string | undefined {
  const value = request?.idempotencyKey;
  if (typeof value !== "string") return undefined;
  const normalized = value.trim();
  return normalized.length > 0 && normalized.length <= 256 && !/[\u0000-\u001f\u007f]/u.test(normalized) && !/(?:secret|token|password|private[-_]?key|credential|vault:\/\/)/iu.test(normalized)
    ? normalized
    : undefined;
}

function parseIfMatch(value: unknown): string | undefined {
  if (value === undefined || value === null || value === "") return undefined;
  if (typeof value !== "string") throw invalidRequest("Invalid If-Match header", { field: "If-Match" });
  const normalized = value.trim();
  if (normalized.length === 0 || normalized.length > 512 || normalized.includes(",") || normalized === "*" || /[\u0000-\u001f\u007f]/u.test(normalized) || /(?:secret|token|password|private[-_]?key|credential|vault:\/\/)/iu.test(normalized)) {
    throw invalidRequest("Invalid If-Match header", { field: "If-Match" });
  }
  return normalized.startsWith("W/") ? normalized.slice(2).trim() : normalized;
}

function stripEtag(value: string): string {
  const normalized = value.trim();
  if (normalized.startsWith("W/")) return normalized.slice(2).trim();
  if (normalized.length >= 2 && normalized.startsWith('"') && normalized.endsWith('"')) return normalized.slice(1, -1);
  return normalized;
}

function sameVersion(
  actual: ApplicationVersion | undefined,
  expected: ApplicationVersion,
  actualVersion: ApplicationVersion | undefined,
  etag: string | undefined,
): boolean {
  const expectedText = stripEtag(String(expected));
  const versionText = String(actualVersion ?? actual ?? 1);
  if (expectedText === versionText) return true;
  if (etag !== undefined && expectedText === stripEtag(etag)) return true;
  const match = /:(\d+)$/u.exec(expectedText);
  return match !== null && match[1] === versionText;
}

function nextSecretVersion(value: ApplicationVersion | undefined): number {
  if (typeof value === "number" && Number.isSafeInteger(value) && value >= 0) return value + 1;
  if (typeof value === "string" && /^\d+$/u.test(value)) {
    const parsed = Number(value);
    if (Number.isSafeInteger(parsed) && parsed >= 0) return parsed + 1;
  }
  return 1;
}

function safeVersionValue(value: unknown): ApplicationVersion | undefined {
  if (typeof value === "number" && Number.isSafeInteger(value) && value >= 0) return value;
  if (typeof value === "string" && /^\d+$/u.test(value) && value.length <= 128) return value;
  return undefined;
}

function normalizePurgeJob(value: unknown, fallback: ApplicationPurgeJob): ApplicationPurgeJob {
  if (!isRecord(value)) return { ...fallback };
  const id = safeContextValue(value.jobId) ?? safeContextValue(value.id) ?? fallback.id;
  const status = value.status === "running" || value.status === "completed" || value.status === "failed"
    ? value.status
    : fallback.status;
  return {
    ...fallback,
    id,
    jobId: id,
    status,
    ...(safeVersionValue(value.expectedVersion) === undefined ? {} : { expectedVersion: safeVersionValue(value.expectedVersion) }),
    ...(typeof value.createdAt === "string" && value.createdAt.length <= 128 && !/[\u0000-\u001f\u007f]/u.test(value.createdAt) ? { createdAt: value.createdAt } : {}),
  };
}

function validationResult(
  value: {
    applicationId: string;
    applicationType?: ApplicationSummary["applicationType"];
    readiness?: ApplicationValidationResult["readiness"];
    effectiveStatus?: ApplicationValidationResult["effectiveStatus"];
    version?: ApplicationVersion;
    etag?: string;
  },
  issues: ApplicationValidationIssue[],
): ApplicationValidationResult {
  return {
    applicationId: value.applicationId,
    ...(value.applicationType === undefined ? {} : { applicationType: value.applicationType }),
    valid: issues.every((issue) => issue.severity !== "error"),
    status: issues.some((issue) => issue.severity === "error") ? "invalid" : "valid",
    issues,
    ...(value.readiness === undefined ? {} : { readiness: value.readiness }),
    ...(value.effectiveStatus === undefined ? {} : { effectiveStatus: value.effectiveStatus }),
    ...(value.version === undefined ? {} : { version: value.version }),
    ...(value.etag === undefined ? {} : { etag: value.etag }),
    checkedAt: new Date().toISOString(),
  };
}

function lifecycleStatusOf(record: { status?: unknown; lifecycleStatus?: unknown }): ApplicationStatus {
  const lifecycle = record.lifecycleStatus;
  if (lifecycle === "active" || lifecycle === "disabled" || lifecycle === "archived" || lifecycle === "purged") {
    return lifecycle;
  }
  return record.status === "disabled" || record.status === "archived" || record.status === "purged"
    ? record.status
    : "active";
}

function parseStatus(value: unknown): ApplicationStatus {
  if (value === "active") return "active";
  if (value === "disabled") return "disabled";
  throw invalidRequest("Invalid status", { field: "status" });
}

function isRecord(value: unknown): value is AnyRecord {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isFiniteNumber(value: unknown): value is number {
  return typeof value === "number" && Number.isFinite(value);
}
