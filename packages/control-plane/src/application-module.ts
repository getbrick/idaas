import {
  Inject,
  Injectable,
  Module,
  Optional,
  type DynamicModule,
  type Provider,
  type OnModuleInit,
} from "@nestjs/common";
import type { IdaasProfile, RoleGraph } from "@getbrick/idaas-core";
import {
  GetbrickIdaasModule,
  type GetbrickAuthLike,
  type GetbrickGuardMode,
} from "@getbrick/idaas-nestjs";
import { ApplicationController } from "./application-controller.js";
import { ApplicationPlatformRuntimeController } from "./application-platform-controller.js";
import { InMemoryApplicationRepository } from "./application-repository.js";
import { ApplicationService } from "./application-service.js";
import {
  ApplicationPlatformAuthService,
  InMemoryApplicationPlatformIdentitySessionBoundary,
  InMemoryApplicationPlatformWebviewTicketService,
  type ApplicationPlatformAuthServiceOptions,
} from "./application-platform-service.js";
import type {
  ApplicationRepository,
  ApplicationServiceOptions,
  OpaqueClientSessionRepository,
  WebviewTicketRepository,
} from "./application-types.js";
import type { IdentityRepository } from "./identity.js";
import type { SecretBindingRepository } from "./secret-binding.js";
import {
  assertTenantProductionSupported,
  normalizeTenantMode,
  type TenantConfigInput,
  type TenantMode,
  type TenantRepository,
} from "./tenant.js";

export const APPLICATION_MANAGEMENT_REPOSITORY = "APPLICATION_MANAGEMENT_REPOSITORY";
export const APPLICATION_MANAGEMENT_READINESS = "APPLICATION_MANAGEMENT_READINESS";
export const APPLICATION_TENANT_REPOSITORY = "APPLICATION_TENANT_REPOSITORY";
export const APPLICATION_SECRET_BINDING_REPOSITORY = "APPLICATION_SECRET_BINDING_REPOSITORY";
export const APPLICATION_IDENTITY_REPOSITORY = "APPLICATION_IDENTITY_REPOSITORY";
export const APPLICATION_PLATFORM_SESSION_SERVICE = "APPLICATION_PLATFORM_SESSION_SERVICE";
export const APPLICATION_PLATFORM_WEBVIEW_TICKET_SERVICE = "APPLICATION_PLATFORM_WEBVIEW_TICKET_SERVICE";
export const APPLICATION_PLATFORM_IDENTITY_SESSION_BOUNDARY = "APPLICATION_PLATFORM_IDENTITY_SESSION_BOUNDARY";
export const APPLICATION_CLIENT_SESSION_REPOSITORY = "APPLICATION_CLIENT_SESSION_REPOSITORY";
export const APPLICATION_WEBVIEW_TICKET_REPOSITORY = "APPLICATION_WEBVIEW_TICKET_REPOSITORY";
export const APPLICATION_REPOSITORY = APPLICATION_MANAGEMENT_REPOSITORY;
export const APPLICATION_MANAGEMENT_REPOSITORY_TOKEN = APPLICATION_MANAGEMENT_REPOSITORY;
export const APPLICATION_REPOSITORY_TOKEN = APPLICATION_MANAGEMENT_REPOSITORY;

export interface ApplicationManagementModuleOptions {
  auth?: GetbrickAuthLike;
  repository?: ApplicationRepository;
  applicationRepository?: ApplicationRepository;
  rbac?: RoleGraph;
  guard?: GetbrickGuardMode;
  globalGuard?: boolean;
  manualGuard?: boolean;
  basePath?: string;
  trustProxy?: boolean;
  profile?: IdaasProfile;
  readiness?: () => boolean | Promise<boolean>;
  service?: ApplicationServiceOptions;
  tenantRepository?: TenantRepository;
  secretBindingRepository?: SecretBindingRepository;
  identityRepository?: IdentityRepository;
  tenant?: TenantConfigInput;
  tenantConfig?: TenantConfigInput;
  tenantMode?: TenantMode | string;
  allowExperimentalShared?: boolean;
  sessionService?: ApplicationPlatformAuthServiceOptions["sessionService"];
  clientSessionService?: ApplicationPlatformAuthServiceOptions["clientSessionService"];
  clientSessionRepository?: OpaqueClientSessionRepository;
  webviewTicketRepository?: WebviewTicketRepository;
  webviewTicketService?: ApplicationPlatformAuthServiceOptions["webviewTicketService"];
  identitySessionBoundary?: ApplicationPlatformAuthServiceOptions["identitySessionBoundary"];
  hostTransaction?: ApplicationPlatformAuthServiceOptions["hostTransaction"];
  requireOpaqueClientSession?: boolean;
  platformAuth?: Omit<ApplicationPlatformAuthServiceOptions, "registry"> & {
    registry?: ApplicationPlatformAuthServiceOptions["registry"];
  };
}

@Injectable()
class ApplicationManagementReadiness implements OnModuleInit {
  constructor(
    @Optional()
    @Inject(APPLICATION_MANAGEMENT_READINESS)
    private readonly check?: () => boolean | Promise<boolean>,
  ) {}

  async onModuleInit(): Promise<void> {
    if (typeof this.check !== "function") return;
    if (!(await this.check())) {
      throw new Error("[getbrick-idaas] application management storage is not ready");
    }
  }
}

@Module({
      controllers: [ApplicationController, ApplicationPlatformRuntimeController],

  providers: [
    {
      provide: APPLICATION_MANAGEMENT_REPOSITORY,
      useFactory: () => new InMemoryApplicationRepository(),
    },
    {
      provide: ApplicationService,
      useFactory: (repository: ApplicationRepository) => new ApplicationService(repository),
      inject: [APPLICATION_MANAGEMENT_REPOSITORY],
    },
  ],
  exports: [APPLICATION_MANAGEMENT_REPOSITORY, ApplicationService],
})
export class ApplicationManagementModule {
  static forRoot(options: ApplicationManagementModuleOptions = {}): DynamicModule {
    const profile = options.profile ?? (process.env.NODE_ENV === "production" ? "production" : undefined);
    if (profile === "production" && !options.auth) {
      throw new Error("[getbrick-idaas] production application management requires authentication");
    }
    const suppliedRepository = options.repository ?? options.applicationRepository;
    if (profile === "production" && !suppliedRepository) {
      throw new Error("[getbrick-idaas] production application management requires a persistent repository");
    }
    if (profile === "production" && suppliedRepository instanceof InMemoryApplicationRepository) {
      throw new Error("[getbrick-idaas] production application management cannot use an in-memory repository");
    }
    const repository = suppliedRepository ?? new InMemoryApplicationRepository();
    const clientSessionRepository = options.clientSessionRepository ?? options.platformAuth?.clientSessionRepository;
    const webviewTicketRepository = options.webviewTicketRepository ?? options.platformAuth?.webviewTicketRepository;
     const platformSessionIssuer = options.platformAuth?.sessionIssuer ?? options.platformAuth?.login?.sessionIssuer ?? options.platformAuth?.loginFlow?.sessionIssuer ?? options.platformAuth?.platformLogin?.sessionIssuer;
     const platformSessionService = options.sessionService ?? options.clientSessionService ?? options.platformAuth?.sessionService ?? options.platformAuth?.clientSessionService ?? options.platformAuth?.login?.sessionService ?? options.platformAuth?.login?.clientSessionService ?? options.platformAuth?.loginFlow?.sessionService ?? options.platformAuth?.loginFlow?.clientSessionService ?? options.platformAuth?.platformLogin?.sessionService ?? options.platformAuth?.platformLogin?.clientSessionService ?? (isOpaqueSessionServiceLike(platformSessionIssuer) ? platformSessionIssuer : undefined);
     const platformStateStore = options.platformAuth?.stateStore ?? options.platformAuth?.login?.stateStore ?? options.platformAuth?.loginFlow?.stateStore ?? options.platformAuth?.platformLogin?.stateStore;
     const platformStateManager = options.platformAuth?.stateManager ?? options.platformAuth?.login?.stateManager ?? options.platformAuth?.loginFlow?.stateManager ?? options.platformAuth?.platformLogin?.stateManager;
     const platformIdentityBoundary = options.identitySessionBoundary ?? options.platformAuth?.identitySessionBoundary ?? options.platformAuth?.login?.identitySessionBoundary ?? options.platformAuth?.loginFlow?.identitySessionBoundary ?? options.platformAuth?.platformLogin?.identitySessionBoundary;
     const platformWebviewTicketService = options.webviewTicketService ?? options.platformAuth?.webviewTicketService ?? options.platformAuth?.login?.webviewTicketService ?? options.platformAuth?.loginFlow?.webviewTicketService ?? options.platformAuth?.platformLogin?.webviewTicketService;
     if (profile === "production") {
       assertPersistentProductionDependency(platformStateStore, "platform login state store");
       assertPersistentProductionDependency(platformStateManager, "platform login state manager");
       assertPersistentProductionDependency(platformIdentityBoundary, "identity session boundary");
       assertPersistentProductionDependency(platformWebviewTicketService, "webview ticket service");
       if (platformIdentityBoundary instanceof InMemoryApplicationPlatformIdentitySessionBoundary || platformWebviewTicketService instanceof InMemoryApplicationPlatformWebviewTicketService) {
         throw new Error("[getbrick-idaas] production application management cannot use in-memory platform authentication helpers");
       }
     }
     const tenantMode = resolveApplicationTenantMode(options, repository);
    if (profile === "production" && tenantMode === "shared" && options.allowExperimentalShared !== true) {
      assertTenantProductionSupported(tenantMode, profile);
    }
     const readinessChecks = [
       repository.isReady?.bind(repository),
       readinessOf(repository),
       options.tenantRepository?.isReady.bind(options.tenantRepository),
       options.tenantRepository === undefined ? undefined : readinessOf(options.tenantRepository),
       options.identityRepository?.isReady.bind(options.identityRepository),
       options.identityRepository === undefined ? undefined : readinessOf(options.identityRepository),
       options.secretBindingRepository?.isReady.bind(options.secretBindingRepository),
       options.secretBindingRepository === undefined ? undefined : readinessOf(options.secretBindingRepository),
        readinessOf(platformSessionService),
        readinessOf(clientSessionRepository),
        readinessOf(platformSessionIssuer),
        readinessOf(platformStateStore),
        readinessOf(platformStateManager),
        readinessOf(platformIdentityBoundary),
        readinessOf(platformWebviewTicketService),


        readinessOf(webviewTicketRepository),
        readinessOf(options.webviewTicketService ?? options.platformAuth?.webviewTicketService),
        readinessOf(options.platformAuth?.webviewTicketRepository),

     ].map(normalizeReadinessCheck).filter((check): check is () => boolean | Promise<boolean> => typeof check === "function");
     const readiness = options.readiness ?? (readinessChecks.length === 0
       ? undefined
       : async () => {
           for (const check of readinessChecks) {
             if (!(await check())) return false;
           }
           return true;
         });

    if (profile === "production" && !readiness) {
      throw new Error("[getbrick-idaas] production application management requires a storage readiness check");
    }
    const providers: Provider[] = [
      { provide: APPLICATION_MANAGEMENT_REPOSITORY, useValue: repository },
      {
         provide: ApplicationService,
         useFactory: (value: ApplicationRepository) => new ApplicationService(value, {
           ...options.service,
            secretBindings: options.service?.secretBindings ?? options.secretBindingRepository,
            requireSecretBindings: options.service?.requireSecretBindings ?? profile === "production",
            readiness: options.service?.readiness ?? readiness,
         }),

        inject: [APPLICATION_MANAGEMENT_REPOSITORY],
      },
     ];
     if (options.tenantRepository) {
       providers.push({ provide: APPLICATION_TENANT_REPOSITORY, useValue: options.tenantRepository });
     }
     if (options.secretBindingRepository) {
       providers.push({ provide: APPLICATION_SECRET_BINDING_REPOSITORY, useValue: options.secretBindingRepository });
     }
      if (options.identityRepository) {
        providers.push({ provide: APPLICATION_IDENTITY_REPOSITORY, useValue: options.identityRepository });
      }
      if (clientSessionRepository) {
        providers.push({ provide: APPLICATION_CLIENT_SESSION_REPOSITORY, useValue: clientSessionRepository });
      }
      if (webviewTicketRepository) {
        providers.push({ provide: APPLICATION_WEBVIEW_TICKET_REPOSITORY, useValue: webviewTicketRepository });
      }

      if (options.platformAuth) {
        const platformAuth = {
          ...options.platformAuth,
           ...(options.sessionService === undefined ? {} : { sessionService: options.sessionService }),
            ...(options.clientSessionService === undefined ? {} : { clientSessionService: options.clientSessionService }),
           ...(clientSessionRepository === undefined ? {} : { clientSessionRepository }),
           ...(webviewTicketRepository === undefined ? {} : { webviewTicketRepository }),
           ...(options.webviewTicketService === undefined ? {} : { webviewTicketService: options.webviewTicketService }),

          ...(options.identitySessionBoundary === undefined ? {} : { identitySessionBoundary: options.identitySessionBoundary }),
          ...(options.hostTransaction === undefined ? {} : { hostTransaction: options.hostTransaction }),
          ...(options.requireOpaqueClientSession === undefined ? {} : { requireOpaqueClientSession: options.requireOpaqueClientSession }),
        };
          if (profile === "production" && options.requireOpaqueClientSession === true && platformSessionService === undefined && platformSessionIssuer === undefined) {


          throw new Error("[getbrick-idaas] production native platform sessions require an opaque client session issuer");
        }
        providers.push({
          provide: ApplicationPlatformAuthService,
          useFactory: (value: ApplicationRepository) => new ApplicationPlatformAuthService(value, platformAuth),
          inject: [APPLICATION_MANAGEMENT_REPOSITORY],
        });
         const resolvedSessionService = platformSessionService ?? (isOpaqueSessionServiceLike(platformSessionIssuer) ? platformSessionIssuer : undefined);
         if (resolvedSessionService !== undefined) providers.push({ provide: APPLICATION_PLATFORM_SESSION_SERVICE, useValue: resolvedSessionService });

        if (platformAuth.webviewTicketService !== undefined) providers.push({ provide: APPLICATION_PLATFORM_WEBVIEW_TICKET_SERVICE, useValue: platformAuth.webviewTicketService });
        if (platformAuth.identitySessionBoundary !== undefined) providers.push({ provide: APPLICATION_PLATFORM_IDENTITY_SESSION_BOUNDARY, useValue: platformAuth.identitySessionBoundary });
      }
    if (readiness) {
      providers.push(
        { provide: APPLICATION_MANAGEMENT_READINESS, useValue: readiness },
        ApplicationManagementReadiness,
      );
    }
    const exports: Array<string | typeof ApplicationService | typeof ApplicationPlatformAuthService> = [
      APPLICATION_MANAGEMENT_REPOSITORY,
      ApplicationService,
    ];
     if (options.tenantRepository) exports.push(APPLICATION_TENANT_REPOSITORY);
     if (options.secretBindingRepository) exports.push(APPLICATION_SECRET_BINDING_REPOSITORY);
     if (options.identityRepository) exports.push(APPLICATION_IDENTITY_REPOSITORY);
     if (clientSessionRepository) exports.push(APPLICATION_CLIENT_SESSION_REPOSITORY);
     if (webviewTicketRepository) exports.push(APPLICATION_WEBVIEW_TICKET_REPOSITORY);
     if (options.platformAuth) {
       exports.push(ApplicationPlatformAuthService);
          if (platformSessionService !== undefined || isOpaqueSessionServiceLike(platformSessionIssuer)) exports.push(APPLICATION_PLATFORM_SESSION_SERVICE);


       if (options.webviewTicketService !== undefined || options.platformAuth.webviewTicketService !== undefined) exports.push(APPLICATION_PLATFORM_WEBVIEW_TICKET_SERVICE);
       if (options.identitySessionBoundary !== undefined || options.platformAuth.identitySessionBoundary !== undefined) exports.push(APPLICATION_PLATFORM_IDENTITY_SESSION_BOUNDARY);
     }

    const imports = options.auth
      ? [
          GetbrickIdaasModule.forRoot({
             auth: options.auth,
             rbac: options.rbac,
             guard: options.guard,

             globalGuard: options.globalGuard,
             manualGuard: options.manualGuard,
             basePath: options.basePath,
             trustProxy: options.trustProxy,
          }),
        ]
      : [];
    return {
      module: ApplicationManagementModule,
      imports,
  controllers: [ApplicationController, ApplicationPlatformRuntimeController],

      providers,
      exports,
    };
  }
}

function resolveApplicationTenantMode(
  options: ApplicationManagementModuleOptions,
  repository: ApplicationRepository,
): TenantMode {
  const candidate = options.tenant?.mode ?? options.tenantConfig?.mode ?? options.tenantMode ?? (repository as ApplicationRepository & { tenant?: { mode?: TenantMode } }).tenant?.mode;
  return normalizeTenantMode(candidate);
}

function assertPersistentProductionDependency(value: unknown, label: string): void {
  if (value === null || typeof value !== "object") return;
  if ((value as { persistent?: unknown }).persistent === false) {
    throw new Error(`[getbrick-idaas] production application management requires a persistent ${label}`);
  }
}

function readinessOf(value: unknown): (() => boolean | Promise<boolean>) | undefined {
  if (value === null || typeof value !== "object") return undefined;
  const record = value as { ready?: unknown; readiness?: unknown; isReady?: unknown };
  const ready = typeof record.ready === "function" ? record.ready : typeof record.readiness === "function" ? record.readiness : typeof record.isReady === "function" ? record.isReady : undefined;
  return typeof ready === "function" ? () => Promise.resolve(ready.call(value)).then(readinessValue) : undefined;
}

function normalizeReadinessCheck(value: unknown): (() => boolean | Promise<boolean>) | undefined {
  if (typeof value !== "function") return undefined;
  return async () => readinessValue(await (value as () => unknown)());
}

function isOpaqueSessionServiceLike(value: unknown): boolean {
  if (value === null || typeof value !== "object") return false;
  const record = value as Record<string, unknown>;
  return typeof record.issue === "function" &&
    (typeof record.refresh === "function" || typeof record.refreshSession === "function") &&
    (typeof record.logout === "function" || typeof record.logoutSession === "function") &&
    (typeof record.revoke === "function" || typeof record.revokeSession === "function");
}

function readinessValue(value: unknown): boolean {
  if (typeof value === "boolean") return value;
  if (value !== null && typeof value === "object" && "ready" in value) return (value as { ready?: unknown }).ready === true;
  return false;
}

export { ApplicationManagementModule as ApplicationsModule };
