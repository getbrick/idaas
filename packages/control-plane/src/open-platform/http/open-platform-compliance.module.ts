import {
  Inject,
  Injectable,
  Module,
  type DynamicModule,
  type OnModuleInit,
  type Provider,
} from "@nestjs/common";
import { configurationError } from "../errors.js";
import {
  isDevelopmentOpenPlatformAuthorization,
  type OpenPlatformAuthorizationPort,
  type OpenPlatformRequestContextIssuer,
} from "../authorization.js";
import {
  createComplianceAuthorizationAdapter,
  createDevelopmentComplianceAuthorization,
  createUnavailableComplianceAuthorization,
  isComplianceAuthorizationPort,
  isComplianceAuthorizationProductionReady,
  type ComplianceAuthorizationPort,
} from "../compliance/authorization.js";
import {
  createComplianceAuditBridge,
  type ComplianceAuditPort,
} from "../compliance/events.js";
import { createInMemoryComplianceAuditStore } from "../compliance/events.js";
import {
  createInMemoryComplianceIdempotencyStore,
  isComplianceIdempotencyPort,
  isComplianceIdempotencyProductionReady,
  type ComplianceIdempotencyPort,
} from "../compliance/idempotency.js";
import { createInMemoryComplianceRepositories } from "../compliance/repositories.js";
import {
  ComplianceDomainService,
  type ComplianceServiceOptions,
} from "../compliance/service.js";
import type { OpenPlatformAuditPort } from "../audit.js";
import { OpenPlatformHttpContextGuard } from "./open-platform-http.guard.js";
import { OpenPlatformHttpResponseInterceptor } from "./open-platform-http.interceptor.js";
import { OpenPlatformComplianceHttpExceptionFilter } from "./open-platform-compliance.filter.js";
import { OpenPlatformComplianceController } from "./open-platform-compliance.controller.js";
import { OpenPlatformComplianceIdempotency } from "./open-platform-compliance.idempotency.js";
import { OpenPlatformComplianceSecurity } from "./open-platform-compliance.security.js";
import {
  OPEN_PLATFORM_HTTP_CONTEXT_ISSUER,
  OPEN_PLATFORM_HTTP_CONTEXT_RESOLVER,
  OPEN_PLATFORM_HTTP_MODE,
  type OpenPlatformHttpContextResolver,
  type OpenPlatformHttpContextResolverLike,
} from "./open-platform-http.types.js";
import {
  OPEN_PLATFORM_COMPLIANCE_AUTHORIZATION,
  OPEN_PLATFORM_COMPLIANCE_AUDIT,
  OPEN_PLATFORM_COMPLIANCE_IDEMPOTENCY,
  OPEN_PLATFORM_COMPLIANCE_MODE,
  OPEN_PLATFORM_COMPLIANCE_SERVICE,
  type OpenPlatformComplianceService,
} from "./open-platform-compliance.tokens.js";

export {
  OPEN_PLATFORM_COMPLIANCE_AUTHORIZATION,
  OPEN_PLATFORM_COMPLIANCE_AUDIT,
  OPEN_PLATFORM_COMPLIANCE_IDEMPOTENCY,
  OPEN_PLATFORM_COMPLIANCE_MODE,
  OPEN_PLATFORM_COMPLIANCE_SERVICE,
};
export type { OpenPlatformComplianceService };
export { OpenPlatformComplianceController } from "./open-platform-compliance.controller.js";
export {
  OpenPlatformComplianceIdempotency,
  COMPLIANCE_IDEMPOTENCY_REPLAY_HEADER,
} from "./open-platform-compliance.idempotency.js";
export {
  OpenPlatformComplianceSecurity,
  COMPLIANCE_AUDIT_METADATA_FIELDS,
  allowlistedComplianceAuditMetadata,
} from "./open-platform-compliance.security.js";
export {
  OpenPlatformComplianceHttpExceptionFilter,
  toOpenPlatformComplianceHttpError,
} from "./open-platform-compliance.filter.js";
export { OPEN_PLATFORM_COMPLIANCE_BASE_PATH } from "./open-platform-compliance.controller.js";
export {
  createDevelopmentComplianceAuthorization,
  createUnavailableComplianceAuthorization,
  isComplianceAuthorizationProductionReady,
} from "../compliance/authorization.js";
export {
  createInMemoryComplianceAuditStore,
  createComplianceAuditBridge,
} from "../compliance/events.js";
export { createInMemoryComplianceIdempotencyStore } from "../compliance/idempotency.js";
export { createInMemoryComplianceRepositories } from "../compliance/repositories.js";

export type {
  ComplianceAuditPort,
  ComplianceAuthorizationPort,
  ComplianceIdempotencyPort,
};

export interface OpenPlatformComplianceModuleOptions {
  readonly service?: OpenPlatformComplianceService;
  readonly complianceService?: OpenPlatformComplianceService;
  readonly domainService?: OpenPlatformComplianceService;
  readonly repositories?: ComplianceServiceOptions["repositories"];
  readonly contextIssuer: OpenPlatformRequestContextIssuer;
  readonly mode?: "development" | "test" | "production";
  readonly resolver?: OpenPlatformHttpContextResolverLike;
  readonly requestContextResolver?: OpenPlatformHttpContextResolverLike;
  readonly contextResolver?: OpenPlatformHttpContextResolverLike;
  readonly clock?: () => Date;
  readonly production?: boolean;
  readonly slaPolicy?: ComplianceServiceOptions["slaPolicy"];
  readonly idGenerator?: ComplianceServiceOptions["idGenerator"];
  readonly authorization?: ComplianceAuthorizationPort;
  readonly complianceAuthorization?: ComplianceAuthorizationPort;
  readonly platformAuthorization?: OpenPlatformAuthorizationPort;
  readonly audit?: ComplianceAuditPort;
  readonly complianceAudit?: ComplianceAuditPort;
  readonly platformAudit?: OpenPlatformAuditPort;
  readonly idempotency?: ComplianceIdempotencyPort;
  readonly complianceIdempotency?: ComplianceIdempotencyPort;
  readonly idempotencyRetentionMs?: number;
  readonly idempotencyMaxEntries?: number;
  readonly eventPublisher?: ComplianceServiceOptions["eventPublisher"];
  readonly eventsEnabled?: ComplianceServiceOptions["eventsEnabled"];
  readonly requireAuthenticatedAssurance?: boolean;
}

export type OpenPlatformComplianceHttpModuleOptions =
  OpenPlatformComplianceModuleOptions;

@Injectable()
class OpenPlatformComplianceReadiness implements OnModuleInit {
  constructor(
    @Inject(OPEN_PLATFORM_COMPLIANCE_SERVICE)
    private readonly service: OpenPlatformComplianceService,
    @Inject(OPEN_PLATFORM_COMPLIANCE_MODE)
    private readonly mode: "development" | "test" | "production",
    @Inject(OpenPlatformComplianceSecurity)
    private readonly security: OpenPlatformComplianceSecurity,
    @Inject(OPEN_PLATFORM_COMPLIANCE_AUTHORIZATION)
    private readonly authorization: ComplianceAuthorizationPort,
    @Inject(OPEN_PLATFORM_COMPLIANCE_IDEMPOTENCY)
    private readonly idempotency: ComplianceIdempotencyPort,
  ) {}

  async onModuleInit(): Promise<void> {
    const security = await this.security.isReady();
    if (!security.ready) {
      throw new Error(security.authorizationReady
        ? "[getbrick-idaas] open platform compliance audit dependency is not ready"
        : "[getbrick-idaas] open platform compliance authorization is not ready");
    }
    if (
      this.mode === "production" &&
      !isComplianceAuthorizationProductionReady(this.authorization)
    ) {
      throw new Error(
        "[getbrick-idaas] production compliance requires a production authorization port",
      );
    }
    if (this.mode === "production" && this.idempotency.productionReady !== true) {
      throw new Error(
        "[getbrick-idaas] production compliance requires a production idempotency port",
      );
    }
    if (typeof this.service.isReady !== "function") {
      if (this.mode === "production") {
        throw new Error("[getbrick-idaas] production compliance readiness is unavailable");
      }
      return;
    }
    const ready: unknown = this.service.isReady();
    const resolved: unknown = ready instanceof Promise ? await ready : ready;
    if (typeof resolved !== "boolean") {
      throw new Error("[getbrick-idaas] open platform compliance readiness is invalid");
    }
    if (!resolved) {
      throw new Error("[getbrick-idaas] open platform compliance storage is not ready");
    }
    if (this.mode === "production") {
      const storage = this.service.repositories?.readiness;
      if (
        storage !== undefined &&
        (storage.storage !== "persistent" || !storage.distributed)
      ) {
        throw new Error(
          "[getbrick-idaas] production compliance requires persistent distributed storage",
        );
      }
    }
  }
}

@Module({})
export class OpenPlatformComplianceModule {
  static forRoot(options: OpenPlatformComplianceModuleOptions): DynamicModule {
    if (options === null || typeof options !== "object") {
      throw configurationError("Open platform compliance HTTP configuration is required");
    }
    if (
      options.contextIssuer === null ||
      typeof options.contextIssuer !== "object" ||
      typeof options.contextIssuer.issueAuthenticated !== "function" ||
      typeof options.contextIssuer.issueDevelopment !== "function"
    ) {
      throw configurationError("Open platform compliance context issuer is invalid");
    }
    const suppliedService = options.service ??
      options.complianceService ??
      options.domainService;
    const suppliedServiceCount = [options.service, options.complianceService, options.domainService]
      .filter((value) => value !== undefined).length;
    if (suppliedServiceCount > 1) {
      throw configurationError("Open platform compliance service options conflict");
    }
    if (suppliedService !== undefined && options.repositories !== undefined) {
      throw configurationError(
        "Open platform compliance service and repositories are mutually exclusive",
      );
    }
    const mode = options.mode ?? "development";
    if (mode !== "development" && mode !== "test" && mode !== "production") {
      throw configurationError("Open platform compliance mode is invalid");
    }
    const resolver = normalizeComplianceResolver(options);
    if (mode === "production" && resolver === undefined) {
      throw configurationError("Production open platform compliance requires a context resolver");
    }
    const production = options.production ?? mode === "production";
    const authorization = resolveComplianceAuthorization(options, mode);
    const audit = resolveComplianceAudit(options, production, suppliedService);
    const idempotency = resolveComplianceIdempotency(options, production);
    const service = suppliedService ?? new ComplianceDomainService({
      ...(options.repositories === undefined
        ? {}
        : { repositories: options.repositories ?? createInMemoryComplianceRepositories() }),
      ...(options.clock === undefined ? {} : { clock: options.clock }),
      ...(options.idGenerator === undefined ? {} : { idGenerator: options.idGenerator }),
      ...(options.slaPolicy === undefined ? {} : { slaPolicy: options.slaPolicy }),
      ...(options.eventPublisher === undefined
        ? {}
        : { eventPublisher: options.eventPublisher }),
      ...(options.eventsEnabled === undefined ? {} : { eventsEnabled: options.eventsEnabled }),
      audit,
      production,
    });
    if (
      options.audit !== undefined &&
      suppliedService !== undefined &&
      service.audit !== audit
    ) {
      throw configurationError(
        "Open platform compliance service and audit port are mutually exclusive",
      );
    }
    const providers: Provider[] = [
      { provide: OPEN_PLATFORM_COMPLIANCE_SERVICE, useValue: service },
      { provide: ComplianceDomainService, useValue: service },
      { provide: OPEN_PLATFORM_COMPLIANCE_MODE, useValue: mode },
      {
        provide: OPEN_PLATFORM_COMPLIANCE_AUTHORIZATION,
        useValue: authorization,
      },
      { provide: OPEN_PLATFORM_COMPLIANCE_AUDIT, useValue: audit },
      { provide: OPEN_PLATFORM_COMPLIANCE_IDEMPOTENCY, useValue: idempotency },
      {
        provide: OPEN_PLATFORM_HTTP_CONTEXT_RESOLVER,
        useValue: resolver,
      },
      {
        provide: OPEN_PLATFORM_HTTP_CONTEXT_ISSUER,
        useValue: options.contextIssuer,
      },
      { provide: OPEN_PLATFORM_HTTP_MODE, useValue: mode },
      OpenPlatformHttpContextGuard,
      OpenPlatformComplianceHttpExceptionFilter,
      OpenPlatformHttpResponseInterceptor,
      OpenPlatformComplianceSecurity,
      OpenPlatformComplianceIdempotency,
      OpenPlatformComplianceReadiness,
    ];
    return {
      module: OpenPlatformComplianceModule,
      controllers: [OpenPlatformComplianceController],
      providers,
      exports: [
        OPEN_PLATFORM_COMPLIANCE_SERVICE,
        ComplianceDomainService,
        OPEN_PLATFORM_COMPLIANCE_MODE,
        OPEN_PLATFORM_COMPLIANCE_AUTHORIZATION,
        OPEN_PLATFORM_COMPLIANCE_AUDIT,
        OPEN_PLATFORM_COMPLIANCE_IDEMPOTENCY,
        OpenPlatformComplianceSecurity,
        OpenPlatformComplianceIdempotency,
        OPEN_PLATFORM_HTTP_CONTEXT_RESOLVER,
        OPEN_PLATFORM_HTTP_CONTEXT_ISSUER,
        OPEN_PLATFORM_HTTP_MODE,
      ],
    };
  }
}

export function createOpenPlatformComplianceModule(
  options: OpenPlatformComplianceModuleOptions,
): DynamicModule {
  return OpenPlatformComplianceModule.forRoot(options);
}

export const createOpenPlatformComplianceHttpModule =
  createOpenPlatformComplianceModule;
export const OpenPlatformComplianceHttpModule = OpenPlatformComplianceModule;

function resolveComplianceAuthorization(
  options: OpenPlatformComplianceModuleOptions,
  mode: "development" | "test" | "production",
): ComplianceAuthorizationPort {
  const supplied = [options.authorization, options.complianceAuthorization]
    .filter((value) => value !== undefined);
  if (supplied.length > 1) {
    throw configurationError("Open platform compliance authorization options conflict");
  }
  const candidate = supplied[0];
  if (candidate !== undefined) {
    if (!isComplianceAuthorizationPort(candidate)) {
      throw configurationError("Open platform compliance authorization port is invalid");
    }
    if (mode === "production" && !isComplianceAuthorizationProductionReady(candidate)) {
      throw configurationError(
        "Production open platform compliance requires a production authorization port",
      );
    }
    return candidate;
  }
  if (options.platformAuthorization !== undefined) {
    const platform = options.platformAuthorization;
    if (
      platform === null ||
      typeof platform !== "object" ||
      typeof platform.authorize !== "function"
    ) {
      throw configurationError("Open platform compliance authorization port is invalid");
    }
    if (mode === "production" && isDevelopmentOpenPlatformAuthorization(platform)) {
      throw configurationError(
        "Development authorization cannot be used in production compliance",
      );
    }
    return createComplianceAuthorizationAdapter(platform, {
      ...(options.requireAuthenticatedAssurance === undefined
        ? {}
        : { requireAuthenticatedAssurance: options.requireAuthenticatedAssurance }),
    });
  }
  return mode === "production"
    ? createUnavailableComplianceAuthorization()
    : createDevelopmentComplianceAuthorization("all");
}

function resolveComplianceAudit(
  options: OpenPlatformComplianceModuleOptions,
  production: boolean,
  suppliedService: OpenPlatformComplianceService | undefined,
): ComplianceAuditPort {
  const supplied = [options.audit, options.complianceAudit]
    .filter((value) => value !== undefined);
  if (supplied.length > 1) {
    throw configurationError("Open platform compliance audit options conflict");
  }
  const candidate = supplied[0];
  if (candidate !== undefined) {
    if (
      candidate === null ||
      typeof candidate !== "object" ||
      typeof candidate.append !== "function"
    ) {
      throw configurationError("Open platform compliance audit port is invalid");
    }
    if (
      suppliedService !== undefined &&
      suppliedService.audit !== undefined &&
      suppliedService.audit !== candidate
    ) {
      throw configurationError(
        "Open platform compliance service and audit port are mutually exclusive",
      );
    }
    return candidate;
  }
  if (suppliedService?.audit !== undefined) return suppliedService.audit;
  if (options.platformAudit !== undefined) {
    const platform = options.platformAudit;
    if (platform === null || typeof platform !== "object" || typeof platform.append !== "function") {
      throw configurationError("Open platform compliance audit port is invalid");
    }
    return createComplianceAuditBridge(platform);
  }
  return createInMemoryComplianceAuditStore({
    ...(options.clock === undefined ? {} : { clock: options.clock }),
    production,
  });
}

function resolveComplianceIdempotency(
  options: OpenPlatformComplianceModuleOptions,
  production: boolean,
): ComplianceIdempotencyPort {
  const supplied = [options.idempotency, options.complianceIdempotency]
    .filter((value) => value !== undefined);
  if (supplied.length > 1) {
    throw configurationError("Open platform compliance idempotency options conflict");
  }
  const candidate = supplied[0];
  if (candidate !== undefined) {
    if (!isComplianceIdempotencyPort(candidate)) {
      throw configurationError("Open platform compliance idempotency port is invalid");
    }
    if (production && !isComplianceIdempotencyProductionReady(candidate)) {
      throw configurationError(
        "Production open platform compliance requires a production idempotency port",
      );
    }
    return candidate;
  }
  if (production) {
    throw configurationError(
      "Production open platform compliance requires an idempotency port",
    );
  }
  return createInMemoryComplianceIdempotencyStore({
    ...(options.clock === undefined ? {} : { clock: options.clock }),
    ...(options.idempotencyRetentionMs === undefined
      ? {}
      : { retentionMs: options.idempotencyRetentionMs }),
    ...(options.idempotencyMaxEntries === undefined
      ? {}
      : { maxEntries: options.idempotencyMaxEntries }),
    production,
  });
}

function normalizeComplianceResolver(
  options: OpenPlatformComplianceModuleOptions,
): OpenPlatformHttpContextResolver | undefined {
  const candidate = options.resolver ??
    options.requestContextResolver ??
    options.contextResolver;
  if (candidate === undefined || candidate === null) return undefined;
  if (typeof candidate === "function") {
    return { resolve: candidate };
  }
  if ("resolve" in candidate && typeof candidate.resolve === "function") {
    return { resolve: candidate.resolve.bind(candidate) };
  }
  if ("resolveContext" in candidate && typeof candidate.resolveContext === "function") {
    return { resolve: candidate.resolveContext.bind(candidate) };
  }
  throw configurationError("Open platform compliance context resolver is invalid");
}
