import {
  Inject,
  Injectable,
  Module,
  type DynamicModule,
  type OnModuleInit,
  type Provider,
} from "@nestjs/common";
import {
  configurationError,
} from "../errors.js";
import {
  isDevelopmentOpenPlatformAuthorization,
  type OpenPlatformAuthorizationPort,
  type OpenPlatformRequestContextIssuer,
} from "../authorization.js";
import {
  createCommerceAuthorizationAdapter,
  createDevelopmentCommerceAuthorization,
  createUnavailableCommerceAuthorization,
  isCommerceAuthorizationPort,
  isCommerceAuthorizationProductionReady,
  type CommerceAuthorizationPort,
} from "../commerce/authorization.js";
import {
  createCommerceAuditAdapter,
  createInMemoryCommerceAuditEventStore,
  type CommerceAuditPort,
} from "../commerce/audit.js";
import {
  createInMemoryCommerceIdempotencyStore,
  isCommerceIdempotencyPort,
  type CommerceIdempotencyPort,
} from "../commerce/idempotency.js";
import {
  CommerceDomainService,
  type CommerceServiceOptions,
} from "../commerce/service.js";
import type { CommerceRepositories } from "../commerce/types.js";
import type { OpenPlatformAuditPort } from "../audit.js";
import { OpenPlatformHttpContextGuard } from "./open-platform-http.guard.js";
import { OpenPlatformHttpResponseInterceptor } from "./open-platform-http.interceptor.js";
import { OpenPlatformCommerceHttpExceptionFilter } from "./open-platform-commerce.filter.js";
import { OpenPlatformCommerceController } from "./open-platform-commerce.controller.js";
import { OpenPlatformCommerceSecurity } from "./open-platform-commerce.security.js";
import {
  OPEN_PLATFORM_HTTP_CONTEXT_ISSUER,
  OPEN_PLATFORM_HTTP_CONTEXT_RESOLVER,
  OPEN_PLATFORM_HTTP_MODE,
  type OpenPlatformHttpContextResolver,
  type OpenPlatformHttpContextResolverLike,
} from "./open-platform-http.types.js";
import {
  OPEN_PLATFORM_COMMERCE_AUTHORIZATION,
  OPEN_PLATFORM_COMMERCE_AUDIT,
  OPEN_PLATFORM_COMMERCE_IDEMPOTENCY,
  OPEN_PLATFORM_COMMERCE_MODE,
  OPEN_PLATFORM_COMMERCE_SERVICE,
  type OpenPlatformCommerceService,
} from "./open-platform-commerce.tokens.js";

export {
  OPEN_PLATFORM_COMMERCE_AUTHORIZATION,
  OPEN_PLATFORM_COMMERCE_AUDIT,
  OPEN_PLATFORM_COMMERCE_IDEMPOTENCY,
  OPEN_PLATFORM_COMMERCE_MODE,
  OPEN_PLATFORM_COMMERCE_SERVICE,
};
export type { OpenPlatformCommerceService };
export { OpenPlatformCommerceController } from "./open-platform-commerce.controller.js";
export {
  OpenPlatformCommerceSecurity,
  COMMERCE_AUDIT_METADATA_FIELDS,
  allowlistedCommerceAuditMetadata,
} from "./open-platform-commerce.security.js";
export {
  OpenPlatformCommerceHttpExceptionFilter,
  toOpenPlatformCommerceHttpError,
} from "./open-platform-commerce.filter.js";
export {
  createDevelopmentCommerceAuthorization,
  createUnavailableCommerceAuthorization,
  isCommerceAuthorizationProductionReady,
} from "../commerce/authorization.js";
export {
  createInMemoryCommerceAuditEventStore,
  createCommerceAuditAdapter,
} from "../commerce/audit.js";
export { createInMemoryCommerceIdempotencyStore } from "../commerce/idempotency.js";

export type { CommerceAuditPort, CommerceAuthorizationPort, CommerceIdempotencyPort };

export interface OpenPlatformCommerceModuleOptions {
  readonly service?: OpenPlatformCommerceService;
  readonly commerceService?: OpenPlatformCommerceService;
  readonly domainService?: OpenPlatformCommerceService;
  readonly repositories?: CommerceRepositories;
  readonly contextIssuer: OpenPlatformRequestContextIssuer;
  readonly mode?: "development" | "test" | "production";
  readonly resolver?: OpenPlatformHttpContextResolverLike;
  readonly requestContextResolver?: OpenPlatformHttpContextResolverLike;
  readonly contextResolver?: OpenPlatformHttpContextResolverLike;
  readonly clock?: () => Date;
  readonly production?: boolean;
  readonly idGenerator?: CommerceServiceOptions["idGenerator"];
  readonly authorization?: CommerceAuthorizationPort;
  readonly commerceAuthorization?: CommerceAuthorizationPort;
  readonly platformAuthorization?: OpenPlatformAuthorizationPort;
  readonly audit?: CommerceAuditPort;
  readonly commerceAudit?: CommerceAuditPort;
  readonly platformAudit?: OpenPlatformAuditPort;
  readonly idempotency?: CommerceIdempotencyPort;
  readonly commerceIdempotency?: CommerceIdempotencyPort;
  readonly idempotencyRetentionMs?: CommerceServiceOptions["idempotencyRetentionMs"];
  readonly idempotencyMaxEntries?: CommerceServiceOptions["idempotencyMaxEntries"];
  readonly eventPublisher?: CommerceServiceOptions["eventPublisher"];
  readonly eventsEnabled?: CommerceServiceOptions["eventsEnabled"];
}

export type OpenPlatformCommerceHttpModuleOptions =
  OpenPlatformCommerceModuleOptions;

@Injectable()
class OpenPlatformCommerceReadiness implements OnModuleInit {
  constructor(
    @Inject(OPEN_PLATFORM_COMMERCE_SERVICE)
    private readonly service: OpenPlatformCommerceService,
    @Inject(OPEN_PLATFORM_COMMERCE_MODE)
    private readonly mode: "development" | "test" | "production",
    @Inject(OpenPlatformCommerceSecurity)
    private readonly security: OpenPlatformCommerceSecurity,
    @Inject(OPEN_PLATFORM_COMMERCE_AUTHORIZATION)
    private readonly authorization: CommerceAuthorizationPort,
  ) {}

  async onModuleInit(): Promise<void> {
    const security = await this.security.isReady();
    if (!security.ready) {
      throw new Error(security.authorizationReady
        ? "[getbrick-idaas] open platform commerce audit dependency is not ready"
        : "[getbrick-idaas] open platform commerce authorization is not ready");
    }
    if (
      this.mode === "production" &&
      !isCommerceAuthorizationProductionReady(this.authorization)
    ) {
      throw new Error(
        "[getbrick-idaas] production commerce requires a production authorization port",
      );
    }
    if (typeof this.service.isReady !== "function") {
      if (this.mode === "production") {
        throw new Error("[getbrick-idaas] production commerce readiness is unavailable");
      }
      return;
    }
    const readiness = await this.service.isReady();
    if (
      readiness === null ||
      typeof readiness !== "object" ||
      typeof readiness.ready !== "boolean"
    ) {
      throw new Error("[getbrick-idaas] open platform commerce readiness is invalid");
    }
    if (!readiness.ready) {
      throw new Error("[getbrick-idaas] open platform commerce storage is not ready");
    }
    if (
      this.mode === "production" &&
      (readiness.storage !== "persistent" || !readiness.distributed)
    ) {
      throw new Error("[getbrick-idaas] production commerce requires persistent distributed storage");
    }
  }
}

@Module({})
export class OpenPlatformCommerceModule {
  static forRoot(options: OpenPlatformCommerceModuleOptions): DynamicModule {
    if (options === null || typeof options !== "object") {
      throw configurationError("Open platform commerce HTTP configuration is required");
    }
    if (
      options.contextIssuer === null ||
      typeof options.contextIssuer !== "object" ||
      typeof options.contextIssuer.issueAuthenticated !== "function" ||
      typeof options.contextIssuer.issueDevelopment !== "function"
    ) {
      throw configurationError("Open platform commerce context issuer is invalid");
    }
    const suppliedService = options.service ?? options.commerceService ?? options.domainService;
    const suppliedServiceCount = [options.service, options.commerceService, options.domainService]
      .filter((value) => value !== undefined).length;
    if (suppliedServiceCount > 1) {
      throw configurationError("Open platform commerce service options conflict");
    }
    if (suppliedService !== undefined && options.repositories !== undefined) {
      throw configurationError("Open platform commerce service and repositories are mutually exclusive");
    }
    const mode = options.mode ?? "development";
    if (mode !== "development" && mode !== "test" && mode !== "production") {
      throw configurationError("Open platform commerce mode is invalid");
    }
    const resolver = normalizeCommerceResolver(options);
    if (mode === "production" && resolver === undefined) {
      throw configurationError("Production open platform commerce requires a context resolver");
    }
    const production = options.production ?? mode === "production";
    const authorization = resolveCommerceAuthorization(options, mode);
    const audit = resolveCommerceAudit(options, production);
    const idempotency = resolveCommerceIdempotency(options, production);
    const service = suppliedService ?? new CommerceDomainService({
      ...(options.repositories === undefined ? {} : { repositories: options.repositories }),
      ...(options.clock === undefined ? {} : { clock: options.clock }),
      ...(options.idGenerator === undefined ? {} : { idGenerator: options.idGenerator }),
      idempotency,
      ...(options.idempotencyRetentionMs === undefined
        ? {}
        : { idempotencyRetentionMs: options.idempotencyRetentionMs }),
      ...(options.idempotencyMaxEntries === undefined
        ? {}
        : { idempotencyMaxEntries: options.idempotencyMaxEntries }),
      ...(options.eventPublisher === undefined
        ? {}
        : { eventPublisher: options.eventPublisher }),
      ...(options.eventsEnabled === undefined ? {} : { eventsEnabled: options.eventsEnabled }),
      audit,
      production,
    });
    if (
      options.idempotency !== undefined &&
      suppliedService !== undefined &&
      service.idempotency !== idempotency
    ) {
      throw configurationError(
        "Open platform commerce service and idempotency port are mutually exclusive",
      );
    }
    const providers: Provider[] = [
      { provide: OPEN_PLATFORM_COMMERCE_SERVICE, useValue: service },
      { provide: CommerceDomainService, useValue: service },
      { provide: OPEN_PLATFORM_COMMERCE_MODE, useValue: mode },
      {
        provide: OPEN_PLATFORM_COMMERCE_AUTHORIZATION,
        useValue: authorization,
      },
      { provide: OPEN_PLATFORM_COMMERCE_AUDIT, useValue: audit },
      { provide: OPEN_PLATFORM_COMMERCE_IDEMPOTENCY, useValue: idempotency },
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
      OpenPlatformCommerceHttpExceptionFilter,
      OpenPlatformHttpResponseInterceptor,
      OpenPlatformCommerceSecurity,
      OpenPlatformCommerceReadiness,
    ];
    return {
      module: OpenPlatformCommerceModule,
      controllers: [OpenPlatformCommerceController],
      providers,
      exports: [
        OPEN_PLATFORM_COMMERCE_SERVICE,
        CommerceDomainService,
        OPEN_PLATFORM_COMMERCE_MODE,
        OPEN_PLATFORM_COMMERCE_AUTHORIZATION,
        OPEN_PLATFORM_COMMERCE_AUDIT,
        OPEN_PLATFORM_COMMERCE_IDEMPOTENCY,
        OpenPlatformCommerceSecurity,
        OPEN_PLATFORM_HTTP_CONTEXT_RESOLVER,
        OPEN_PLATFORM_HTTP_CONTEXT_ISSUER,
        OPEN_PLATFORM_HTTP_MODE,
      ],
    };
  }
}

export function createOpenPlatformCommerceModule(
  options: OpenPlatformCommerceModuleOptions,
): DynamicModule {
  return OpenPlatformCommerceModule.forRoot(options);
}

export const createOpenPlatformCommerceHttpModule =
  createOpenPlatformCommerceModule;
export const OpenPlatformCommerceHttpModule = OpenPlatformCommerceModule;

function resolveCommerceAuthorization(
  options: OpenPlatformCommerceModuleOptions,
  mode: "development" | "test" | "production",
): CommerceAuthorizationPort {
  const supplied = [options.authorization, options.commerceAuthorization]
    .filter((value) => value !== undefined);
  if (supplied.length > 1) {
    throw configurationError("Open platform commerce authorization options conflict");
  }
  const candidate = supplied[0];
  if (candidate !== undefined) {
    if (!isCommerceAuthorizationPort(candidate)) {
      throw configurationError("Open platform commerce authorization port is invalid");
    }
    if (mode === "production" && !isCommerceAuthorizationProductionReady(candidate)) {
      throw configurationError(
        "Production open platform commerce requires a production authorization port",
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
      throw configurationError("Open platform commerce authorization port is invalid");
    }
    if (mode === "production" && isDevelopmentOpenPlatformAuthorization(platform)) {
      throw configurationError(
        "Development authorization cannot be used in production commerce",
      );
    }
    return createCommerceAuthorizationAdapter(platform);
  }
  return mode === "production"
    ? createUnavailableCommerceAuthorization()
    : createDevelopmentCommerceAuthorization("all");
}

function resolveCommerceAudit(
  options: OpenPlatformCommerceModuleOptions,
  production: boolean,
): CommerceAuditPort {
  const supplied = [options.audit, options.commerceAudit]
    .filter((value) => value !== undefined);
  if (supplied.length > 1) {
    throw configurationError("Open platform commerce audit options conflict");
  }
  const candidate = supplied[0];
  if (candidate !== undefined) {
    if (candidate === null || typeof candidate !== "object" || typeof candidate.append !== "function") {
      throw configurationError("Open platform commerce audit port is invalid");
    }
    return candidate;
  }
  if (options.platformAudit !== undefined) {
    const platform = options.platformAudit;
    if (platform === null || typeof platform !== "object" || typeof platform.append !== "function") {
      throw configurationError("Open platform commerce audit port is invalid");
    }
    return createCommerceAuditAdapter(platform);
  }
  return createInMemoryCommerceAuditEventStore({
    ...(options.clock === undefined ? {} : { clock: options.clock }),
    production,
  });
}

function resolveCommerceIdempotency(
  options: OpenPlatformCommerceModuleOptions,
  production: boolean,
): CommerceIdempotencyPort {
  const supplied = [options.idempotency, options.commerceIdempotency]
    .filter((value) => value !== undefined);
  if (supplied.length > 1) {
    throw configurationError("Open platform commerce idempotency options conflict");
  }
  const candidate = supplied[0];
  if (candidate !== undefined) {
    if (!isCommerceIdempotencyPort(candidate)) {
      throw configurationError("Open platform commerce idempotency port is invalid");
    }
    return candidate;
  }
  return createInMemoryCommerceIdempotencyStore({
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

function normalizeCommerceResolver(
  options: OpenPlatformCommerceModuleOptions,
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
  throw configurationError("Open platform commerce context resolver is invalid");
}
