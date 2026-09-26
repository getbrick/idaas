import {
  Inject,
  Injectable,
  Module,
  type DynamicModule,
  type OnModuleDestroy,
  type OnModuleInit,
  type Provider,
} from "@nestjs/common";
import type { OpenPlatformRequestContextIssuer } from "./authorization.js";
import { configurationError } from "./errors.js";
import {
  OpenPlatformEventRelay,
  createOpenPlatformEventRelay,
  isOpenPlatformEventRelay,
  type OpenPlatformEventRelayOptions,
} from "./events-relay.js";
import {
  OpenPlatformService,
  createOpenPlatformService,
} from "./service.js";
import type {
  OpenPlatformServiceOptions,
} from "./types.js";
import { OpenPlatformHttpController } from "./http/open-platform-http.controller.js";
import { OpenPlatformDomainEventsController } from "./http/open-platform-domain-events.controller.js";
import { OpenPlatformHttpContextGuard } from "./http/open-platform-http.guard.js";
import { OpenPlatformHttpExceptionFilter } from "./http/open-platform-http.filter.js";
import { OpenPlatformHttpResponseInterceptor } from "./http/open-platform-http.interceptor.js";
import {
  OPEN_PLATFORM_HTTP_CONTEXT_ISSUER,
  OPEN_PLATFORM_HTTP_CONTEXT_RESOLVER,
  OPEN_PLATFORM_HTTP_MODE,
  type OpenPlatformHttpContextResolver,
  type OpenPlatformHttpContextResolverLike,
} from "./http/open-platform-http.types.js";
import {
  OpenPlatformCommerceModule,
  type OpenPlatformCommerceModuleOptions,
} from "./http/open-platform-commerce.module.js";
import {
  OpenPlatformComplianceModule,
  type OpenPlatformComplianceModuleOptions,
} from "./http/open-platform-compliance.module.js";

export const OPEN_PLATFORM_SERVICE = "OPEN_PLATFORM_SERVICE";
export const OPEN_PLATFORM_AUTHORIZATION = "OPEN_PLATFORM_AUTHORIZATION";
export const OPEN_PLATFORM_REQUEST_CONTEXT_ISSUER =
  "OPEN_PLATFORM_REQUEST_CONTEXT_ISSUER";
export const OPEN_PLATFORM_OUTBOX = "OPEN_PLATFORM_OUTBOX";
export const OPEN_PLATFORM_EVENT_PUBLISHER = "OPEN_PLATFORM_EVENT_PUBLISHER";
export const OPEN_PLATFORM_EVENT_RELAY = "OPEN_PLATFORM_EVENT_RELAY";
export const OPEN_PLATFORM_EVENT_RELAY_ENABLED = "OPEN_PLATFORM_EVENT_RELAY_ENABLED";
export const OPEN_PLATFORM_WEBHOOK_SERVICE = "OPEN_PLATFORM_WEBHOOK_SERVICE";

export interface OpenPlatformProviderModuleOptions
  extends OpenPlatformServiceOptions {
  contextIssuer: OpenPlatformRequestContextIssuer;
}

interface OpenPlatformHttpResolverModuleOptions {
  resolver?: OpenPlatformHttpContextResolverLike;
  requestContextResolver?: OpenPlatformHttpContextResolverLike;
  contextResolver?: OpenPlatformHttpContextResolverLike;
}

export interface OpenPlatformHttpServiceModuleOptions
  extends OpenPlatformHttpResolverModuleOptions {
  service: OpenPlatformService;
  contextIssuer: OpenPlatformRequestContextIssuer;
  mode?: OpenPlatformServiceOptions["mode"];
  authorization?: OpenPlatformServiceOptions["authorization"];
}

export type OpenPlatformHttpModuleOptions =
  | (OpenPlatformProviderModuleOptions & OpenPlatformHttpResolverModuleOptions)
  | OpenPlatformHttpServiceModuleOptions;

@Injectable()
class OpenPlatformProviderReadiness implements OnModuleInit {
  constructor(
    @Inject(OPEN_PLATFORM_SERVICE)
    private readonly service: OpenPlatformService,
  ) {}

  async onModuleInit(): Promise<void> {
    const readiness = await this.service.isReady().catch(() => undefined);
    if (readiness?.ready === true) return;
    if (readiness !== undefined && readiness.events === false) {
      throw new Error("[getbrick-idaas] open platform domain event outbox is not ready");
    }
    throw new Error("[getbrick-idaas] open platform storage is not ready");
  }
}

@Module({})
export class OpenPlatformProviderModule {
  static forRoot(
    options: OpenPlatformProviderModuleOptions,
  ): DynamicModule {
    const service = createOpenPlatformService(options);
    const providers: Provider[] = [
      { provide: OPEN_PLATFORM_SERVICE, useValue: service },
      { provide: OpenPlatformService, useValue: service },
      {
        provide: OPEN_PLATFORM_AUTHORIZATION,
        useValue: options.authorization,
      },
      {
        provide: OPEN_PLATFORM_REQUEST_CONTEXT_ISSUER,
        useValue: options.contextIssuer,
      },
      { provide: OPEN_PLATFORM_OUTBOX, useValue: service.outbox },
      {
        provide: OPEN_PLATFORM_EVENT_PUBLISHER,
        useValue: service.eventPublisher,
      },
      { provide: OPEN_PLATFORM_WEBHOOK_SERVICE, useValue: service.webhooks },
      OpenPlatformProviderReadiness,
    ];
    return {
      module: OpenPlatformProviderModule,
      providers,
      exports: [
        OPEN_PLATFORM_SERVICE,
        OpenPlatformService,
        OPEN_PLATFORM_AUTHORIZATION,
        OPEN_PLATFORM_REQUEST_CONTEXT_ISSUER,
        OPEN_PLATFORM_OUTBOX,
        OPEN_PLATFORM_EVENT_PUBLISHER,
        OPEN_PLATFORM_WEBHOOK_SERVICE,
      ],
    };
  }
}

@Module({})
export class OpenPlatformHttpModule {
  static forRoot(
    options: OpenPlatformHttpModuleOptions,
  ): DynamicModule {
    if (options === null || typeof options !== "object") {
      throw configurationError("Open platform HTTP configuration is required");
    }
    const serviceBranch = "service" in options;
    if (
      serviceBranch &&
      (
        options.service === null ||
        typeof options.service !== "object" ||
        typeof options.service.isReady !== "function" ||
        !isHttpRuntimeMode(options.service.mode)
      )
    ) {
      throw configurationError("Open platform HTTP service is invalid");
    }
    if (
      serviceBranch &&
      options.mode !== undefined &&
      options.mode !== options.service.mode
    ) {
      throw configurationError("Open platform HTTP mode must match service mode");
    }
    const resolver = normalizeHttpResolver(options);
    const mode = serviceBranch
      ? options.mode ?? options.service.mode
      : options.mode;
    if (mode === "production" && resolver === undefined) {
      throw configurationError("Production open platform HTTP requires a context resolver");
    }
    if (serviceBranch) {
      const service = options.service;
      const providers: Provider[] = [
        { provide: OPEN_PLATFORM_SERVICE, useValue: service },
        { provide: OpenPlatformService, useValue: service },
        { provide: OPEN_PLATFORM_OUTBOX, useValue: service.outbox },
        {
          provide: OPEN_PLATFORM_EVENT_PUBLISHER,
          useValue: service.eventPublisher,
        },
        { provide: OPEN_PLATFORM_WEBHOOK_SERVICE, useValue: service.webhooks },
        {
          provide: OPEN_PLATFORM_HTTP_CONTEXT_RESOLVER,
          useValue: resolver,
        },
        {
          provide: OPEN_PLATFORM_HTTP_CONTEXT_ISSUER,
          useValue: options.contextIssuer,
        },
        {
          provide: OPEN_PLATFORM_HTTP_MODE,
          useValue: mode,
        },
        OpenPlatformHttpContextGuard,
        OpenPlatformHttpExceptionFilter,
        OpenPlatformHttpResponseInterceptor,
        OpenPlatformProviderReadiness,
      ];
      const exports: Array<string | typeof OpenPlatformService> = [
        OPEN_PLATFORM_SERVICE,
        OpenPlatformService,
        OPEN_PLATFORM_OUTBOX,
        OPEN_PLATFORM_EVENT_PUBLISHER,
        OPEN_PLATFORM_WEBHOOK_SERVICE,
        OPEN_PLATFORM_HTTP_CONTEXT_RESOLVER,
        OPEN_PLATFORM_HTTP_CONTEXT_ISSUER,
        OPEN_PLATFORM_HTTP_MODE,
      ];
      if (options.authorization !== undefined) {
        providers.push({
          provide: OPEN_PLATFORM_AUTHORIZATION,
          useValue: options.authorization,
        });
        exports.push(OPEN_PLATFORM_AUTHORIZATION);
      }
      return {
        module: OpenPlatformHttpModule,
        controllers: [OpenPlatformHttpController, OpenPlatformDomainEventsController],
        providers,
        exports,
      };
    }
    const providerModule = OpenPlatformProviderModule.forRoot(options);
    const providers: Provider[] = [
      {
        provide: OPEN_PLATFORM_HTTP_CONTEXT_RESOLVER,
        useValue: resolver,
      },
      {
        provide: OPEN_PLATFORM_HTTP_CONTEXT_ISSUER,
        useValue: options.contextIssuer,
      },
      {
        provide: OPEN_PLATFORM_HTTP_MODE,
        useValue: mode,
      },
      OpenPlatformHttpContextGuard,
      OpenPlatformHttpExceptionFilter,
      OpenPlatformHttpResponseInterceptor,
    ];
    return {
      module: OpenPlatformHttpModule,
      imports: [providerModule],
      controllers: [OpenPlatformHttpController, OpenPlatformDomainEventsController],
      providers,
      exports: [
        providerModule,
        OPEN_PLATFORM_HTTP_CONTEXT_RESOLVER,
        OPEN_PLATFORM_HTTP_CONTEXT_ISSUER,
        OPEN_PLATFORM_HTTP_MODE,
      ],
    };
  }
}

export function createOpenPlatformHttpModule(
  options: OpenPlatformHttpModuleOptions,
): DynamicModule {
  return OpenPlatformHttpModule.forRoot(options);
}

export interface OpenPlatformModuleOptions {
  readonly platform: OpenPlatformHttpModuleOptions;
  readonly commerce: OpenPlatformCommerceModuleOptions;
  readonly compliance?: OpenPlatformComplianceModuleOptions;
  readonly relay?: OpenPlatformEventRelayModuleOptions;
}

@Module({})
export class OpenPlatformModule {
  static forRoot(options: OpenPlatformModuleOptions): DynamicModule {
    if (options === null || typeof options !== "object") {
      throw configurationError("Open platform module configuration is required");
    }
    if (options.platform === null || typeof options.platform !== "object") {
      throw configurationError("Open platform HTTP module configuration is required");
    }
    if (options.commerce === null || typeof options.commerce !== "object") {
      throw configurationError("Open platform commerce module configuration is required");
    }
    const platform = OpenPlatformHttpModule.forRoot(options.platform);
    const commerce = OpenPlatformCommerceModule.forRoot(options.commerce);
    const compliance = options.compliance === undefined
      ? undefined
      : OpenPlatformComplianceModule.forRoot(options.compliance);
    const relay = options.relay === undefined
      ? undefined
      : OpenPlatformEventRelayModule.forRoot(options.relay);
    return {
      module: OpenPlatformModule,
      imports: [
        platform,
        commerce,
        ...(compliance === undefined ? [] : [compliance]),
        ...(relay === undefined ? [] : [relay]),
      ],
      exports: [
        OpenPlatformHttpModule,
        OpenPlatformCommerceModule,
        ...(compliance === undefined ? [] : [OpenPlatformComplianceModule]),
        ...(relay === undefined ? [] : [OpenPlatformEventRelayModule]),
      ],
    };
  }
}

export function createOpenPlatformModule(
  options: OpenPlatformModuleOptions,
): DynamicModule {
  return OpenPlatformModule.forRoot(options);
}

export const OpenPlatformFullModule = OpenPlatformModule;
export const createOpenPlatformFullModule = createOpenPlatformModule;

export interface OpenPlatformEventRelayProviderOptions {
  readonly relay: OpenPlatformEventRelay;
  readonly enabled?: boolean;
}

export type OpenPlatformEventRelayModuleOptions =
  | OpenPlatformEventRelayProviderOptions
  | OpenPlatformEventRelayOptions;

export interface ResolvedOpenPlatformEventRelay {
  readonly relay: OpenPlatformEventRelay;
  readonly enabled: boolean;
}

@Injectable()
class OpenPlatformEventRelayLifecycle
implements OnModuleInit, OnModuleDestroy {
  constructor(
    @Inject(OPEN_PLATFORM_EVENT_RELAY)
    private readonly relay: OpenPlatformEventRelay,
    @Inject(OPEN_PLATFORM_EVENT_RELAY_ENABLED)
    private readonly enabled: boolean,
  ) {}

  async onModuleInit(): Promise<void> {
    if (!this.enabled) return;
    try {
      await this.relay.start();
    } catch (error) {
      throw new Error(
        `[getbrick-idaas] open platform event relay did not start: ${relayFailureMessage(error)}`,
        { cause: error },
      );
    }
  }

  async onModuleDestroy(): Promise<void> {
    await this.relay.stop();
  }
}

@Module({})
export class OpenPlatformEventRelayModule {
  static forRoot(
    options: OpenPlatformEventRelayModuleOptions,
  ): DynamicModule {
    const resolved = resolveOpenPlatformEventRelay(options);
    const providers: Provider[] = [
      { provide: OPEN_PLATFORM_EVENT_RELAY, useValue: resolved.relay },
      { provide: OpenPlatformEventRelay, useValue: resolved.relay },
      {
        provide: OPEN_PLATFORM_EVENT_RELAY_ENABLED,
        useValue: resolved.enabled,
      },
      OpenPlatformEventRelayLifecycle,
    ];
    return {
      module: OpenPlatformEventRelayModule,
      providers,
      exports: [
        OPEN_PLATFORM_EVENT_RELAY,
        OpenPlatformEventRelay,
        OPEN_PLATFORM_EVENT_RELAY_ENABLED,
      ],
    };
  }
}

export function createOpenPlatformEventRelayModule(
  options: OpenPlatformEventRelayModuleOptions,
): DynamicModule {
  return OpenPlatformEventRelayModule.forRoot(options);
}

export function resolveOpenPlatformEventRelay(
  options: OpenPlatformEventRelayModuleOptions,
): ResolvedOpenPlatformEventRelay {
  if (options === null || typeof options !== "object") {
    throw configurationError("Open platform event relay configuration is required");
  }
  if ("relay" in options) {
    if (!isOpenPlatformEventRelay(options.relay)) {
      throw configurationError("Open platform event relay is invalid");
    }
    const conflicting = options as {
      readonly publisher?: unknown;
      readonly outbox?: unknown;
    };
    if (conflicting.publisher !== undefined || conflicting.outbox !== undefined) {
      throw configurationError("Open platform event relay options conflict");
    }
    const supplied = options.enabled ?? options.relay.enabled;
    if (typeof supplied !== "boolean") {
      throw configurationError(
        "Open platform event relay enabled flag is invalid",
      );
    }
    return Object.freeze({ relay: options.relay, enabled: supplied });
  }
  if (options.publisher === undefined || options.outbox === undefined) {
    throw configurationError(
      "Open platform event relay requires a publisher and outbox",
    );
  }
  const relay = createOpenPlatformEventRelay(options);
  return Object.freeze({ relay, enabled: relay.enabled });
}

function relayFailureMessage(error: unknown): string {
  if (error instanceof Error) {
    return error.message
      .replace(/[\u0000-\u001f\u007f]/gu, " ")
      .trim()
      .slice(0, 256);
  }
  return "unknown error";
}

function isHttpRuntimeMode(
  value: unknown,
): value is OpenPlatformServiceOptions["mode"] {
  return value === "development" || value === "test" || value === "production";
}

function normalizeHttpResolver(
  options: OpenPlatformHttpModuleOptions,
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
  throw configurationError("Open platform HTTP context resolver is invalid");
}
