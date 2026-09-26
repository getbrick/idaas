import type { DynamicModule } from "@nestjs/common";
import { Inject, Module, Optional } from "@nestjs/common";
import { APP_GUARD } from "@nestjs/core";
import { DEFAULT_ROLE_GRAPH, type RoleGraph } from "@getbrick/idaas-core";
import {
  AUTH_BASE_PATH,
  GETBRICK_AUTH,
  GETBRICK_AUTH_BASE_PATH,
  GETBRICK_AUTH_BASE_URL,
  GETBRICK_RBAC,
  GETBRICK_TRUST_PROXY,
  type GetbrickAuthLike,
} from "./tokens.js";
import { GetbrickAuthGuard } from "./guard.js";
import {
  GetbrickAuthMiddleware,
  normalizeAuthBasePath,
  normalizeCanonicalOrigin,
  normalizeTrustProxy,
  resolveCanonicalOrigin,
} from "./middleware.js";

export type GetbrickGuardMode = "global" | "manual";

export interface GetbrickIdaasRootOptions {
  auth: GetbrickAuthLike;
  rbac?: RoleGraph;
  guard?: GetbrickGuardMode;
  globalGuard?: boolean;
  manualGuard?: boolean;
  basePath?: string;
  baseURL?: string | URL;
  trustProxy?: boolean;
}

@Module({})
export class GetbrickIdaasModule {
  constructor(
    @Optional() @Inject(GETBRICK_AUTH_BASE_PATH)
    private readonly authBasePath = AUTH_BASE_PATH,
  ) {}

  static forRoot(input: GetbrickIdaasRootOptions): DynamicModule {
    const configuredBasePath = input.basePath ?? input.auth.options?.basePath;
    const authBasePath = configuredBasePath
      ? normalizeAuthBasePath(configuredBasePath)
      : AUTH_BASE_PATH;
    const trustProxy = normalizeTrustProxy(input.trustProxy);
    const configuredBaseURL = input.baseURL !== undefined
      ? input.baseURL
      : input.auth.options?.baseURL;
    const canonicalBaseURL = normalizeCanonicalOrigin(configuredBaseURL);
    if (!canonicalBaseURL && !trustProxy) resolveCanonicalOrigin(undefined);
    const providers: NonNullable<DynamicModule["providers"]> = [
      { provide: GETBRICK_AUTH, useValue: input.auth },
      { provide: GETBRICK_AUTH_BASE_PATH, useValue: authBasePath },
      { provide: GETBRICK_AUTH_BASE_URL, useValue: canonicalBaseURL },
      { provide: GETBRICK_TRUST_PROXY, useValue: trustProxy },
      { provide: GETBRICK_RBAC, useValue: input.rbac ?? DEFAULT_ROLE_GRAPH },
    ];
    if (shouldRegisterGlobalGuard(input)) {
      providers.push({ provide: APP_GUARD, useClass: GetbrickAuthGuard });
    }

    return {
      module: GetbrickIdaasModule,
      global: true,
      providers,
      exports: [
        GETBRICK_AUTH,
        GETBRICK_AUTH_BASE_PATH,
        GETBRICK_AUTH_BASE_URL,
        GETBRICK_TRUST_PROXY,
        GETBRICK_RBAC,
      ],
    };
  }

  configure(consumer: {
    apply(middleware: unknown): { forRoutes(...routes: string[]): unknown };
  }): void {
    const route = normalizeAuthBasePath(this.authBasePath).replace(/^\/+/, "");
    consumer.apply(GetbrickAuthMiddleware).forRoutes(route || "api/auth");
  }
}

function shouldRegisterGlobalGuard(input: GetbrickIdaasRootOptions): boolean {
  if (input.guard === "manual" || input.manualGuard === true) return false;
  if (input.guard === "global") return true;
  return input.globalGuard !== false;
}
