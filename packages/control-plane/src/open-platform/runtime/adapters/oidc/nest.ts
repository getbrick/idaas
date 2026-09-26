import { Module, type DynamicModule, type Provider } from "@nestjs/common";
import {
  OPEN_PLATFORM_RUNTIME_OIDC_BEARER_VERIFIER,
  OPEN_PLATFORM_RUNTIME_SERVICE_CLIENT_VERIFIER,
} from "../../module.js";
import type {
  OpenPlatformOidcBearerVerifierPort,
  OpenPlatformServiceClientVerifierPort,
} from "../../types.js";
import { normalizeOidcMode } from "./shared.js";
import type { OidcRuntimeMode } from "./contracts.js";
import { OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES, oidcAdapterError } from "./errors.js";

export const OPEN_PLATFORM_OIDC_BEARER_VERIFIER_ADAPTER =
  "OPEN_PLATFORM_OIDC_BEARER_VERIFIER_ADAPTER";
export const OPEN_PLATFORM_OIDC_SERVICE_CLIENT_VERIFIER_ADAPTER =
  "OPEN_PLATFORM_OIDC_SERVICE_CLIENT_VERIFIER_ADAPTER";

export interface OpenPlatformOidcAdapterNestModuleOptions {
  readonly mode?: OidcRuntimeMode;
  readonly oidcBearerVerifier?: OpenPlatformOidcBearerVerifierPort;
  readonly serviceClientVerifier?: OpenPlatformServiceClientVerifierPort;
}

@Module({})
export class OpenPlatformOidcAdapterNestModule {
  static forRoot(
    options: OpenPlatformOidcAdapterNestModuleOptions,
  ): DynamicModule {
    if (options === null || typeof options !== "object") {
      throw oidcAdapterError(OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.CONFIGURATION);
    }
    const mode = normalizeOidcMode(options.mode);
    const bearer = options.oidcBearerVerifier;
    const serviceClient = options.serviceClientVerifier;
    if (
      bearer === undefined &&
      serviceClient === undefined
    ) {
      throw oidcAdapterError(OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.CONFIGURATION);
    }
    if (
      (bearer !== undefined && !isProductionPort(bearer, mode)) ||
      (serviceClient !== undefined && !isProductionPort(serviceClient, mode))
    ) {
      throw oidcAdapterError(OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.CONFIGURATION);
    }
    const providers: Provider[] = [];
    const exports: Array<string> = [];
    if (bearer !== undefined) {
      providers.push(
        {
          provide: OPEN_PLATFORM_RUNTIME_OIDC_BEARER_VERIFIER,
          useValue: bearer,
        },
        {
          provide: OPEN_PLATFORM_OIDC_BEARER_VERIFIER_ADAPTER,
          useValue: bearer,
        },
      );
      exports.push(
        OPEN_PLATFORM_RUNTIME_OIDC_BEARER_VERIFIER,
        OPEN_PLATFORM_OIDC_BEARER_VERIFIER_ADAPTER,
      );
    }
    if (serviceClient !== undefined) {
      providers.push(
        {
          provide: OPEN_PLATFORM_RUNTIME_SERVICE_CLIENT_VERIFIER,
          useValue: serviceClient,
        },
        {
          provide: OPEN_PLATFORM_OIDC_SERVICE_CLIENT_VERIFIER_ADAPTER,
          useValue: serviceClient,
        },
      );
      exports.push(
        OPEN_PLATFORM_RUNTIME_SERVICE_CLIENT_VERIFIER,
        OPEN_PLATFORM_OIDC_SERVICE_CLIENT_VERIFIER_ADAPTER,
      );
    }
    return {
      module: OpenPlatformOidcAdapterNestModule,
      providers,
      exports,
    };
  }
}

export function createOpenPlatformOidcAdapterNestModule(
  options: OpenPlatformOidcAdapterNestModuleOptions,
): DynamicModule {
  return OpenPlatformOidcAdapterNestModule.forRoot(options);
}

function isProductionPort(
  value: unknown,
  mode: OidcRuntimeMode,
): value is { readonly productionReady: boolean } {
  if (value === null || typeof value !== "object") return false;
  const candidate = value as {
    readonly productionReady?: unknown;
    readonly verify?: unknown;
    readonly readiness?: unknown;
  };
  if (
    typeof candidate.verify !== "function" ||
    typeof candidate.productionReady !== "boolean"
  ) {
    return false;
  }
  return mode !== "production" ||
    (candidate.productionReady === true && typeof candidate.readiness === "function");
}
