import { Module, type DynamicModule, type Provider } from "@nestjs/common";
import type { OpenPlatformDomainService, OpenPlatformRuntimeMode } from "../types.js";
import {
  InMemoryOpenPlatformAuditOutbox,
  OpenPlatformApiAuditService,
} from "./audit.js";
import { OpenPlatformCredentialVerificationService } from "./credentials.js";
import { OPEN_PLATFORM_RUNTIME_ERROR_CODES, runtimeError } from "./errors.js";
import { OpenPlatformPolicyEvaluator } from "./policy.js";
import {
  InMemoryOpenPlatformRateLimitStore,
  OpenPlatformRateLimitService,
} from "./rate-limit.js";
import { OpenPlatformApiRuntimeService } from "./service.js";
import type {
  OpenPlatformAuditOutboxPort,
  OpenPlatformOidcBearerVerifierPort,
  OpenPlatformPolicyDecisionPort,
  OpenPlatformRateLimitStorePort,
  OpenPlatformServiceClientVerifierPort,
} from "./types.js";

export const OPEN_PLATFORM_RUNTIME_DOMAIN_SERVICE =
  "OPEN_PLATFORM_RUNTIME_DOMAIN_SERVICE";
export const OPEN_PLATFORM_RUNTIME_RATE_LIMIT_STORE =
  "OPEN_PLATFORM_RUNTIME_RATE_LIMIT_STORE";
export const OPEN_PLATFORM_RUNTIME_AUDIT_OUTBOX =
  "OPEN_PLATFORM_RUNTIME_AUDIT_OUTBOX";
export const OPEN_PLATFORM_RUNTIME_OIDC_BEARER_VERIFIER =
  "OPEN_PLATFORM_RUNTIME_OIDC_BEARER_VERIFIER";
export const OPEN_PLATFORM_RUNTIME_SERVICE_CLIENT_VERIFIER =
  "OPEN_PLATFORM_RUNTIME_SERVICE_CLIENT_VERIFIER";
export const OPEN_PLATFORM_RUNTIME_POLICY_DECISION_PORT =
  "OPEN_PLATFORM_RUNTIME_POLICY_DECISION_PORT";

export interface OpenPlatformRuntimeModuleOptions {
  readonly mode?: OpenPlatformRuntimeMode;
  readonly domain: OpenPlatformDomainService;
  readonly rateLimitStore?: OpenPlatformRateLimitStorePort;
  readonly auditOutbox?: OpenPlatformAuditOutboxPort;
  readonly oidcBearerVerifier?: OpenPlatformOidcBearerVerifierPort;
  readonly serviceClientVerifier?: OpenPlatformServiceClientVerifierPort;
  readonly policyDecisionPort?: OpenPlatformPolicyDecisionPort;
  readonly clock?: () => Date;
}

@Module({})
export class OpenPlatformRuntimeModule {
  static forRoot(
    options: OpenPlatformRuntimeModuleOptions,
  ): DynamicModule {
    if (options === null || typeof options !== "object") {
      throw runtimeError(
        OPEN_PLATFORM_RUNTIME_ERROR_CODES.CONFIGURATION_ERROR,
      );
    }
    const mode = options.mode ?? "test";
    if (
      mode !== "development" &&
      mode !== "test" &&
      mode !== "production"
    ) {
      throw runtimeError(
        OPEN_PLATFORM_RUNTIME_ERROR_CODES.CONFIGURATION_ERROR,
      );
    }
    if (
      options.domain === null ||
      typeof options.domain !== "object" ||
      typeof options.domain.isReady !== "function" ||
      (options.clock !== undefined && typeof options.clock !== "function")
    ) {
      throw runtimeError(
        OPEN_PLATFORM_RUNTIME_ERROR_CODES.CONFIGURATION_ERROR,
      );
    }
    const rateLimitStore = options.rateLimitStore ??
      (mode === "test"
        ? new InMemoryOpenPlatformRateLimitStore(
          options.clock === undefined ? {} : { clock: options.clock },
        )
        : undefined);
    const auditOutbox = options.auditOutbox ??
      (mode === "test" ? new InMemoryOpenPlatformAuditOutbox() : undefined);
    if (
      rateLimitStore === undefined ||
      auditOutbox === undefined ||
      !isRateLimitStore(rateLimitStore) ||
      !isAuditOutbox(auditOutbox) ||
      (options.oidcBearerVerifier !== undefined &&
        !isOidcBearerVerifier(options.oidcBearerVerifier)) ||
      (options.serviceClientVerifier !== undefined &&
        !isServiceClientVerifier(options.serviceClientVerifier)) ||
      (options.policyDecisionPort !== undefined &&
        !isPolicyDecisionPort(options.policyDecisionPort))
    ) {
      throw runtimeError(
        OPEN_PLATFORM_RUNTIME_ERROR_CODES.CONFIGURATION_ERROR,
      );
    }
    if (
      mode === "production" &&
      (rateLimitStore.productionReady !== true ||
        auditOutbox.productionReady !== true ||
        !isProductionDependency(rateLimitStore.readiness) ||
        !isProductionDependency(auditOutbox.readiness) ||
        (options.oidcBearerVerifier !== undefined &&
          options.oidcBearerVerifier.productionReady !== true) ||
        (options.serviceClientVerifier !== undefined &&
          options.serviceClientVerifier.productionReady !== true) ||
        (options.policyDecisionPort !== undefined &&
          options.policyDecisionPort.productionReady !== true))
    ) {
      throw runtimeError(
        OPEN_PLATFORM_RUNTIME_ERROR_CODES.CONFIGURATION_ERROR,
      );
    }
    const policyEvaluator = new OpenPlatformPolicyEvaluator({
      ...(options.policyDecisionPort === undefined
        ? {}
        : { decisionPort: options.policyDecisionPort }),
    });
    const credentials = new OpenPlatformCredentialVerificationService({
      domain: options.domain,
      mode,
      ...(options.clock === undefined ? {} : { clock: options.clock }),
      ...(options.oidcBearerVerifier === undefined
        ? {}
        : { oidcBearerVerifier: options.oidcBearerVerifier }),
      ...(options.serviceClientVerifier === undefined
        ? {}
        : { serviceClientVerifier: options.serviceClientVerifier }),
    });
    const rateLimits = new OpenPlatformRateLimitService({
      mode,
      store: rateLimitStore,
      ...(options.clock === undefined ? {} : { clock: options.clock }),
    });
    const audit = new OpenPlatformApiAuditService({
      mode,
      outbox: auditOutbox,
      ...(options.clock === undefined ? {} : { clock: options.clock }),
    });
    const runtime = new OpenPlatformApiRuntimeService({
      mode,
      credentials,
      policyEvaluator,
      rateLimits,
      audit,
      readiness: async () => (await options.domain.isReady()).ready,
    });
    const providers: Provider[] = [
      { provide: OPEN_PLATFORM_RUNTIME_DOMAIN_SERVICE, useValue: options.domain },
      { provide: OPEN_PLATFORM_RUNTIME_RATE_LIMIT_STORE, useValue: rateLimitStore },
      { provide: OPEN_PLATFORM_RUNTIME_AUDIT_OUTBOX, useValue: auditOutbox },
      { provide: OpenPlatformPolicyEvaluator, useValue: policyEvaluator },
      { provide: OpenPlatformCredentialVerificationService, useValue: credentials },
      { provide: OpenPlatformRateLimitService, useValue: rateLimits },
      { provide: OpenPlatformApiAuditService, useValue: audit },
      { provide: OpenPlatformApiRuntimeService, useValue: runtime },
    ];
    if (options.oidcBearerVerifier !== undefined) {
      providers.push({
        provide: OPEN_PLATFORM_RUNTIME_OIDC_BEARER_VERIFIER,
        useValue: options.oidcBearerVerifier,
      });
    }
    if (options.serviceClientVerifier !== undefined) {
      providers.push({
        provide: OPEN_PLATFORM_RUNTIME_SERVICE_CLIENT_VERIFIER,
        useValue: options.serviceClientVerifier,
      });
    }
    if (options.policyDecisionPort !== undefined) {
      providers.push({
        provide: OPEN_PLATFORM_RUNTIME_POLICY_DECISION_PORT,
        useValue: options.policyDecisionPort,
      });
    }
    const runtimeExports = [
      OPEN_PLATFORM_RUNTIME_DOMAIN_SERVICE,
      OPEN_PLATFORM_RUNTIME_RATE_LIMIT_STORE,
      OPEN_PLATFORM_RUNTIME_AUDIT_OUTBOX,
      OpenPlatformPolicyEvaluator,
      OpenPlatformCredentialVerificationService,
      OpenPlatformRateLimitService,
      OpenPlatformApiAuditService,
      OpenPlatformApiRuntimeService,
    ];
    if (options.oidcBearerVerifier !== undefined) {
      runtimeExports.push(OPEN_PLATFORM_RUNTIME_OIDC_BEARER_VERIFIER);
    }
    if (options.serviceClientVerifier !== undefined) {
      runtimeExports.push(OPEN_PLATFORM_RUNTIME_SERVICE_CLIENT_VERIFIER);
    }
    if (options.policyDecisionPort !== undefined) {
      runtimeExports.push(OPEN_PLATFORM_RUNTIME_POLICY_DECISION_PORT);
    }
    return {
      module: OpenPlatformRuntimeModule,
      providers,
      exports: runtimeExports,
    };
  }
}

export function createOpenPlatformRuntimeModule(
  options: OpenPlatformRuntimeModuleOptions,
): DynamicModule {
  return OpenPlatformRuntimeModule.forRoot(options);
}

function isRateLimitStore(value: unknown): value is OpenPlatformRateLimitStorePort {
  if (value === null || typeof value !== "object") return false;
  const store = value as OpenPlatformRateLimitStorePort;
  return typeof store.consume === "function" &&
    (store.productionReady === undefined ||
      typeof store.productionReady === "boolean") &&
    typeof store.readiness === "object" &&
    store.readiness !== null &&
    typeof store.readiness.ready === "function" &&
    (store.readiness.storage === "memory" ||
      store.readiness.storage === "persistent") &&
    typeof store.readiness.distributed === "boolean";
}

function isAuditOutbox(value: unknown): value is OpenPlatformAuditOutboxPort {
  if (value === null || typeof value !== "object") return false;
  const outbox = value as OpenPlatformAuditOutboxPort;
  return typeof outbox.enqueue === "function" &&
    (outbox.productionReady === undefined ||
      typeof outbox.productionReady === "boolean") &&
    typeof outbox.readiness === "object" &&
    outbox.readiness !== null &&
    typeof outbox.readiness.ready === "function" &&
    (outbox.readiness.storage === "memory" ||
      outbox.readiness.storage === "persistent") &&
    typeof outbox.readiness.distributed === "boolean";
}

function isOidcBearerVerifier(
  value: unknown,
): value is OpenPlatformOidcBearerVerifierPort {
  return value !== null &&
    typeof value === "object" &&
    typeof (value as OpenPlatformOidcBearerVerifierPort).verify === "function" &&
    typeof (value as OpenPlatformOidcBearerVerifierPort).productionReady ===
      "boolean";
}

function isServiceClientVerifier(
  value: unknown,
): value is OpenPlatformServiceClientVerifierPort {
  return value !== null &&
    typeof value === "object" &&
    typeof (value as OpenPlatformServiceClientVerifierPort).verify ===
      "function" &&
    typeof (value as OpenPlatformServiceClientVerifierPort).productionReady ===
      "boolean";
}

function isPolicyDecisionPort(
  value: unknown,
): value is OpenPlatformPolicyDecisionPort {
  const port = value as OpenPlatformPolicyDecisionPort;
  return value !== null &&
    typeof value === "object" &&
    typeof port.evaluate === "function" &&
    (port.productionReady === undefined ||
      typeof port.productionReady === "boolean");
}

function isProductionDependency(readiness: {
  readonly storage: string;
  readonly distributed: boolean;
}): boolean {
  return readiness.storage === "persistent" && readiness.distributed;
}
