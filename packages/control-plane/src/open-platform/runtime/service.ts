import type { MaybePromise, OpenPlatformRuntimeMode } from "../types.js";
import type { OpenPlatformApiAuditService } from "./audit.js";
import type { OpenPlatformCredentialVerificationService } from "./credentials.js";
import {
  OPEN_PLATFORM_RUNTIME_ERROR_CODES,
  isOpenPlatformRuntimeError,
  runtimeError,
} from "./errors.js";
import { normalizeOpenPlatformApiRoutePolicy } from "./policy.js";
import type { OpenPlatformRateLimitService } from "./rate-limit.js";
import type {
  OpenPlatformApiAdmission,
  OpenPlatformApiAuthentication,
  OpenPlatformApiCallAuditEvent,
  OpenPlatformApiCallAuditInput,
  OpenPlatformApiPrincipal,
  OpenPlatformApiRequestContext,
  OpenPlatformApiRoutePolicy,
  OpenPlatformPolicyDecision,
  OpenPlatformPolicyDenialReason,
  OpenPlatformPolicyEvaluatorPort,
  OpenPlatformRuntimeReadiness,
} from "./types.js";

export interface OpenPlatformApiRuntimeServiceOptions {
  readonly mode?: OpenPlatformRuntimeMode;
  readonly credentials: OpenPlatformCredentialVerificationService;
  readonly policyEvaluator: OpenPlatformPolicyEvaluatorPort;
  readonly rateLimits: OpenPlatformRateLimitService;
  readonly audit: OpenPlatformApiAuditService;
  readonly readiness?: () => MaybePromise<boolean>;
}

export class OpenPlatformApiRuntimeService {
  readonly mode: OpenPlatformRuntimeMode;
  private readonly credentials: OpenPlatformCredentialVerificationService;
  private readonly policyEvaluator: OpenPlatformPolicyEvaluatorPort;
  private readonly rateLimits: OpenPlatformRateLimitService;
  private readonly auditService: OpenPlatformApiAuditService;
  private readonly readiness: (() => MaybePromise<boolean>) | undefined;

  constructor(options: OpenPlatformApiRuntimeServiceOptions) {
    if (
      options === null ||
      typeof options !== "object" ||
      !isCredentialService(options.credentials) ||
      !isPolicyEvaluator(options.policyEvaluator) ||
      !isRateLimitService(options.rateLimits) ||
      !isAuditService(options.audit) ||
      (options.readiness !== undefined &&
        typeof options.readiness !== "function")
    ) {
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
    this.mode = mode;
    this.credentials = options.credentials;
    this.policyEvaluator = options.policyEvaluator;
    this.rateLimits = options.rateLimits;
    this.auditService = options.audit;
    this.readiness = options.readiness;
  }

  async isReady(): Promise<OpenPlatformRuntimeReadiness> {
    const checks = await Promise.all([
      safelyReady(this.rateLimits.isReady.bind(this.rateLimits)),
      safelyReady(this.auditService.isReady.bind(this.auditService)),
      this.readiness === undefined
        ? Promise.resolve(true)
        : safelyReady(this.readiness),
    ]);
    return {
      ready: checks.every((ready) => ready),
      mode: this.mode,
      rateLimitStorage: this.rateLimits.storage,
      auditStorage: this.auditService.storage,
    };
  }

  async admit(
    context: OpenPlatformApiRequestContext,
    routeValue: OpenPlatformApiRoutePolicy,
    authentication: OpenPlatformApiAuthentication,
  ): Promise<OpenPlatformApiAdmission> {
    const route = normalizeOpenPlatformApiRoutePolicy(routeValue);
    const principal = await this.credentials.verify(
      context,
      route,
      authentication,
    );
    const policy = await this.evaluatePolicy(context, route, principal);
    const rateLimit = await this.rateLimits.enforce(
      context,
      principal,
      route,
    );
    return Object.freeze({
      context,
      route,
      principal,
      policy,
      rateLimit,
    });
  }

  async audit(
    input: OpenPlatformApiCallAuditInput,
  ): Promise<OpenPlatformApiCallAuditEvent> {
    return this.auditService.record(input);
  }

  private async evaluatePolicy(
    context: OpenPlatformApiRequestContext,
    route: OpenPlatformApiRoutePolicy,
    principal: OpenPlatformApiPrincipal,
  ): Promise<Extract<OpenPlatformPolicyDecision, { effect: "allow" }>> {
    let decision: OpenPlatformPolicyDecision;
    try {
      decision = await this.policyEvaluator.evaluate({
        context,
        route,
        principal,
      });
    } catch (error) {
      if (isOpenPlatformRuntimeError(error)) throw error;
      throw runtimeError(OPEN_PLATFORM_RUNTIME_ERROR_CODES.POLICY_UNAVAILABLE, {
        requestId: context.requestId,
      });
    }
    if (!isAllowDecision(decision)) {
      if (isDenyDecision(decision)) {
        throw policyDenied(decision.reason, context.requestId);
      }
      throw runtimeError(OPEN_PLATFORM_RUNTIME_ERROR_CODES.POLICY_UNAVAILABLE, {
        requestId: context.requestId,
      });
    }
    return decision;
  }
}

export function createOpenPlatformApiRuntimeService(
  options: OpenPlatformApiRuntimeServiceOptions,
): OpenPlatformApiRuntimeService {
  return new OpenPlatformApiRuntimeService(options);
}

function isAllowDecision(
  value: OpenPlatformPolicyDecision,
): value is Extract<OpenPlatformPolicyDecision, { effect: "allow" }> {
  return value !== null &&
    typeof value === "object" &&
    value.effect === "allow" &&
    typeof value.policyId === "string" &&
    value.policyId.length > 0 &&
    typeof value.policyVersion === "string" &&
    value.policyVersion.length > 0;
}

function isDenyDecision(
  value: OpenPlatformPolicyDecision,
): value is Extract<OpenPlatformPolicyDecision, { effect: "deny" }> {
  return value !== null &&
    typeof value === "object" &&
    value.effect === "deny" &&
    typeof value.reason === "string";
}

function policyDenied(
  reason: OpenPlatformPolicyDenialReason,
  requestId: string,
): ReturnType<typeof runtimeError> {
  const code = reason === "client_not_allowed"
    ? OPEN_PLATFORM_RUNTIME_ERROR_CODES.CLIENT_NOT_ALLOWED
    : reason === "invalid_audience"
    ? OPEN_PLATFORM_RUNTIME_ERROR_CODES.INVALID_AUDIENCE
    : reason === "invalid_scope"
    ? OPEN_PLATFORM_RUNTIME_ERROR_CODES.INVALID_SCOPE
    : reason === "route_not_allowed"
    ? OPEN_PLATFORM_RUNTIME_ERROR_CODES.ROUTE_NOT_ALLOWED
    : OPEN_PLATFORM_RUNTIME_ERROR_CODES.POLICY_DENIED;
  return runtimeError(code, { requestId });
}

async function safelyReady(check: () => MaybePromise<boolean>): Promise<boolean> {
  try {
    return (await check()) === true;
  } catch {
    return false;
  }
}

function isCredentialService(
  value: unknown,
): value is OpenPlatformCredentialVerificationService {
  return value !== null &&
    typeof value === "object" &&
    typeof (value as OpenPlatformCredentialVerificationService).verify ===
      "function";
}

function isPolicyEvaluator(
  value: unknown,
): value is OpenPlatformPolicyEvaluatorPort {
  return value !== null &&
    typeof value === "object" &&
    typeof (value as OpenPlatformPolicyEvaluatorPort).evaluate === "function";
}

function isRateLimitService(
  value: unknown,
): value is OpenPlatformRateLimitService {
  return value !== null &&
    typeof value === "object" &&
    typeof (value as OpenPlatformRateLimitService).enforce === "function" &&
    typeof (value as OpenPlatformRateLimitService).isReady === "function";
}

function isAuditService(
  value: unknown,
): value is OpenPlatformApiAuditService {
  return value !== null &&
    typeof value === "object" &&
    typeof (value as OpenPlatformApiAuditService).record === "function" &&
    typeof (value as OpenPlatformApiAuditService).isReady === "function";
}
