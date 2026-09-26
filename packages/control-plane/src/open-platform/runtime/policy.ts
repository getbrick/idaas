import {
  normalizeIdentifier,
  normalizeResourceId,
  normalizeScopes,
} from "../validation.js";
import {
  normalizeApiMethod,
  normalizeApiPath,
  normalizeAudience,
  isOpenPlatformApiRequestContext,
} from "./context.js";
import {
  OPEN_PLATFORM_RUNTIME_ERROR_CODES,
  runtimeError,
} from "./errors.js";
import type {
  OpenPlatformApiRoutePolicy,
  OpenPlatformPolicyDecision,
  OpenPlatformPolicyDecisionPort,
  OpenPlatformPolicyDenialReason,
  OpenPlatformPolicyEvaluationInput,
  OpenPlatformPolicyEvaluatorPort,
  OpenPlatformQuotaPolicy,
  OpenPlatformRateLimitPolicy,
} from "./types.js";

export interface OpenPlatformPolicyEvaluatorOptions {
  readonly decisionPort?: OpenPlatformPolicyDecisionPort;
}

const POLICY_DENIAL_REASONS = new Set<OpenPlatformPolicyDenialReason>([
  "client_not_allowed",
  "invalid_audience",
  "invalid_scope",
  "policy_denied",
  "route_not_allowed",
]);

export class OpenPlatformPolicyEvaluator implements OpenPlatformPolicyEvaluatorPort {
  private readonly decisionPort: OpenPlatformPolicyDecisionPort | undefined;

  constructor(options: OpenPlatformPolicyEvaluatorOptions = {}) {
    if (
      options.decisionPort !== undefined &&
      (options.decisionPort === null ||
        typeof options.decisionPort !== "object" ||
        typeof options.decisionPort.evaluate !== "function")
    ) {
      throw runtimeError(
        OPEN_PLATFORM_RUNTIME_ERROR_CODES.CONFIGURATION_ERROR,
      );
    }
    this.decisionPort = options.decisionPort;
  }

  async evaluate(
    input: OpenPlatformPolicyEvaluationInput,
  ): Promise<OpenPlatformPolicyDecision> {
    if (
      input === null ||
      typeof input !== "object" ||
      !isOpenPlatformApiRequestContext(input.context)
    ) {
      throw runtimeError(
        OPEN_PLATFORM_RUNTIME_ERROR_CODES.AUTHENTICATION_REQUIRED,
      );
    }
    const route = normalizeOpenPlatformApiRoutePolicy(input.route);
    if (
      !route.enabled ||
      route.method !== input.context.method ||
      route.path !== input.context.path
    ) {
      return deny("route_not_allowed");
    }
    if (route.audience !== input.context.audience) {
      return deny("invalid_audience");
    }
    if (
      input.principal === null ||
      typeof input.principal !== "object" ||
      input.principal.tenantId !== input.context.tenantId ||
      input.principal.applicationId !== input.context.applicationId ||
      input.principal.clientId !== input.context.clientId ||
      input.principal.audience !== route.audience
    ) {
      return deny("policy_denied");
    }
    if (!route.clientIds.includes(input.context.clientId)) {
      return deny("client_not_allowed");
    }
    if (
      route.requiredScopes.some(
        (scope) => !input.principal.scopes.includes(scope),
      )
    ) {
      return deny("invalid_scope");
    }
    if (this.decisionPort === undefined) {
      return Object.freeze({
        effect: "allow",
        policyId: route.routeId,
        policyVersion: route.policyVersion,
      });
    }
    let decision: OpenPlatformPolicyDecision;
    try {
      decision = await this.decisionPort.evaluate({
        context: input.context,
        principal: input.principal,
        route,
      });
    } catch {
      throw runtimeError(OPEN_PLATFORM_RUNTIME_ERROR_CODES.POLICY_UNAVAILABLE);
    }
    if (!isValidPolicyDecision(decision)) {
      throw runtimeError(OPEN_PLATFORM_RUNTIME_ERROR_CODES.POLICY_UNAVAILABLE);
    }
    if (decision.effect === "deny") return decision;
    try {
      return Object.freeze({
        effect: "allow",
        policyId: normalizeIdentifier(decision.policyId, "policyId"),
        policyVersion: normalizeIdentifier(
          decision.policyVersion,
          "policyVersion",
        ),
      });
    } catch {
      throw runtimeError(OPEN_PLATFORM_RUNTIME_ERROR_CODES.POLICY_UNAVAILABLE);
    }
  }
}

export { OpenPlatformPolicyEvaluator as OpenPlatformFailClosedPolicyEvaluator };

export function createOpenPlatformPolicyEvaluator(
  options: OpenPlatformPolicyEvaluatorOptions = {},
): OpenPlatformPolicyEvaluator {
  return new OpenPlatformPolicyEvaluator(options);
}

export function normalizeOpenPlatformApiRoutePolicy(
  value: unknown,
): OpenPlatformApiRoutePolicy {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw runtimeError(OPEN_PLATFORM_RUNTIME_ERROR_CODES.INVALID_REQUEST);
  }
  const route = value as OpenPlatformApiRoutePolicy;
  if (typeof route.enabled !== "boolean") {
    throw runtimeError(OPEN_PLATFORM_RUNTIME_ERROR_CODES.INVALID_REQUEST);
  }
  const clientIds = normalizeIdentifierList(route.clientIds, "clientIds");
  if (clientIds.length === 0) {
    throw runtimeError(OPEN_PLATFORM_RUNTIME_ERROR_CODES.INVALID_REQUEST);
  }
  return Object.freeze({
    routeId: normalizeIdentifier(route.routeId, "routeId"),
    policyVersion: normalizeIdentifier(route.policyVersion, "policyVersion"),
    enabled: route.enabled,
    method: normalizeApiMethod(route.method),
    path: normalizeApiPath(route.path),
    audience: normalizeAudience(route.audience),
    productId: normalizeResourceId(route.productId, "apiProduct"),
    ...(route.apiVersionId === undefined
      ? {}
      : {
          apiVersionId: normalizeResourceId(
            route.apiVersionId,
            "apiVersion",
          ),
        }),
    requiredScopes: normalizeScopes(
      route.requiredScopes,
      "requiredScopes",
      true,
    ),
    clientIds: Object.freeze(clientIds),
    ...(route.rateLimit === undefined
      ? {}
      : { rateLimit: normalizeRatePolicy(route.rateLimit) }),
    ...(route.quota === undefined
      ? {}
      : { quota: normalizeRatePolicy(route.quota) }),
  });
}

function normalizeIdentifierList(
  value: unknown,
  field: string,
): string[] {
  if (!Array.isArray(value) || value.length > 128) {
    throw runtimeError(OPEN_PLATFORM_RUNTIME_ERROR_CODES.INVALID_REQUEST);
  }
  return [...new Set(
    value.map((item) => normalizeIdentifier(item, field)),
  )].sort((left, right) => left.localeCompare(right));
}

function normalizeRatePolicy(
  value: OpenPlatformRateLimitPolicy | OpenPlatformQuotaPolicy,
): OpenPlatformRateLimitPolicy {
  if (
    value === null ||
    typeof value !== "object" ||
    !Number.isSafeInteger(value.requests) ||
    value.requests < 1 ||
    value.requests > 1_000_000 ||
    !Number.isSafeInteger(value.windowMs) ||
    value.windowMs < 1 ||
    value.windowMs > 604_800_000
  ) {
    throw runtimeError(OPEN_PLATFORM_RUNTIME_ERROR_CODES.INVALID_REQUEST);
  }
  return Object.freeze({
    requests: value.requests,
    windowMs: value.windowMs,
  });
}

function isValidPolicyDecision(value: unknown): value is OpenPlatformPolicyDecision {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }
  const decision = value as OpenPlatformPolicyDecision;
  if (decision.effect === "deny") {
    return POLICY_DENIAL_REASONS.has(decision.reason);
  }
  return decision.effect === "allow" &&
    typeof decision.policyId === "string" &&
    typeof decision.policyVersion === "string";
}

function deny(
  reason: OpenPlatformPolicyDenialReason,
): OpenPlatformPolicyDecision {
  return Object.freeze({ effect: "deny", reason });
}
