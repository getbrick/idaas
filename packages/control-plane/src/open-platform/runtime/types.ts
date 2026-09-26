import type { OpenPlatformRequestContext } from "../authorization.js";
import type {
  MaybePromise,
  OpenPlatformDomainService,
  OpenPlatformRuntimeMode,
} from "../types.js";

export const OPEN_PLATFORM_API_METHODS = Object.freeze([
  "GET",
  "POST",
  "PUT",
  "PATCH",
  "DELETE",
  "HEAD",
  "OPTIONS",
] as const);

export type OpenPlatformApiMethod = (typeof OPEN_PLATFORM_API_METHODS)[number];

export interface OpenPlatformApiRequestContext {
  readonly method: OpenPlatformApiMethod;
  readonly path: string;
  readonly audience: string;
  readonly tenantId: string;
  readonly applicationId: string;
  readonly clientId: string;
  readonly ip: string;
  readonly requestId: string;
  readonly trustedContext: OpenPlatformRequestContext;
}

export interface OpenPlatformRateLimitPolicy {
  readonly requests: number;
  readonly windowMs: number;
}

export type OpenPlatformQuotaPolicy = OpenPlatformRateLimitPolicy;

export interface OpenPlatformApiRoutePolicy {
  readonly routeId: string;
  readonly policyVersion: string;
  readonly enabled: boolean;
  readonly method: OpenPlatformApiMethod;
  readonly path: string;
  readonly audience: string;
  readonly productId: string;
  readonly apiVersionId?: string;
  readonly requiredScopes: readonly string[];
  readonly clientIds: readonly string[];
  readonly rateLimit?: OpenPlatformRateLimitPolicy;
  readonly quota?: OpenPlatformQuotaPolicy;
}

export interface OpenPlatformApiKeyAuthentication {
  readonly type: "apiKey";
  readonly credentialId: string;
  readonly credentialVersion: number;
  readonly secret: string;
}

export interface OpenPlatformOidcBearerAuthentication {
  readonly type: "oidcBearer";
  readonly token: string;
}

export interface OpenPlatformServiceClientAuthentication {
  readonly type: "serviceClient";
  readonly clientId: string;
  readonly assertion: string;
}

export type OpenPlatformApiAuthentication =
  | OpenPlatformApiKeyAuthentication
  | OpenPlatformServiceClientAuthentication
  | OpenPlatformOidcBearerAuthentication;

export interface OpenPlatformAdapterCredentialIdentity {
  readonly active: true;
  readonly tenantId: string;
  readonly applicationId: string;
  readonly clientId: string;
  readonly credentialId: string;
  readonly credentialVersion: number;
  readonly scopes: readonly string[];
  readonly audiences: readonly string[];
  readonly issuedAt: string;
  readonly expiresAt: string;
}

export interface OpenPlatformOidcBearerVerifierInput {
  readonly token: string;
  readonly audience: string;
  readonly requestId: string;
}

export interface OpenPlatformServiceClientVerifierInput {
  readonly assertion: string;
  readonly clientId: string;
  readonly audience: string;
  readonly requestId: string;
}

export interface OpenPlatformOidcBearerVerifierPort {
  readonly productionReady: boolean;
  verify(
    input: OpenPlatformOidcBearerVerifierInput,
  ): MaybePromise<OpenPlatformAdapterCredentialIdentity | undefined>;
}

export interface OpenPlatformServiceClientVerifierPort {
  readonly productionReady: boolean;
  verify(
    input: OpenPlatformServiceClientVerifierInput,
  ): MaybePromise<OpenPlatformAdapterCredentialIdentity | undefined>;
}

export interface OpenPlatformApiPrincipal {
  readonly authenticationType: OpenPlatformApiAuthentication["type"];
  readonly tenantId: string;
  readonly applicationId: string;
  readonly clientId: string;
  readonly credentialId: string;
  readonly credentialVersion: number;
  readonly scopes: readonly string[];
  readonly audience: string;
  readonly issuedAt: string;
  readonly expiresAt?: string;
}

export type OpenPlatformCredentialDomain = Pick<
  OpenPlatformDomainService,
  | "authorizeScopes"
  | "getApiProduct"
  | "getApiVersion"
  | "getApplication"
  | "getApplicationEnvironment"
  | "getCredential"
  | "getTenant"
  | "listScopeGrants"
  | "verifyCredentialSecret"
>;

export interface OpenPlatformCredentialVerifier {
  verify(
    context: OpenPlatformApiRequestContext,
    route: OpenPlatformApiRoutePolicy,
    authentication: OpenPlatformApiAuthentication,
  ): MaybePromise<OpenPlatformApiPrincipal>;
}

export interface OpenPlatformPolicyEvaluationInput {
  readonly context: OpenPlatformApiRequestContext;
  readonly principal: OpenPlatformApiPrincipal;
  readonly route: OpenPlatformApiRoutePolicy;
}

export type OpenPlatformPolicyDenialReason =
  | "client_not_allowed"
  | "invalid_audience"
  | "invalid_scope"
  | "policy_denied"
  | "route_not_allowed";

export type OpenPlatformPolicyDecision =
  | {
      readonly effect: "allow";
      readonly policyId: string;
      readonly policyVersion: string;
    }
  | {
      readonly effect: "deny";
      readonly reason: OpenPlatformPolicyDenialReason;
    };

export interface OpenPlatformPolicyEvaluatorPort {
  evaluate(
    input: OpenPlatformPolicyEvaluationInput,
  ): MaybePromise<OpenPlatformPolicyDecision>;
}

export interface OpenPlatformPolicyDecisionPort {
  readonly productionReady?: boolean;
  evaluate(
    input: OpenPlatformPolicyEvaluationInput,
  ): MaybePromise<OpenPlatformPolicyDecision>;
}

export interface OpenPlatformRateLimitKey {
  readonly tenantId: string;
  readonly applicationId: string;
  readonly credentialId: string;
  readonly routeId: string;
}

export interface OpenPlatformRateLimitWindowState {
  readonly limit: number;
  readonly remaining: number;
  readonly resetAt: string;
  readonly retryAfterSeconds: number;
}

export interface OpenPlatformRateLimitConsumption {
  readonly key: OpenPlatformRateLimitKey;
  readonly rateLimit?: OpenPlatformRateLimitPolicy;
  readonly quota?: OpenPlatformQuotaPolicy;
  readonly now: string;
}

export interface OpenPlatformRateLimitConsumptionResult {
  readonly allowed: boolean;
  readonly limitedBy?: "rateLimit" | "quota";
  readonly rateLimit?: OpenPlatformRateLimitWindowState;
  readonly quota?: OpenPlatformRateLimitWindowState;
}

export interface OpenPlatformDependencyReadiness {
  readonly storage: "memory" | "persistent";
  readonly distributed: boolean;
  ready(): MaybePromise<boolean>;
}

export interface OpenPlatformRateLimitStorePort {
  readonly productionReady?: boolean;
  readonly readiness: OpenPlatformDependencyReadiness;
  consume(
    request: OpenPlatformRateLimitConsumption,
  ): MaybePromise<OpenPlatformRateLimitConsumptionResult>;
}

export type OpenPlatformApiCallEventType =
  | "api.call.accepted"
  | "api.call.rejected"
  | "api.call.completed"
  | "api.call.failed"
  | "api.call.rate_limited";

export type OpenPlatformApiCallOutcome =
  | "accepted"
  | "rejected"
  | "completed"
  | "failed"
  | "rate_limited";

export type OpenPlatformAuditMetadata = Readonly<
  Record<string, string | number | boolean | null>
>;

export interface OpenPlatformApiCallAuditEvent {
  readonly id: string;
  readonly schemaVersion: "open-platform.api-call.audit.v1";
  readonly type: OpenPlatformApiCallEventType;
  readonly outcome: OpenPlatformApiCallOutcome;
  readonly occurredAt: string;
  readonly tenantId: string;
  readonly applicationId: string;
  readonly clientId: string;
  readonly credentialId?: string;
  readonly credentialVersion?: number;
  readonly request: {
    readonly method: OpenPlatformApiMethod;
    readonly path: string;
    readonly audience: string;
    readonly ip: string;
    readonly requestId: string;
  };
  readonly metadata: OpenPlatformAuditMetadata;
}

export interface OpenPlatformApiCallAuditInput {
  readonly context: OpenPlatformApiRequestContext;
  readonly principal?: OpenPlatformApiPrincipal;
  readonly type: OpenPlatformApiCallEventType;
  readonly metadata?: Readonly<Record<string, unknown>>;
  readonly eventId?: string;
  readonly occurredAt?: string;
}

export interface OpenPlatformAuditOutboxReceipt {
  readonly eventId: string;
}

export interface OpenPlatformAuditOutboxPort {
  readonly productionReady?: boolean;
  readonly readiness: OpenPlatformDependencyReadiness;
  enqueue(
    event: OpenPlatformApiCallAuditEvent,
  ): MaybePromise<OpenPlatformAuditOutboxReceipt>;
}

export interface OpenPlatformRuntimeReadiness {
  readonly ready: boolean;
  readonly mode: OpenPlatformRuntimeMode;
  readonly rateLimitStorage: "memory" | "persistent";
  readonly auditStorage: "memory" | "persistent";
}

export interface OpenPlatformApiAdmission {
  readonly context: OpenPlatformApiRequestContext;
  readonly route: OpenPlatformApiRoutePolicy;
  readonly principal: OpenPlatformApiPrincipal;
  readonly policy: Extract<OpenPlatformPolicyDecision, { effect: "allow" }>;
  readonly rateLimit: OpenPlatformRateLimitConsumptionResult;
}
