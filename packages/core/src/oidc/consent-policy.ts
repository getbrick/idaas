import { createHash } from "node:crypto";
import {
  OIDC_CLAIM_SOURCES,
  OIDC_CONSENT_DENIAL_REASONS,
  type OidcClaimDefinition,
  type OidcConsentContext,
  type OidcConsentDecision,
  type OidcConsentDenialReason,
  type OidcConsentGrant,
} from "./contracts.js";

export const DEFAULT_OIDC_SENSITIVE_SCOPES = ["offline_access"] as const;
export const OIDC_REQUIRED_CONSENT_SCOPES = ["openid"] as const;
export const DEFAULT_OIDC_POLICY_VERSION = "policy-v1";
export const OIDC_LEGACY_CONSENT_RESOLVER_SEMANTICS = Object.freeze({
  mode: "legacy" as const,
  legacy: true as const,
  approvesMissingScopes: true,
  approvesMissingClaims: true,
});

export const OIDC_PROTOCOL_RESERVED_CLAIMS = Object.freeze([
  "sub",
  "iss",
  "aud",
  "exp",
  "iat",
  "nbf",
  "jti",
  "auth_time",
  "nonce",
  "acr",
  "amr",
  "azp",
  "at_hash",
  "c_hash",
  "s_hash",
  "sid",
  "cnf",
  "act",
  "may_act",
  "client_id",
  "scope",
  "token_type",
  "events",
  "authorization_details",
  "alg",
  "kid",
  "jku",
  "x5c",
  "x5t",
  "x5t#S256",
  "typ",
] as const);
export const OIDC_RESERVED_CLAIMS = OIDC_PROTOCOL_RESERVED_CLAIMS;
export const OIDC_RESERVED_PROTOCOL_CLAIMS = OIDC_PROTOCOL_RESERVED_CLAIMS;

const OIDC_BUILTIN_CLAIMS = new Set([
  "name",
  "given_name",
  "family_name",
  "middle_name",
  "nickname",
  "preferred_username",
  "profile",
  "picture",
  "website",
  "email",
  "email_verified",
  "gender",
  "birthdate",
  "zoneinfo",
  "locale",
  "updated_at",
  "address",
  "phone_number",
  "phone_number_verified",
]);
const OIDC_CLAIM_SOURCES_SET = new Set<string>(OIDC_CLAIM_SOURCES);
const OIDC_CONSENT_DENIAL_REASONS_SET = new Set<string>(OIDC_CONSENT_DENIAL_REASONS);
const OIDC_SCOPE_PATTERN = /^[!#-[\]-~]+$/u;
const OIDC_CLAIM_NAME_PATTERN = /^[^\u0000-\u001f\u007f\s]+$/u;
const MAX_OIDC_CONSENT_VALUES = 256;

export interface OidcConsentPolicy {
  sensitiveScopes: readonly string[];
  requireExplicitConsent: boolean;
  policyVersion?: string;
}

export interface OidcConsentPolicyInput {
  sensitiveScopes?: readonly string[];
  requireExplicitConsent?: boolean;
  policyVersion?: string;
}

export interface OidcConsentRequest {
  clientId: string;
  userId: string;
  scopes: readonly string[];
  requestedScopes: readonly string[];
  missingScopes: readonly string[];
  nativeInteraction: boolean;
  requestedClaims?: readonly string[];
  policyVersion?: string;
  consentId?: string;
}

export type OidcConsentResolver = (
  request: OidcConsentRequest,
) => boolean | { approved: boolean } | undefined | Promise<boolean | { approved: boolean } | undefined>;
export type OidcLegacyConsentResolver = OidcConsentResolver;

export type OidcApprovedConsentDecision = Extract<OidcConsentDecision, { decision: "approved" }>;
export type OidcDeniedConsentDecision = Extract<OidcConsentDecision, { decision: "denied" }>;

export class OidcConsentValidationError extends Error {
  readonly reason: OidcConsentDenialReason;

  constructor(message: string, reason: OidcConsentDenialReason = "policy_denied") {
    super(`[getbrick-idaas] OIDC consent ${message}`);
    this.name = "OidcConsentValidationError";
    this.reason = reason;
  }
}

export function normalizeOidcConsentPolicy(input: OidcConsentPolicyInput = {}): OidcConsentPolicy {
  const configured = Array.isArray(input.sensitiveScopes)
    ? input.sensitiveScopes
      .map((scope) => typeof scope === "string" ? scope.trim() : "")
      .filter((scope) => isValidOidcScope(scope) && scope.length <= 128)
    : [];
  const sensitiveScopes = new Set<string>([...DEFAULT_OIDC_SENSITIVE_SCOPES, ...configured]);
  return {
    sensitiveScopes: [...sensitiveScopes],
    requireExplicitConsent: input.requireExplicitConsent !== false,
    ...(input.policyVersion === undefined ? {} : { policyVersion: normalizeOidcPolicyVersion(input.policyVersion) }),
  };
}

export function isSensitiveOidcScope(scope: string, policy: OidcConsentPolicy): boolean {
  return policy.sensitiveScopes.includes(scope);
}

export function requiresExplicitOidcConsent(
  scopes: readonly string[],
  policy: OidcConsentPolicy,
  nativeInteraction = false,
): boolean {
  if (!policy.requireExplicitConsent) return false;
  return nativeInteraction || scopes.some((scope) => isSensitiveOidcScope(scope, policy));
}

export function readOidcConsentScopes(
  params: Record<string, unknown>,
  details?: Record<string, unknown>,
): string[] {
  const values: string[] = [];
  const requested = params.scope;
  if (typeof requested === "string") values.push(...requested.split(/\s+/u));
  const missing = details?.missingOIDCScope;
  if (Array.isArray(missing)) {
    for (const value of missing) {
      if (typeof value === "string") values.push(value);
    }
  }
  return normalizeOidcValues(values, isValidOidcScope, 128);
}

export function readOidcConsentClaims(
  params: Record<string, unknown>,
  details?: Record<string, unknown>,
): string[] {
  const values: string[] = [];
  const requested = params.claims;
  if (typeof requested === "string") {
    try {
      const parsed: unknown = JSON.parse(requested);
      if (isRecord(parsed)) {
        const nested = ["id_token", "userinfo"].some((container) => {
          if (!isRecord(parsed[container])) return false;
          values.push(...Object.keys(parsed[container]));
          return true;
        });
        if (!nested) values.push(...Object.keys(parsed));
      }
    } catch {
      return [];
    }
  } else if (isRecord(requested)) {
    values.push(...Object.keys(requested));
  }
  const missing = details?.missingOIDCClaims;
  if (Array.isArray(missing)) {
    for (const value of missing) {
      if (typeof value === "string") values.push(value);
    }
  }
  return normalizeOidcValues(values, isValidOidcClaimName, MAX_OIDC_CONSENT_VALUES);
}

export function resolveOidcConsentDecision(
  value: boolean | { approved: boolean } | undefined,
): boolean {
  if (typeof value === "boolean") return value;
  return isRecord(value) && value.approved === true;
}

export function resolveLegacyOidcConsentDecision(
  value: boolean | { approved: boolean } | undefined,
): boolean {
  return resolveOidcConsentDecision(value);
}

export function validateOidcConsentContext(value: unknown): asserts value is OidcConsentContext {
  if (!isRecord(value)) {
    throw new OidcConsentValidationError("context is invalid");
  }
  for (const key of ["consentId", "tenantId", "applicationId", "clientId", "userId", "grantId", "interactionId", "policyVersion"]) {
    if (!isNonEmptyText(value[key], 512)) {
      throw new OidcConsentValidationError(`context ${key} is invalid`);
    }
  }
  assertExactStringArray(value.requestedScopes, isValidOidcScope, "context requestedScopes");
  assertExactStringArray(value.requestedClaims, isValidOidcClaimName, "context requestedClaims");
  if (value.origin !== undefined && !isNonEmptyText(value.origin, 2048)) {
    throw new OidcConsentValidationError("context origin is invalid");
  }
}

export function isValidOidcConsentContext(value: unknown): value is OidcConsentContext {
  try {
    validateOidcConsentContext(value);
    return true;
  } catch {
    return false;
  }
}

export function snapshotOidcConsentContext(context: OidcConsentContext): OidcConsentContext {
  validateOidcConsentContext(context);
  return Object.freeze({
    ...context,
    requestedScopes: Object.freeze([...context.requestedScopes]),
    requestedClaims: Object.freeze([...context.requestedClaims]),
  });
}

export const cloneOidcConsentContext = snapshotOidcConsentContext;

export function createOidcConsentContext(input: {
  consentId: string;
  tenantId: string;
  applicationId: string;
  clientId: string;
  userId: string;
  grantId: string;
  interactionId: string;
  requestedScopes: readonly string[];
  requestedClaims: readonly string[];
  policyVersion?: string;
  origin?: string;
}): OidcConsentContext {
  const context: OidcConsentContext = {
    consentId: input.consentId,
    tenantId: input.tenantId,
    applicationId: input.applicationId,
    clientId: input.clientId,
    userId: input.userId,
    grantId: input.grantId,
    interactionId: input.interactionId,
    requestedScopes: [...input.requestedScopes],
    requestedClaims: [...input.requestedClaims],
    policyVersion: normalizeOidcPolicyVersion(input.policyVersion ?? DEFAULT_OIDC_POLICY_VERSION),
    ...(input.origin === undefined ? {} : { origin: input.origin }),
  };
  validateOidcConsentContext(context);
  return context;
}

export function validateOidcConsentDecision(
  context: OidcConsentContext,
  value: unknown,
  claimPolicy?: OidcClaimPolicy,
): OidcConsentDecision {
  validateOidcConsentContext(context);
  if (claimPolicy !== undefined && claimPolicy.policyVersion !== context.policyVersion) {
    throw new OidcConsentValidationError("policyVersion does not match the claim policy", "stale_version");
  }
  if (!isRecord(value) || (value.decision !== "approved" && value.decision !== "denied")) {
    throw new OidcConsentValidationError("decision is invalid");
  }
  if (value.decision === "denied") {
    if (!isDenialReason(value.reason)) {
      throw new OidcConsentValidationError("denial reason is invalid");
    }
    return { decision: "denied", reason: value.reason };
  }
  if (value.consentId !== context.consentId) {
    throw new OidcConsentValidationError("consentId does not match the request");
  }
  if (value.policyVersion !== context.policyVersion) {
    throw new OidcConsentValidationError("policyVersion does not match the request", "stale_version");
  }
  if (value.userGesture !== true) {
    throw new OidcConsentValidationError("approved consent requires an explicit user gesture");
  }
  const approvedScopes = assertApprovedSubset(
    value.approvedScopes,
    context.requestedScopes,
    isValidOidcScope,
    "approved scopes",
    "scope_mismatch",
  );
  if (
    !context.requestedScopes.includes("openid") ||
    OIDC_REQUIRED_CONSENT_SCOPES.some((scope) => !approvedScopes.includes(scope))
  ) {
    throw new OidcConsentValidationError("approved consent must include the required openid scope", "scope_mismatch");
  }
  const approvedClaims = assertApprovedSubset(
    value.approvedClaims,
    context.requestedClaims,
    isValidOidcClaimName,
    "approved claims",
    "claim_mismatch",
  );
  for (const claim of approvedClaims) {
    if (isOidcProtocolReservedClaim(claim)) {
      throw new OidcConsentValidationError("protocol claims cannot be approved as custom claims", "claim_mismatch");
    }
    if (claimPolicy !== undefined && !isOidcBuiltinClaim(claim) && !isOidcClaimAllowedByPolicy(claim, claimPolicy, context)) {
      throw new OidcConsentValidationError("approved claim is not allowed by the claim policy", "claim_mismatch");
    }
  }
  return {
    decision: "approved",
    consentId: context.consentId,
    approvedScopes,
    approvedClaims,
    policyVersion: context.policyVersion,
    userGesture: true,
  };
}

export function isValidOidcConsentDecision(
  context: OidcConsentContext,
  value: unknown,
  claimPolicy?: OidcClaimPolicy,
): value is OidcConsentDecision {
  try {
    validateOidcConsentDecision(context, value, claimPolicy);
    return true;
  } catch {
    return false;
  }
}

export function assertOidcConsentDecision(
  context: OidcConsentContext,
  value: unknown,
  claimPolicy?: OidcClaimPolicy,
): asserts value is OidcConsentDecision {
  validateOidcConsentDecision(context, value, claimPolicy);
}

export function resolveOidcConsentDecisionV2(
  context: OidcConsentContext,
  value: unknown,
  claimPolicy?: OidcClaimPolicy,
): OidcConsentDecision {
  try {
    return validateOidcConsentDecision(context, value, claimPolicy);
  } catch (error) {
    return {
      decision: "denied",
      reason: error instanceof OidcConsentValidationError ? error.reason : "policy_denied",
    };
  }
}

export function resolveOidcConsentV2(
  context: OidcConsentContext,
  value: unknown,
  claimPolicy?: OidcClaimPolicy,
): OidcConsentDecision {
  return resolveOidcConsentDecisionV2(context, value, claimPolicy);
}

export interface OidcHostGrant extends OidcConsentGrant {
  expiresAt: string;
  legacy?: false;
  approvedScopes: readonly string[];
  approvedClaims: readonly string[];
  userGesture: true;
}

export interface OidcHostGrantLookupInput {
  tenantId: string;
  applicationId: string;
  clientId: string;
  userId: string;
  scopeHash: string;
  claimHash: string;
  policyVersion: string;
}

export interface OidcHostGrantPort {
  resolve(context: OidcConsentContext): OidcConsentDecision | null | undefined | Promise<OidcConsentDecision | null | undefined>;
}

export interface OidcHostGrantLookupPort {
  findActive(input: OidcHostGrantLookupInput): OidcHostGrant | OidcConsentGrant | null | undefined | Promise<OidcHostGrant | OidcConsentGrant | null | undefined>;
}

export type OidcHostGrantBoundary = OidcHostGrantPort | OidcHostGrantLookupPort | OidcHostGrantResolver;
export type OidcConsentHostPort = OidcHostGrantBoundary;
export type OidcConsentGrantPort = OidcHostGrantBoundary;
export type OidcHostConsentGrantPort = OidcHostGrantBoundary;

export type OidcHostGrantResolver = (
  context: OidcConsentContext,
) => OidcConsentDecision | null | undefined | Promise<OidcConsentDecision | null | undefined>;

export function createOidcHostGrantPort(
  resolver: OidcHostGrantPort | OidcHostGrantResolver,
): OidcHostGrantPort {
  if (typeof resolver === "function") {
    return { resolve: async (context) => resolver(context) };
  }
  if (!resolver || typeof resolver.resolve !== "function") {
    throw new Error("[getbrick-idaas] OIDC host grant port is invalid");
  }
  return { resolve: (context) => resolver.resolve(context) };
}

export function hashOidcConsentValues(values: readonly string[]): string {
  const normalized = [...new Set(values)].sort();
  return createHash("sha256")
    .update(normalized.map((value) => `${value.length}:${value}`).join("|"))
    .digest("hex");
}

export function createOidcConsentResolverV2(
  port: OidcHostGrantBoundary | OidcHostGrantResolver,
  claimPolicy?: OidcClaimPolicy,
): (context: OidcConsentContext) => Promise<OidcConsentDecision> {
  const hostPort = typeof port === "function" ? createOidcHostGrantPort(port) : port;
  return async (context) => {
    const request = snapshotOidcConsentContext(context);
    const decision = await resolveOidcHostGrant(hostPort, request);
    return decision === null
      ? { decision: "denied", reason: "policy_denied" }
      : validateOidcConsentDecision(request, decision, claimPolicy);
  };
}

export function createOidcHostConsentResolver(
  port: OidcHostGrantBoundary | OidcHostGrantResolver,
  claimPolicy?: OidcClaimPolicy,
): (context: OidcConsentContext) => Promise<OidcConsentDecision> {
  return createOidcConsentResolverV2(port, claimPolicy);
}

export async function resolveOidcHostGrant(
  port: OidcHostGrantBoundary,
  context: OidcConsentContext,
  now = Date.now(),
): Promise<OidcConsentDecision | null> {
  const request = snapshotOidcConsentContext(context);
  const hostPort = typeof port === "function" ? createOidcHostGrantPort(port) : port;
  if (typeof (hostPort as OidcHostGrantPort).resolve === "function") {
    return (await (hostPort as OidcHostGrantPort).resolve(request)) ?? null;
  }
  const grant = await (hostPort as OidcHostGrantLookupPort).findActive({
    tenantId: request.tenantId,
    applicationId: request.applicationId,
    clientId: request.clientId,
    userId: request.userId,
    scopeHash: hashOidcConsentValues(request.requestedScopes),
    claimHash: hashOidcConsentValues(request.requestedClaims),
    policyVersion: request.policyVersion,
  });
  if (!grant) return null;
  if (isRecord(grant) && (grant.decision === "approved" || grant.decision === "denied")) {
    return grant as unknown as OidcConsentDecision;
  }
  const approval = getHostGrantApproval(grant, request, now);
  if (approval === null) return null;
  return {
    decision: "approved",
    consentId: request.consentId,
    approvedScopes: approval.approvedScopes,
    approvedClaims: approval.approvedClaims,
    policyVersion: request.policyVersion,
    userGesture: true,
  };
}

export const OIDC_PROTOCOL_CLAIMS = OIDC_PROTOCOL_RESERVED_CLAIMS;
export const OIDC_RESERVED_CLAIM_NAMES = OIDC_PROTOCOL_RESERVED_CLAIMS;

export function isOidcProtocolReservedClaim(name: string): boolean {
  return (OIDC_PROTOCOL_RESERVED_CLAIMS as readonly string[]).includes(name);
}

export function isOidcReservedClaim(name: string): boolean {
  return isOidcProtocolReservedClaim(name);
}

export function isOidcBuiltinClaim(name: string): boolean {
  return OIDC_BUILTIN_CLAIMS.has(name);
}

export interface OidcClaimPolicy {
  policyVersion: string;
  definitions: readonly OidcClaimDefinition[];
  allowlist: readonly string[];
  allowedClaims?: readonly string[];
  claims?: readonly OidcClaimDefinition[];
}

export interface OidcClaimPolicyInput {
  policyVersion?: string;
  definitions?: readonly OidcClaimDefinition[];
  claimDefinitions?: readonly OidcClaimDefinition[];
  claims?: readonly OidcClaimDefinition[];
  allowlist?: readonly string[];
  allowedClaims?: readonly string[];
}

export interface OidcClaimPolicyContext {
  requestedScopes: readonly string[];
  requestedClaims: readonly string[];
  clientId?: string;
}

export interface OidcResolvedClaimPolicy {
  policyVersion: string;
  requestedClaims: readonly string[];
  allowedClaims: readonly string[];
}

export type OidcClaimsPolicy = OidcClaimPolicy;
export type OidcClaimsPolicyInput = OidcClaimPolicyInput;

export function normalizeOidcClaimPolicy(
  input: OidcClaimPolicyInput | readonly OidcClaimDefinition[] = {},
): OidcClaimPolicy {
  if (typeof input !== "object" || input === null) {
    throw new Error("[getbrick-idaas] OIDC claim policy is invalid");
  }
  const policyInput: OidcClaimPolicyInput = Array.isArray(input)
    ? { definitions: input }
    : input as OidcClaimPolicyInput;
  const policyVersion = normalizeOidcPolicyVersion(policyInput.policyVersion ?? DEFAULT_OIDC_POLICY_VERSION);
  const definitions = normalizeClaimDefinitions(
    policyInput.definitions ?? policyInput.claimDefinitions ?? policyInput.claims ?? [],
  );
  const definitionNames = new Set(definitions.map((definition) => definition.name));
  const allowlist = normalizeOidcValues(
    policyInput.allowlist ?? policyInput.allowedClaims ?? definitions.map((definition) => definition.name),
    isValidOidcClaimName,
    MAX_OIDC_CONSENT_VALUES,
  );
  for (const claim of allowlist) {
    if (isOidcProtocolReservedClaim(claim) && !isOidcBuiltinClaim(claim)) {
      throw new Error(`[getbrick-idaas] OIDC protocol claim ${claim} cannot be configured`);
    }
    if (definitions.length > 0 && !definitionNames.has(claim) && !isOidcBuiltinClaim(claim)) {
      throw new Error(`[getbrick-idaas] OIDC claim ${claim} is not defined by policy`);
    }
  }
  return {
    policyVersion,
    definitions,
    allowlist,
    allowedClaims: allowlist,
    claims: definitions,
  };
}

export function normalizeOidcClaimsPolicy(input: OidcClaimPolicyInput = {}): OidcClaimPolicy {
  return normalizeOidcClaimPolicy(input);
}

export function resolveOidcClaimPolicy(
  policy: OidcClaimPolicy,
  context: OidcClaimPolicyContext,
): OidcResolvedClaimPolicy {
  if (!isRecord(policy) || !isNonEmptyText(policy.policyVersion, 128)) {
    throw new Error("[getbrick-idaas] OIDC claim policy is invalid");
  }
  const normalizedPolicy = policy as OidcClaimPolicy;
  const rawDefinitions = normalizedPolicy.definitions ?? normalizedPolicy.claims ?? [];
  const rawAllowlist = normalizedPolicy.allowlist ?? normalizedPolicy.allowedClaims ?? [];
  if (!Array.isArray(rawDefinitions) || !Array.isArray(rawAllowlist)) {
    throw new Error("[getbrick-idaas] OIDC claim policy is invalid");
  }
  const policyDefinitions = rawDefinitions as readonly OidcClaimDefinition[];
  const policyAllowlist = rawAllowlist as readonly string[];
  assertExactStringArray(context.requestedScopes, isValidOidcScope, "requested scopes");
  assertExactStringArray(context.requestedClaims, isValidOidcClaimName, "requested claims");
  const requested = new Set(context.requestedClaims);
  const scopes = new Set(context.requestedScopes);
  const allowed: string[] = [];
  for (const claim of policyAllowlist) {
    if (!isValidOidcClaimName(claim) || isOidcProtocolReservedClaim(claim) || !requested.has(claim)) continue;
    const definition = policyDefinitions.find((entry) => entry.name === claim);
    if (definition !== undefined) {
      if (definition.scopes.length > 0 && !definition.scopes.some((scope) => scopes.has(scope))) continue;
      if (definition.clients.length > 0 && (context.clientId === undefined || !definition.clients.includes(context.clientId))) continue;
    }
    if (!allowed.includes(claim)) allowed.push(claim);
  }
  return {
    policyVersion: normalizedPolicy.policyVersion,
    requestedClaims: [...context.requestedClaims],
    allowedClaims: allowed,
  };
}

export function getOidcClaimAllowlist(
  policy: OidcClaimPolicy,
  context: OidcClaimPolicyContext,
): readonly string[] {
  return resolveOidcClaimPolicy(policy, context).allowedClaims;
}

export const getOidcAllowedClaims = getOidcClaimAllowlist;

export function isOidcClaimAllowedByPolicy(
  claim: string,
  policy: OidcClaimPolicy,
  context: OidcClaimPolicyContext,
): boolean {
  return getOidcClaimAllowlist(policy, context).includes(claim);
}

export function requiresExplicitOidcClaimConsent(
  claims: readonly string[],
  policy: OidcClaimPolicy,
  scopes: readonly string[] = [],
  clientId?: string,
): boolean {
  const resolved = resolveOidcClaimPolicy(policy, {
    requestedScopes: scopes,
    requestedClaims: claims,
    ...(clientId === undefined ? {} : { clientId }),
  });
  return resolved.allowedClaims.length > 0;
}

export function projectOidcClaims(
  value: unknown,
  options: {
    requestedClaims: readonly string[];
    allowlist: readonly string[];
    protectedClaims?: readonly string[];
  },
): Record<string, unknown> {
  if (!isRecord(value) || options.requestedClaims.length === 0 || options.allowlist.length === 0) return {};
  const requested = new Set(options.requestedClaims);
  const allowed = new Set(options.allowlist);
  const protectedClaims = new Set(options.protectedClaims ?? []);
  const output: Record<string, unknown> = {};
  for (const [key, claimValue] of Object.entries(value)) {
    if (!isValidOidcClaimName(key) || isOidcProtocolReservedClaim(key) || protectedClaims.has(key)) continue;
    if (!requested.has(key) || !allowed.has(key) || claimValue === undefined) continue;
    output[key] = claimValue;
  }
  return output;
}

export function sanitizeOidcClaims(
  value: unknown,
  requestedClaims: readonly string[],
  allowlist: readonly string[],
  protectedClaims: readonly string[] = [],
): Record<string, unknown> {
  return projectOidcClaims(value, { requestedClaims, allowlist, protectedClaims });
}

export const filterOidcCustomClaims = projectOidcClaims;

export function isValidOidcScope(value: unknown): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= 128 && value === value.trim() && OIDC_SCOPE_PATTERN.test(value);
}

export function isValidOidcClaimName(value: unknown): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= 256 && value === value.trim() && OIDC_CLAIM_NAME_PATTERN.test(value) && value !== "__proto__" && value !== "constructor" && value !== "prototype";
}

function normalizeOidcPolicyVersion(value: string): string {
  if (!isNonEmptyText(value, 128) || /[\u0000-\u001f\u007f\s]/u.test(value)) {
    throw new Error("[getbrick-idaas] OIDC policyVersion is invalid");
  }
  return value;
}

function normalizeClaimDefinitions(values: readonly OidcClaimDefinition[]): OidcClaimDefinition[] {
  if (!Array.isArray(values) || values.length > MAX_OIDC_CONSENT_VALUES) {
    throw new Error("[getbrick-idaas] OIDC claim definitions are invalid");
  }
  const definitions: OidcClaimDefinition[] = [];
  const names = new Set<string>();
  for (const value of values) {
    if (!isRecord(value) || !isValidOidcClaimName(value.name) || isOidcProtocolReservedClaim(value.name) || names.has(value.name)) {
      throw new Error("[getbrick-idaas] OIDC claim definition is invalid");
    }
    const scopes = normalizeDefinitionValues(value.scopes, isValidOidcScope);
    const clients = normalizeDefinitionValues(value.clients, (entry) => isNonEmptyText(entry, 512));
    if (typeof value.source !== "string" || !OIDC_CLAIM_SOURCES_SET.has(value.source) || typeof value.required !== "boolean" || typeof value.sensitive !== "boolean" || !isNonEmptyText(value.version, 128)) {
      throw new Error("[getbrick-idaas] OIDC claim definition is invalid");
    }
    names.add(value.name);
    definitions.push({
      name: value.name,
      scopes,
      clients,
      source: value.source as OidcClaimDefinition["source"],
      required: value.required,
      sensitive: value.sensitive,
      version: value.version,
    });
  }
  return definitions;
}

function normalizeDefinitionValues(
  values: unknown,
  validator: (value: string) => boolean,
): string[] {
  if (!Array.isArray(values) || values.length > MAX_OIDC_CONSENT_VALUES) {
    throw new Error("[getbrick-idaas] OIDC claim definition list is invalid");
  }
  const output: string[] = [];
  for (const value of values) {
    if (typeof value !== "string" || !validator(value) || output.includes(value)) {
      throw new Error("[getbrick-idaas] OIDC claim definition list is invalid");
    }
    output.push(value);
  }
  return output;
}

function assertApprovedSubset(
  value: unknown,
  requested: readonly string[],
  validator: (entry: unknown) => entry is string,
  label: string,
  reason: OidcConsentDenialReason,
): string[] {
  if (!Array.isArray(value) || value.length > MAX_OIDC_CONSENT_VALUES) {
    throw new OidcConsentValidationError(`${label} are invalid`, reason);
  }
  const requestedSet = new Set(requested);
  const output: string[] = [];
  for (const entry of value) {
    if (!validator(entry) || output.includes(entry)) {
      throw new OidcConsentValidationError(`${label} are invalid`, reason);
    }
    if (!requestedSet.has(entry)) {
      throw new OidcConsentValidationError(`${label} must be a subset of requested values`, reason);
    }
    output.push(entry);
  }
  return output;
}

function assertExactStringArray(
  value: unknown,
  validator: (entry: unknown) => entry is string,
  label: string,
): void {
  if (!Array.isArray(value) || value.length > MAX_OIDC_CONSENT_VALUES) {
    throw new OidcConsentValidationError(`${label} are invalid`);
  }
  const seen = new Set<string>();
  for (const entry of value) {
    if (!validator(entry) || seen.has(entry)) {
      throw new OidcConsentValidationError(`${label} are invalid`);
    }
    seen.add(entry);
  }
}

function isDenialReason(value: unknown): value is OidcConsentDenialReason {
  return typeof value === "string" && OIDC_CONSENT_DENIAL_REASONS_SET.has(value);
}

interface HostGrantApproval {
  approvedScopes: string[];
  approvedClaims: string[];
}

function getHostGrantApproval(
  value: OidcConsentGrant | OidcHostGrant,
  context: OidcConsentContext,
  now: number,
): HostGrantApproval | null {
  if (!isRecord(value) || value.contractVersion !== 1 || value.status !== "active" || value.projectionStatus !== "projected" || (value.legacy !== undefined && value.legacy !== false) || !isHostGrantUnexpired(value, now)) return null;
  if (
    !isNonEmptyText(value.consentId, 512) ||
    value.tenantId !== context.tenantId ||
    value.applicationId !== context.applicationId ||
    value.clientId !== context.clientId ||
    value.userId !== context.userId ||
    value.policyVersion !== context.policyVersion ||
    value.scopeHash !== hashOidcConsentValues(context.requestedScopes) ||
    value.claimHash !== hashOidcConsentValues(context.requestedClaims)
  ) return null;
  if (value.userGesture !== true || !Array.isArray(value.approvedScopes) || !Array.isArray(value.approvedClaims)) return null;
  const approvedScopes = value.approvedScopes as string[];
  const approvedClaims = value.approvedClaims as string[];
  try {
    assertExactStringArray(approvedScopes, isValidOidcScope, "host grant approved scopes");
    assertExactStringArray(approvedClaims, isValidOidcClaimName, "host grant approved claims");
    assertApprovedSubset(approvedScopes, context.requestedScopes, isValidOidcScope, "host grant approved scopes", "scope_mismatch");
    if (!context.requestedScopes.includes("openid") || OIDC_REQUIRED_CONSENT_SCOPES.some((scope) => !approvedScopes.includes(scope))) return null;
    assertApprovedSubset(approvedClaims, context.requestedClaims, isValidOidcClaimName, "host grant approved claims", "claim_mismatch");
    if (approvedClaims.some((claim) => isOidcProtocolReservedClaim(claim))) return null;
  } catch {
    return null;
  }
  return { approvedScopes: [...approvedScopes], approvedClaims: [...approvedClaims] };
}

function isHostGrantUnexpired(value: OidcConsentGrant, now: number): boolean {
  if (value.revokedAt !== undefined || !Number.isFinite(now)) return false;
  if (!isNonEmptyText(value.expiresAt, 128) || value.expiresAt !== value.expiresAt.trim()) return false;
  const expiresAt = Date.parse(value.expiresAt);
  return Number.isFinite(expiresAt) && expiresAt > now;
}

function normalizeOidcValues(
  values: readonly unknown[],
  validator: (value: unknown) => value is string,
  limit: number,
): string[] {
  const output: string[] = [];
  for (const value of values) {
    if (validator(value) && !output.includes(value)) output.push(value);
    if (output.length >= limit) break;
  }
  return output;
}

function isNonEmptyText(value: unknown, maxLength: number): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= maxLength && value === value.trim() && !/[\u0000-\u001f\u007f]/u.test(value);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
