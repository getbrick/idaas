import { hasPermission } from "@getbrick/idaas-core";
import {
  canonicalOpenPlatformAuthorizationAction,
  isOpenPlatformRequestContext,
  OPEN_PLATFORM_LIFECYCLE_AUTHORIZATION_ACTION_ALIASES,
  OPEN_PLATFORM_LIFECYCLE_AUTHORIZATION_ACTIONS,
  openPlatformLifecycleAuthorizationActionForStatus,
  type OpenPlatformAuthorizationAction,
  type OpenPlatformAuthorizationPort,
  type OpenPlatformAuthorizationRequest,
  type OpenPlatformRequestContext,
} from "../../authorization.js";
import {
  OPEN_PLATFORM_LIFECYCLE_RESOURCE_KINDS,
  type OpenPlatformLifecycleStatus,
} from "../../types.js";
import type { ControlPlaneActor } from "../../../types.js";

type MaybePromise<T> = T | PromiseLike<T>;

export type OpenPlatformAuthorizationDenialReason =
  | "invalid-request"
  | "untrusted-context"
  | "tenant-mismatch"
  | "actor-unavailable"
  | "actor-mismatch"
  | "tenant-scope-missing"
  | "platform-boundary"
  | "unknown-permission"
  | "permission-denied"
  | "invalid-policy-result"
  | "resolver-unavailable";

export interface OpenPlatformAuthorizationDecision {
  readonly allowed: boolean;
  readonly reason?: OpenPlatformAuthorizationDenialReason;
}

export interface OpenPlatformAuthorizationAdapter extends OpenPlatformAuthorizationPort {
  authorizeWithReason(
    request: OpenPlatformAuthorizationRequest,
  ): Promise<OpenPlatformAuthorizationDecision>;
  invalidate(
    selector?: OpenPlatformPermissionCacheInvalidation,
  ): Promise<boolean>;
  invalidateVersion(input: OpenPlatformAuthorizationVersionInvalidation): Promise<boolean>;
}

export interface ProductionOpenPlatformAuthorizationAdapter extends OpenPlatformAuthorizationAdapter {
  readonly productionReady: true;
}

export interface DevelopmentOpenPlatformAuthorizationAdapter extends OpenPlatformAuthorizationAdapter {
  readonly productionReady: false;
}

export interface OpenPlatformTrustedActorResolutionRequest {
  readonly actorId: string;
  readonly tenantId: string;
}

export interface OpenPlatformTrustedActorResolution {
  readonly actor: ControlPlaneActor;
  readonly tenantIds: readonly string[];
  readonly platformRoles?: readonly string[];
  readonly tenantRoles?: Readonly<Record<string, readonly string[]>>;
  readonly permissionVersion?: string;
}

export interface OpenPlatformTrustedActorResolver {
  readonly productionReady: true;
  resolve(
    request: OpenPlatformTrustedActorResolutionRequest,
  ): MaybePromise<OpenPlatformTrustedActorResolution | undefined>;
}

export interface DevelopmentOpenPlatformActorResolver {
  readonly productionReady: false;
  resolve(
    request: OpenPlatformTrustedActorResolutionRequest,
  ): MaybePromise<OpenPlatformTrustedActorResolution | undefined>;
}

export interface OpenPlatformDevelopmentActorEntry extends OpenPlatformTrustedActorResolution {
  readonly actorId: string;
}

export type OpenPlatformRoleScope =
  | { readonly kind: "platform" }
  | { readonly kind: "tenant"; readonly tenantId: string };

export interface OpenPlatformRolePermissionResolutionInput {
  readonly actor: ControlPlaneActor;
  readonly role: string;
  readonly scope: OpenPlatformRoleScope;
  readonly requiredPermission: string;
  readonly resource: OpenPlatformAuthorizationRequest["resource"];
  readonly action: OpenPlatformAuthorizationRequest["action"];
  readonly resourceId?: string;
}

export type OpenPlatformRolePermissionResolver = (
  input: OpenPlatformRolePermissionResolutionInput,
) => MaybePromise<readonly string[]>;

export interface OpenPlatformResourcePolicyInput {
  readonly actor: ControlPlaneActor;
  readonly actorId: string;
  readonly tenantId: string;
  readonly roles: readonly string[];
  readonly scope: OpenPlatformRoleScope;
  readonly requiredPermission: string;
  readonly permissionVersion: string;
  readonly resource: OpenPlatformAuthorizationRequest["resource"];
  readonly action: OpenPlatformAuthorizationRequest["action"];
  readonly resourceId?: string;
}

export type OpenPlatformResourcePolicyResolver = (
  input: OpenPlatformResourcePolicyInput,
) => MaybePromise<unknown>;

export interface OpenPlatformPermissionCacheInvalidation {
  readonly actorId?: string;
  readonly tenantId?: string;
  readonly resourceKind?: OpenPlatformAuthorizationRequest["resource"];
  readonly resourceId?: string;
  readonly permission?: string;
  readonly role?: string;
}

export interface OpenPlatformAuthorizationVersionInvalidation {
  readonly actorId: string;
  readonly tenantId: string;
}

export interface OpenPlatformPermissionCache {
  get(key: string): MaybePromise<unknown>;
  set(
    key: string,
    permissions: readonly string[],
    ttlMs: number,
  ): MaybePromise<void>;
  delete(key: string): MaybePromise<void>;
  invalidate(selector: Readonly<OpenPlatformPermissionCacheInvalidation>): MaybePromise<void>;
}

export interface OpenPlatformAuthorizationAdapterBehaviorOptions {
  readonly rolePermissions?: OpenPlatformRolePermissionResolver;
  readonly resourcePolicy?: OpenPlatformResourcePolicyResolver;
  readonly platformPermissions?: readonly string[];
  readonly permissionCache?: OpenPlatformPermissionCache;
  readonly permissionCacheTtlMs?: number;
  readonly onDenied?: (
    reason: OpenPlatformAuthorizationDenialReason,
  ) => MaybePromise<void>;
}

export interface ProductionOpenPlatformAuthorizationAdapterOptions
  extends OpenPlatformAuthorizationAdapterBehaviorOptions {
  readonly resolver: OpenPlatformTrustedActorResolver;
}

export interface DevelopmentOpenPlatformAuthorizationAdapterOptions
  extends OpenPlatformAuthorizationAdapterBehaviorOptions {
  readonly resolver: DevelopmentOpenPlatformActorResolver;
}

interface NormalizedTrustedAuthority {
  readonly actor: ControlPlaneActor;
  readonly permissions: readonly string[];
  readonly platformRoles: readonly string[];
  readonly tenantRoles: readonly string[];
  readonly tenantIds: ReadonlySet<string>;
  readonly permissionVersion: string;
}

interface PermissionCacheMetadata {
  readonly key: string;
  readonly actorId: string;
  readonly tenantId: string;
  readonly resourceKind: OpenPlatformAuthorizationRequest["resource"];
  readonly resourceId: string | undefined;
  readonly permission: string;
  readonly role: string;
}

interface NormalizedCacheKeyInput extends Omit<PermissionCacheMetadata, "key"> {
  readonly action: OpenPlatformAuthorizationRequest["action"];
  readonly scope: OpenPlatformRoleScope;
  readonly permissionVersion: string;
  readonly generation: number;
}

const RESOURCE_PERMISSIONS = Object.freeze({
  tenant: "tenant",
  developerOrganization: "developer",
  application: "application",
  applicationEnvironment: "application",
  apiProduct: "api-product",
  apiVersion: "api-product",
  subscription: "authorization",
  credential: "credential",
  scopeGrant: "authorization",
  usage: "usage",
  webhook: "webhook",
  auditEvent: "audit",
} as const);

const ACTION_PERMISSIONS: Readonly<
  Partial<Record<OpenPlatformAuthorizationAction, string>>
> = Object.freeze({
  create: "write",
  read: "read",
  update: "write",
  issue: "write",
  rotate: "rotate",
  revoke: "revoke",
  grant: "write",
  authorize: "read",
  record: "write",
  publish: "publish",
  disable: "disable",
  archive: "archive",
  submitReview: "submit-review",
});

const LIFECYCLE_RESOURCE_PERMISSIONS: readonly string[] = Object.freeze([
  ...new Set(
    OPEN_PLATFORM_LIFECYCLE_RESOURCE_KINDS.map(
      (kind) => RESOURCE_PERMISSIONS[kind],
    ),
  ),
]);

export const OPEN_PLATFORM_LIFECYCLE_RBAC_ACTIONS = Object.freeze([
  "publish",
  "disable",
  "archive",
  "submit-review",
] as const);

export const OPEN_PLATFORM_LIFECYCLE_RBAC_PERMISSIONS: readonly string[] =
  Object.freeze(
    LIFECYCLE_RESOURCE_PERMISSIONS.flatMap((resource) =>
      OPEN_PLATFORM_LIFECYCLE_RBAC_ACTIONS.map(
        (action) => `open:${resource}:${action}`,
      )),
  );

const LIFECYCLE_ALLOWED_ACTIONS = Object.freeze([
  ...OPEN_PLATFORM_LIFECYCLE_AUTHORIZATION_ACTIONS,
  ...Object.keys(OPEN_PLATFORM_LIFECYCLE_AUTHORIZATION_ACTION_ALIASES),
]);

const ALLOWED_OPERATIONS = new Set([
  "tenant.create",
  "tenant.read",
  "tenant.update",
  "developerOrganization.create",
  "developerOrganization.read",
  "developerOrganization.update",
  "application.create",
  "application.read",
  "application.update",
  "applicationEnvironment.create",
  "applicationEnvironment.read",
  "applicationEnvironment.update",
  "apiProduct.create",
  "apiProduct.read",
  "apiProduct.update",
  "apiVersion.create",
  "apiVersion.read",
  "apiVersion.update",
  "credential.issue",
  "credential.rotate",
  "credential.revoke",
  "credential.read",
  "subscription.create",
  "subscription.read",
  "scopeGrant.grant",
  "scopeGrant.revoke",
  "scopeGrant.authorize",
  "scopeGrant.read",
  "usage.record",
  "usage.read",
  "webhook.create",
  "webhook.read",
  "webhook.update",
  "webhook.rotate",
  "webhook.record",
  "auditEvent.read",
  ...OPEN_PLATFORM_LIFECYCLE_RESOURCE_KINDS.flatMap((resource) =>
    LIFECYCLE_ALLOWED_ACTIONS.map((action) => `${resource}.${action}`)
  ),
]);

const VALID_REQUIRED_PERMISSIONS = new Set([
  "open:tenant:read",
  "open:tenant:write",
  "open:developer:read",
  "open:developer:write",
  "open:application:read",
  "open:application:write",
  "open:api-product:read",
  "open:api-product:write",
  "open:api-product:rotate",
  "open:api-product:revoke",
  "open:authorization:read",
  "open:authorization:write",
  "open:authorization:revoke",
  "open:credential:read",
  "open:credential:write",
  "open:credential:rotate",
  "open:credential:revoke",
  "open:usage:read",
  "open:usage:write",
  "open:webhook:read",
  "open:webhook:write",
  "open:webhook:rotate",
  "open:audit:read",
  ...OPEN_PLATFORM_LIFECYCLE_RBAC_PERMISSIONS,
]);

const RESOURCE_PART = /^(?:\*|[a-z][a-z0-9-]*)$/u;
const CONTROL_OR_SPACE = /[\s\u0000-\u001f\u007f]/u;
const TENANT_ID = /^[a-z][a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u;
const developmentActorResolvers = new WeakSet<object>();
const invalidRoleResolution = Symbol("invalid-role-resolution");

export function toOpenPlatformRbacPermission(
  request: Pick<OpenPlatformAuthorizationRequest, "resource" | "action">,
): string | undefined {
  if (
    !isRecord(request) ||
    typeof request.resource !== "string" ||
    typeof request.action !== "string" ||
    !ALLOWED_OPERATIONS.has(`${request.resource}.${request.action}`)
  ) {
    return undefined;
  }
  const resource = RESOURCE_PERMISSIONS[
    request.resource as keyof typeof RESOURCE_PERMISSIONS
  ];
  const canonical = canonicalOpenPlatformAuthorizationAction(request.action);
  if (resource === undefined || canonical === undefined) return undefined;
  const action = ACTION_PERMISSIONS[canonical];
  if (action === undefined) return undefined;
  return `open:${resource}:${action}`;
}

export function openPlatformLifecycleRbacPermission(
  resource: OpenPlatformAuthorizationRequest["resource"],
  targetStatus: OpenPlatformLifecycleStatus,
): string | undefined {
  const action = openPlatformLifecycleAuthorizationActionForStatus(targetStatus);
  if (action === undefined) return undefined;
  return toOpenPlatformRbacPermission({
    resource,
    action,
  } as Pick<OpenPlatformAuthorizationRequest, "resource" | "action">);
}

export function createProductionOpenPlatformAuthorizationAdapter(
  options: ProductionOpenPlatformAuthorizationAdapterOptions,
): ProductionOpenPlatformAuthorizationAdapter {
  if (
    !isRecord(options) ||
    !isRecord(options.resolver) ||
    options.resolver.productionReady !== true ||
    typeof options.resolver.resolve !== "function" ||
    developmentActorResolvers.has(options.resolver)
  ) {
    throw new TypeError("Production open platform authorization requires a trusted actor resolver");
  }
  return createAdapter(options, true) as ProductionOpenPlatformAuthorizationAdapter;
}

export const createOpenPlatformAuthorizationAdapter =
  createProductionOpenPlatformAuthorizationAdapter;

export function createDevelopmentOpenPlatformActorResolver(
  entries: readonly OpenPlatformDevelopmentActorEntry[],
): DevelopmentOpenPlatformActorResolver {
  if (!Array.isArray(entries)) {
    throw new TypeError("Development open platform actors must be an array");
  }
  const actors = new Map<string, OpenPlatformTrustedActorResolution>();
  for (const entry of entries) {
    if (
      !isRecord(entry) ||
      !validActorId(entry.actorId) ||
      !isRecord(entry.actor) ||
      !Array.isArray(entry.tenantIds) ||
      actors.has(entry.actorId)
    ) {
      throw new TypeError("Development open platform actor entry is invalid");
    }
    actors.set(
      entry.actorId,
      freezeResolution(entry as unknown as OpenPlatformDevelopmentActorEntry),
    );
  }
  const resolver: DevelopmentOpenPlatformActorResolver = Object.freeze({
    productionReady: false,
    resolve(request: OpenPlatformTrustedActorResolutionRequest) {
      return actors.get(request.actorId);
    },
  });
  developmentActorResolvers.add(resolver);
  return resolver;
}

export function isDevelopmentOpenPlatformActorResolver(
  value: unknown,
): value is DevelopmentOpenPlatformActorResolver {
  return isRecord(value) && developmentActorResolvers.has(value);
}

export function createDevelopmentOpenPlatformAuthorizationAdapter(
  options: DevelopmentOpenPlatformAuthorizationAdapterOptions,
): DevelopmentOpenPlatformAuthorizationAdapter {
  if (
    !isRecord(options) ||
    !isRecord(options.resolver) ||
    options.resolver.productionReady !== false ||
    typeof options.resolver.resolve !== "function" ||
    !developmentActorResolvers.has(options.resolver)
  ) {
    throw new TypeError("Development open platform authorization requires the development actor resolver");
  }
  return createAdapter(options, false) as DevelopmentOpenPlatformAuthorizationAdapter;
}

function createAdapter(
  options: ProductionOpenPlatformAuthorizationAdapterOptions |
    DevelopmentOpenPlatformAuthorizationAdapterOptions,
  productionReady: boolean,
): OpenPlatformAuthorizationAdapter {
  const resolver = options.resolver;
  const rolePermissions = options.rolePermissions;
  const resourcePolicy = options.resourcePolicy;
  const permissionCache = options.permissionCache;
  const permissionCacheTtlMs = options.permissionCacheTtlMs ?? 30_000;
  const platformPermissions = validatePlatformPermissions(options.platformPermissions);
  const knownPermissionCacheKeys = new Map<string, PermissionCacheMetadata>();
  const authorizationGenerations = new Map<string, number>();
  const latestPermissionVersions = new Map<string, string>();
  if (rolePermissions !== undefined && typeof rolePermissions !== "function") {
    throw new TypeError("Open platform role permission resolver is invalid");
  }
  if (resourcePolicy !== undefined && typeof resourcePolicy !== "function") {
    throw new TypeError("Open platform resource policy resolver is invalid");
  }
  if (permissionCache !== undefined && !isPermissionCache(permissionCache)) {
    throw new TypeError("Open platform permission cache is invalid");
  }
  if (
    !Number.isSafeInteger(permissionCacheTtlMs) ||
    permissionCacheTtlMs < 1_000 ||
    permissionCacheTtlMs > 300_000
  ) {
    throw new TypeError("Open platform permission cache TTL is invalid");
  }
  if (options.onDenied !== undefined && typeof options.onDenied !== "function") {
    throw new TypeError("Open platform denial handler is invalid");
  }
  const platformPermissionSet = new Set(platformPermissions);
  const authorizeWithReason = async (
    request: OpenPlatformAuthorizationRequest,
  ): Promise<OpenPlatformAuthorizationDecision> => {
    const decision = await evaluate(request);
    if (!decision.allowed && options.onDenied !== undefined) {
      try {
        await options.onDenied(decision.reason!);
      } catch {}
    }
    return decision;
  };
  return Object.freeze({
    productionReady,
    authorizeWithReason,
    invalidate,
    invalidateVersion: invalidateAuthorizationVersion,
    async authorize(request: OpenPlatformAuthorizationRequest) {
      return (await authorizeWithReason(request)).allowed === true;
    },
  });

  async function evaluate(
    request: OpenPlatformAuthorizationRequest,
  ): Promise<OpenPlatformAuthorizationDecision> {
    if (!validRequest(request)) return denied("invalid-request");
    const context = request.context;
    if (!isOpenPlatformRequestContext(context)) return denied("untrusted-context");
    if (
      productionReady
        ? context.assurance !== "authenticated"
        : context.assurance !== "authenticated" && context.assurance !== "development"
    ) {
      return denied("untrusted-context");
    }
    const actorId = normalizeActorId(context.actorId);
    const tenantId = normalizeTenantId(context.tenantId);
    if (actorId === undefined || tenantId === undefined) {
      return denied("untrusted-context");
    }
    if (tenantId !== request.tenantId) return denied("tenant-mismatch");
    const requiredPermission = toOpenPlatformRbacPermission(request);
    if (requiredPermission === undefined) return denied("unknown-permission");
    const resourceId = request.resourceId === undefined
      ? undefined
      : normalizeResourceId(request.resourceId);
    if (request.resourceId !== undefined && resourceId === undefined) {
      return denied("invalid-request");
    }
    if (resolver.productionReady !== productionReady) return denied("actor-unavailable");
    let resolved: OpenPlatformTrustedActorResolution | undefined;
    try {
      resolved = await resolver.resolve({
        actorId,
        tenantId,
      });
    } catch {
      return denied("resolver-unavailable");
    }
    if (resolved === undefined) return denied("actor-unavailable");
    const authority = normalizeAuthority(resolved, context);
    if (authority === undefined) return denied("actor-mismatch");
    const versionScope = authorizationScopeKey(actorId, tenantId);
    const previousPermissionVersion = latestPermissionVersions.get(versionScope);
    latestPermissionVersions.set(versionScope, authority.permissionVersion);
    if (
      previousPermissionVersion !== undefined &&
      previousPermissionVersion !== authority.permissionVersion
    ) {
      await invalidate({ actorId, tenantId });
    }
    const isTenantMember = authority.tenantIds.has(tenantId);
    const scope: OpenPlatformRoleScope = isTenantMember
      ? { kind: "tenant", tenantId }
      : { kind: "platform" };
    const roles = isTenantMember
      ? authority.tenantRoles
      : authority.platformRoles;
    if (!isTenantMember && roles.length === 0) return denied("tenant-scope-missing");
    if (
      !isTenantMember &&
      !platformPermissionSet.has(requiredPermission)
    ) {
      return denied("platform-boundary");
    }
    const permissions = [...authority.permissions];
    for (const role of roles) {
      const rolePermission = await resolveRolePermission(
        actorId,
        tenantId,
        authority.actor,
        role,
        scope,
        requiredPermission,
        resourceId,
        authority.permissionVersion,
        request,
      );
      if (rolePermission === invalidRoleResolution) {
        return denied("resolver-unavailable");
      }
      permissions.push(...rolePermission);
    }
    const granted = sanitizePermissions(permissions) ?? [];
    if (!hasPermission([...granted], requiredPermission)) {
      return denied("permission-denied");
    }
    if (resourcePolicy === undefined) return allowed();
    let policyResult: unknown;
    try {
      policyResult = await resourcePolicy({
        actor: authority.actor,
        actorId,
        tenantId,
        roles: Object.freeze([...roles]),
        scope,
        requiredPermission,
        permissionVersion: authority.permissionVersion,
        resource: request.resource,
        action: request.action,
        ...(resourceId === undefined ? {} : { resourceId }),
      });
    } catch {
      return denied("resolver-unavailable");
    }
    if (policyResult === true) return allowed();
    return denied(
      policyResult === false ? "permission-denied" : "invalid-policy-result",
    );
  }

  async function resolveRolePermission(
    actorId: string,
    tenantId: string,
    actor: ControlPlaneActor,
    role: string,
    scope: OpenPlatformRoleScope,
    requiredPermission: string,
    resourceId: string | undefined,
    permissionVersion: string,
    request: OpenPlatformAuthorizationRequest,
  ): Promise<readonly string[] | typeof invalidRoleResolution> {
    const cacheKeyInput: NormalizedCacheKeyInput = {
      actorId,
      tenantId,
      resourceKind: request.resource,
      resourceId,
      permission: requiredPermission,
      role,
      action: request.action,
      scope,
      permissionVersion,
      generation: currentAuthorizationGeneration(actorId, tenantId),
    };
    const cacheKey = permissionCacheKey(cacheKeyInput);
    const cacheMetadata: PermissionCacheMetadata = Object.freeze({
      key: cacheKey,
      actorId,
      tenantId,
      resourceKind: request.resource,
      resourceId,
      permission: requiredPermission,
      role,
    });
    if (permissionCache !== undefined) {
      try {
        const value = await permissionCache.get(cacheKey);
        if (value !== undefined) {
          const cached = sanitizePermissions(value);
          if (cached !== undefined) {
            knownPermissionCacheKeys.set(cacheKey, cacheMetadata);
            return cached;
          }
        }
      } catch {}
    }
    if (rolePermissions === undefined) return Object.freeze([]);
    let resolved: readonly string[];
    try {
      resolved = await rolePermissions({
        actor,
        role,
        scope,
        requiredPermission,
        resource: request.resource,
        action: request.action,
        ...(resourceId === undefined ? {} : { resourceId }),
      });
    } catch {
      return invalidRoleResolution;
    }
    const sanitized = sanitizePermissions(resolved);
    if (sanitized === undefined) return invalidRoleResolution;
    if (permissionCache !== undefined) {
      try {
        await permissionCache.set(cacheKey, sanitized, permissionCacheTtlMs);
        knownPermissionCacheKeys.set(cacheKey, cacheMetadata);
      } catch {}
    }
    return sanitized;
  }

  async function invalidate(
    selector: OpenPlatformPermissionCacheInvalidation = {},
  ): Promise<boolean> {
    const normalized = normalizeCacheInvalidation(selector);
    if (normalized === undefined) return false;
    if (permissionCache === undefined) return true;
    let successful = true;
    for (const [key, metadata] of knownPermissionCacheKeys) {
      if (!cacheMetadataMatches(metadata, normalized)) continue;
      try {
        await permissionCache.delete(key);
        knownPermissionCacheKeys.delete(key);
      } catch {
        successful = false;
      }
    }
    try {
      await permissionCache.invalidate(normalized);
    } catch {
      successful = false;
    }
    return successful;
  }

  async function invalidateAuthorizationVersion(
    input: OpenPlatformAuthorizationVersionInvalidation,
  ): Promise<boolean> {
    if (!isRecord(input)) return false;
    const actorId = normalizeActorId(input.actorId);
    const tenantId = normalizeTenantId(input.tenantId);
    if (actorId === undefined || tenantId === undefined) return false;
    const key = authorizationScopeKey(actorId, tenantId);
    const current = authorizationGenerations.get(key) ?? 0;
    authorizationGenerations.set(
      key,
      current === Number.MAX_SAFE_INTEGER ? current : current + 1,
    );
    return invalidate({ actorId, tenantId });
  }

  function currentAuthorizationGeneration(
    actorId: string,
    tenantId: string,
  ): number {
    return authorizationGenerations.get(authorizationScopeKey(actorId, tenantId)) ?? 0;
  }
}

function permissionCacheKey(input: NormalizedCacheKeyInput): string {
  return JSON.stringify([
    "open-platform-rbac-v2",
    input.actorId,
    input.tenantId,
    input.resourceKind,
    input.resourceId ?? null,
    input.permission,
    input.action,
    input.role,
    input.scope.kind,
    input.scope.kind === "tenant" ? input.scope.tenantId : null,
    input.permissionVersion,
    input.generation,
  ]);
}

function authorizationScopeKey(actorId: string, tenantId: string): string {
  return JSON.stringify([actorId, tenantId]);
}

function normalizeAuthority(
  value: OpenPlatformTrustedActorResolution,
  context: OpenPlatformRequestContext,
): NormalizedTrustedAuthority | undefined {
  if (!isRecord(value) || !isRecord(value.actor)) return undefined;
  const actor = value.actor;
  if (!isRecord(actor.user) || actor.user.id !== context.actorId) return undefined;
  const permissions = sanitizePermissions(actor.permissions);
  const actorRoles = normalizeRoleNames(actor.roles);
  if (permissions === undefined || actorRoles === undefined) return undefined;
  const tenantIds = normalizeTenantIds(value.tenantIds);
  const platformRoleNames = normalizeRoleNames(value.platformRoles ?? []);
  const permissionVersion = normalizePermissionVersion(value.permissionVersion);
  if (
    tenantIds === undefined ||
    platformRoleNames === undefined ||
    permissionVersion === undefined
  ) {
    return undefined;
  }
  const actorRoleSet = new Set(actorRoles);
  const platformRoles = platformRoleNames.filter((role) =>
    actorRoleSet.has(role)
  );
  const tenantRoleRecord = normalizeTenantRoleRecord(
    value.tenantRoles,
    tenantIds,
    actorRoleSet,
  );
  if (tenantRoleRecord === undefined) return undefined;
  const tenantRoles = tenantRoleRecord.get(context.tenantId) ?? [];
  const safeActor: ControlPlaneActor = Object.freeze({
    user: Object.freeze({ ...actor.user }),
    permissions: Object.freeze([...permissions]),
    roles: Object.freeze([...actorRoles]),
  });
  return Object.freeze({
    actor: safeActor,
    permissions,
    platformRoles: Object.freeze(platformRoles),
    tenantRoles: Object.freeze(tenantRoles),
    tenantIds,
    permissionVersion,
  });
}

function normalizeTenantRoleRecord(
  value: unknown,
  tenantIds: ReadonlySet<string>,
  actorRoles: ReadonlySet<string>,
): Map<string, readonly string[]> | undefined {
  if (value === undefined) return new Map();
  if (!isRecord(value) || Array.isArray(value)) return undefined;
  const output = new Map<string, readonly string[]>();
  for (const [tenantId, rawRoles] of Object.entries(value)) {
    if (!tenantIds.has(tenantId)) return undefined;
    const roles = normalizeRoleNames(rawRoles);
    if (roles === undefined) return undefined;
    output.set(
      tenantId,
      Object.freeze(roles.filter((role) => actorRoles.has(role))),
    );
  }
  return output;
}

function normalizeTenantIds(value: unknown): ReadonlySet<string> | undefined {
  if (!Array.isArray(value)) return undefined;
  const tenantIds = new Set<string>();
  for (const tenantId of value) {
    const normalized = normalizeTenantId(tenantId);
    if (normalized === undefined) return undefined;
    tenantIds.add(normalized);
  }
  return tenantIds;
}

function normalizeResourceId(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  const normalized = value.trim();
  if (
    normalized.length < 1 ||
    normalized.length > 256 ||
    CONTROL_OR_SPACE.test(normalized)
  ) {
    return undefined;
  }
  return normalized;
}

function normalizeActorId(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  const normalized = value.trim();
  return validActorId(normalized) ? normalized : undefined;
}

function normalizeTenantId(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  const normalized = value.trim();
  return TENANT_ID.test(normalized) ? normalized : undefined;
}

function normalizePermissionVersion(value: unknown): string | undefined {
  if (value === undefined) return "0";
  return normalizeActorId(value);
}

function normalizeCacheInvalidation(
  value: unknown,
): Readonly<OpenPlatformPermissionCacheInvalidation> | undefined {
  if (!isRecord(value)) return undefined;
  const actorId = value.actorId === undefined
    ? undefined
    : normalizeActorId(value.actorId);
  const tenantId = value.tenantId === undefined
    ? undefined
    : normalizeTenantId(value.tenantId);
  const resourceKind = value.resourceKind === undefined
    ? undefined
    : value.resourceKind;
  const resourceId = value.resourceId === undefined
    ? undefined
    : normalizeResourceId(value.resourceId);
  const permission = value.permission === undefined
    ? undefined
    : typeof value.permission === "string"
      ? value.permission.trim()
      : undefined;
  const role = value.role === undefined
    ? undefined
    : normalizeActorId(value.role);
  if (
    (value.actorId !== undefined && actorId === undefined) ||
    (value.tenantId !== undefined && tenantId === undefined) ||
    (resourceKind !== undefined && !isResourceKind(resourceKind)) ||
    (value.resourceId !== undefined && resourceId === undefined) ||
    (value.permission !== undefined && !validOpenPermission(permission ?? "")) ||
    (value.role !== undefined && role === undefined)
  ) {
    return undefined;
  }
  return Object.freeze({
    ...(actorId === undefined ? {} : { actorId }),
    ...(tenantId === undefined ? {} : { tenantId }),
    ...(resourceKind === undefined ? {} : { resourceKind }),
    ...(resourceId === undefined ? {} : { resourceId }),
    ...(permission === undefined ? {} : { permission }),
    ...(role === undefined ? {} : { role }),
  });
}

function cacheMetadataMatches(
  metadata: PermissionCacheMetadata,
  selector: Readonly<OpenPlatformPermissionCacheInvalidation>,
): boolean {
  return (
    (selector.actorId === undefined || metadata.actorId === selector.actorId) &&
    (selector.tenantId === undefined || metadata.tenantId === selector.tenantId) &&
    (
      selector.resourceKind === undefined ||
      metadata.resourceKind === selector.resourceKind
    ) &&
    (
      selector.resourceId === undefined ||
      metadata.resourceId === selector.resourceId
    ) &&
    (
      selector.permission === undefined ||
      metadata.permission === selector.permission
    ) &&
    (selector.role === undefined || metadata.role === selector.role)
  );
}

function isResourceKind(value: unknown): value is OpenPlatformAuthorizationRequest["resource"] {
  return (
    typeof value === "string" &&
    Object.hasOwn(RESOURCE_PERMISSIONS, value)
  );
}

function normalizeRoleNames(value: unknown): string[] | undefined {
  if (value === undefined) return [];
  if (!Array.isArray(value)) return undefined;
  const roles: string[] = [];
  const seen = new Set<string>();
  for (const role of value) {
    const normalized = normalizeActorId(role);
    if (normalized === undefined || seen.has(normalized)) return undefined;
    seen.add(normalized);
    roles.push(normalized);
  }
  return roles;
}

function sanitizePermissions(value: unknown): readonly string[] | undefined {
  if (value === undefined) return Object.freeze([]);
  if (!Array.isArray(value)) return undefined;
  const permissions: string[] = [];
  const seen = new Set<string>();
  for (const permission of value) {
    if (typeof permission !== "string" || !validOpenPermission(permission)) continue;
    if (seen.has(permission)) continue;
    seen.add(permission);
    permissions.push(permission);
  }
  return Object.freeze(permissions);
}

function validOpenPermission(value: string): boolean {
  const parts = value.split(":");
  if (
    (parts.length !== 3 && parts.length !== 4) ||
    parts[0] !== "open" ||
    !RESOURCE_PART.test(parts[1]) ||
    !RESOURCE_PART.test(parts[2])
  ) {
    return false;
  }
  if (parts.length === 3) return true;
  return parts[3] === "all" || parts[3] === "*";
}

function validatePlatformPermissions(value: unknown): readonly string[] {
  if (value === undefined) return Object.freeze([]);
  if (!Array.isArray(value)) {
    throw new TypeError("Open platform permission boundary is invalid");
  }
  const permissions: string[] = [];
  const seen = new Set<string>();
  for (const permission of value) {
    if (
      typeof permission !== "string" ||
      !VALID_REQUIRED_PERMISSIONS.has(permission)
    ) {
      throw new TypeError("Open platform permission boundary is invalid");
    }
    if (seen.has(permission)) continue;
    seen.add(permission);
    permissions.push(permission);
  }
  return Object.freeze(permissions);
}

function isPermissionCache(value: unknown): value is OpenPlatformPermissionCache {
  return (
    isRecord(value) &&
    typeof value.get === "function" &&
    typeof value.set === "function" &&
    typeof value.delete === "function" &&
    typeof value.invalidate === "function"
  );
}

function validRequest(value: unknown): value is OpenPlatformAuthorizationRequest {
  return (
    isRecord(value) &&
    isRecord(value.context) &&
    typeof value.tenantId === "string" &&
    typeof value.resource === "string" &&
    typeof value.action === "string" &&
    (value.resourceId === undefined || typeof value.resourceId === "string")
  );
}

function validActorId(value: unknown): value is string {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    value.length <= 128 &&
    !CONTROL_OR_SPACE.test(value)
  );
}

function freezeResolution(
  entry: OpenPlatformDevelopmentActorEntry,
): OpenPlatformTrustedActorResolution {
  return Object.freeze({
    actor: Object.freeze({
      ...entry.actor,
      permissions: entry.actor.permissions === undefined
        ? undefined
        : Object.freeze([...entry.actor.permissions]),
      roles: entry.actor.roles === undefined
        ? undefined
        : Object.freeze([...entry.actor.roles]),
    }),
    tenantIds: Object.freeze([...entry.tenantIds]),
    permissionVersion: entry.permissionVersion,
    platformRoles: entry.platformRoles === undefined
      ? undefined
      : Object.freeze([...entry.platformRoles]),
    tenantRoles: entry.tenantRoles === undefined
      ? undefined
      : Object.freeze(Object.fromEntries(
        Object.entries(entry.tenantRoles).map(([tenantId, roles]) => [
          tenantId,
          Object.freeze([...roles]),
        ]),
      )),
  });
}

function allowed(): OpenPlatformAuthorizationDecision {
  return Object.freeze({ allowed: true });
}

function denied(
  reason: OpenPlatformAuthorizationDenialReason,
): OpenPlatformAuthorizationDecision {
  return Object.freeze({ allowed: false, reason });
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
