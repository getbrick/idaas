import {
  isDevelopmentOpenPlatformAuthorization,
  isOpenPlatformRequestContext,
  type OpenPlatformAuthorizationAction,
  type OpenPlatformAuthorizationPort,
  type OpenPlatformAuthorizationRequest,
  type OpenPlatformRequestContext,
} from "../authorization.js";
import {
  forbidden,
  validationError,
} from "../errors.js";
import type {
  MaybePromise,
  OpenPlatformEntityKind,
} from "../types.js";
import type { CommerceDependencyReadiness } from "./types.js";

export const COMMERCE_AUTHORIZATION_ACTIONS = Object.freeze([
  "read",
  "create",
  "update",
  "record",
  "dispute.review",
  "dispute.decide",
  "dispute.withdraw",
] as const);

export type CommerceAuthorizationAction =
  (typeof COMMERCE_AUTHORIZATION_ACTIONS)[number];

export const COMMERCE_DISPUTE_AUTHORIZATION_ACTIONS = Object.freeze([
  "dispute.review",
  "dispute.decide",
  "dispute.withdraw",
] as const satisfies readonly CommerceAuthorizationAction[]);

export const COMMERCE_PLATFORM_AUTHORIZATION_ACTIONS: Readonly<
  Record<CommerceAuthorizationAction, string>
> = Object.freeze({
  read: "read",
  create: "create",
  update: "update",
  record: "record",
  "dispute.review": "dispute.review",
  "dispute.decide": "dispute.decide",
  "dispute.withdraw": "dispute.withdraw",
});

export const COMMERCE_AUTHORIZATION_RESOURCES = Object.freeze([
  "marketplaceListing",
  "partnerAccount",
  "commissionRule",
  "invoice",
] as const);

export type CommerceAuthorizationResource =
  (typeof COMMERCE_AUTHORIZATION_RESOURCES)[number];

export type CommercePermission =
  `${CommerceAuthorizationResource}.${CommerceAuthorizationAction}`;

export type DevelopmentCommercePermissions =
  | "all"
  | readonly CommercePermission[];

export interface CommerceAuthorizationRequest {
  readonly context: OpenPlatformRequestContext;
  readonly tenantId: string;
  readonly action: CommerceAuthorizationAction;
  readonly resource: CommerceAuthorizationResource;
  readonly resourceId?: string;
}

export interface CommerceAuthorizationPort {
  readonly productionReady: boolean;
  readonly readiness?: CommerceDependencyReadiness;
  authorize(
    request: CommerceAuthorizationRequest,
  ): MaybePromise<boolean>;
}

export const COMMERCE_AUTHORIZATION_ENTITY_KINDS: Readonly<
  Record<CommerceAuthorizationResource, OpenPlatformEntityKind>
> = Object.freeze({
  marketplaceListing: "apiProduct",
  partnerAccount: "developerOrganization",
  commissionRule: "apiProduct",
  invoice: "subscription",
});

export interface CommerceAuthorizationAdapterOptions {
  readonly entityKinds?: Partial<
    Record<CommerceAuthorizationResource, OpenPlatformEntityKind>
  >;
  readonly requireAuthenticatedAssurance?: boolean;
}

const developmentAuthorizers = new WeakSet<object>();
const unavailableAuthorizers = new WeakSet<object>();

export function createDevelopmentCommerceAuthorization(
  permissions: DevelopmentCommercePermissions = "all",
): CommerceAuthorizationPort {
  const allowed = normalizeDevelopmentPermissions(permissions);
  const authorizer: CommerceAuthorizationPort = Object.freeze({
    productionReady: false,
    authorize(request: CommerceAuthorizationRequest) {
      if (!isDevelopmentCommerceRequest(request)) return false;
      if (allowed === undefined) return true;
      return allowed.includes(commercePermissionFor(request));
    },
  });
  developmentAuthorizers.add(authorizer);
  return authorizer;
}

export function createUnavailableCommerceAuthorization(): CommerceAuthorizationPort {
  const authorizer: CommerceAuthorizationPort = Object.freeze({
    productionReady: false,
    authorize(): boolean {
      return false;
    },
  });
  unavailableAuthorizers.add(authorizer);
  return authorizer;
}

export function isDevelopmentCommerceAuthorization(
  value: CommerceAuthorizationPort,
): boolean {
  return developmentAuthorizers.has(value);
}

export function isUnavailableCommerceAuthorization(
  value: CommerceAuthorizationPort,
): boolean {
  return unavailableAuthorizers.has(value);
}

export function commercePermissionFor(
  request: CommerceAuthorizationRequest,
): CommercePermission {
  return `${request.resource}.${request.action}`;
}

export function commercePlatformAuthorizationAction(
  action: CommerceAuthorizationAction,
): OpenPlatformAuthorizationAction {
  return COMMERCE_PLATFORM_AUTHORIZATION_ACTIONS[
    action
  ] as OpenPlatformAuthorizationAction;
}

export function isCommerceAuthorizationPort(
  value: unknown,
): value is CommerceAuthorizationPort {
  return value !== null &&
    typeof value === "object" &&
    typeof (value as CommerceAuthorizationPort).authorize === "function" &&
    typeof (value as CommerceAuthorizationPort).productionReady === "boolean";
}

export function isCommerceAuthorizationProductionReady(
  value: CommerceAuthorizationPort,
): boolean {
  return value.productionReady === true &&
    !isDevelopmentCommerceAuthorization(value) &&
    !isUnavailableCommerceAuthorization(value);
}

export function createCommerceAuthorizationAdapter(
  authorization: OpenPlatformAuthorizationPort,
  options: CommerceAuthorizationAdapterOptions = {},
): CommerceAuthorizationPort {
  if (
    authorization === null ||
    typeof authorization !== "object" ||
    typeof authorization.authorize !== "function"
  ) {
    throw validationError("Open platform authorization port is invalid");
  }
  const entityKinds: Readonly<Record<CommerceAuthorizationResource, OpenPlatformEntityKind>> =
    Object.freeze({ ...COMMERCE_AUTHORIZATION_ENTITY_KINDS, ...(options.entityKinds ?? {}) });
  const requireAuthenticated = options.requireAuthenticatedAssurance === true;
  return Object.freeze({
    productionReady: isCommerceAuthorizationProductionReadyAdapter(authorization),
    authorize(request: CommerceAuthorizationRequest): MaybePromise<boolean> {
      if (!isCommerceRequest(request)) return false;
      if (requireAuthenticated && request.context.assurance !== "authenticated") {
        return false;
      }
      const forwarded: OpenPlatformAuthorizationRequest = {
        context: request.context,
        tenantId: request.tenantId,
        action: commercePlatformAuthorizationAction(request.action),
        resource: entityKinds[request.resource],
        ...(request.resourceId === undefined ? {} : { resourceId: request.resourceId }),
      };
      return Promise.resolve(authorization.authorize(forwarded))
        .then((allowed) => allowed === true)
        .catch(() => false);
    },
  });
}

export function isCommerceAuthorizationProductionReadyAdapter(
  authorization: OpenPlatformAuthorizationPort,
): boolean {
  return authorization.productionReady === true &&
    !isDevelopmentOpenPlatformAuthorization(authorization);
}

export async function requireCommerceAuthorization(
  authorization: CommerceAuthorizationPort,
  request: CommerceAuthorizationRequest,
): Promise<OpenPlatformRequestContext> {
  if (
    !isCommerceAuthorizationPort(authorization) ||
    !isOpenPlatformRequestContext(request.context) ||
    request.context.tenantId !== request.tenantId
  ) {
    throw forbidden();
  }
  let allowed = false;
  try {
    allowed = await authorization.authorize(request) === true;
  } catch {
    allowed = false;
  }
  if (!allowed) throw forbidden();
  return request.context;
}

function isCommerceRequest(
  request: CommerceAuthorizationRequest,
): request is CommerceAuthorizationRequest {
  return request !== null &&
    typeof request === "object" &&
    isOpenPlatformRequestContext(request.context) &&
    (request.context.assurance === "development" ||
      request.context.assurance === "authenticated") &&
    request.context.tenantId === request.tenantId &&
    isCommerceAuthorizationAction(request.action) &&
    isCommerceAuthorizationResource(request.resource) &&
    (request.resourceId === undefined || isSafeCommerceResourceId(request.resourceId));
}

function isDevelopmentCommerceRequest(
  request: CommerceAuthorizationRequest,
): request is CommerceAuthorizationRequest {
  return isCommerceRequest(request) && request.context.assurance === "development";
}

function isCommerceAuthorizationAction(
  value: unknown,
): value is CommerceAuthorizationAction {
  return typeof value === "string" &&
    (COMMERCE_AUTHORIZATION_ACTIONS as readonly string[]).includes(value);
}

function isCommerceAuthorizationResource(
  value: unknown,
): value is CommerceAuthorizationResource {
  return typeof value === "string" &&
    (COMMERCE_AUTHORIZATION_RESOURCES as readonly string[]).includes(value);
}

function isSafeCommerceResourceId(value: unknown): boolean {
  if (typeof value !== "string") return false;
  const normalized = value.trim();
  return normalized.length >= 1 &&
    normalized.length <= 256 &&
    !/[\s\u0000-\u001f\u007f]/su.test(normalized);
}

function normalizeDevelopmentPermissions(
  permissions: DevelopmentCommercePermissions,
): readonly CommercePermission[] | undefined {
  if (permissions === "all") return undefined;
  if (!Array.isArray(permissions) || permissions.length === 0) {
    throw validationError("Development commerce permissions are invalid");
  }
  const normalized: CommercePermission[] = [];
  for (const permission of permissions) {
    if (typeof permission !== "string" || !isCommercePermission(permission)) {
      throw validationError("Development commerce permissions are invalid");
    }
    normalized.push(permission);
  }
  return Object.freeze([...new Set(normalized)]);
}

function isCommercePermission(value: string): value is CommercePermission {
  const separator = value.indexOf(".");
  if (separator < 1) return false;
  const resource = value.slice(0, separator);
  const action = value.slice(separator + 1);
  return isCommerceAuthorizationResource(resource) &&
    isCommerceAuthorizationAction(action);
}
