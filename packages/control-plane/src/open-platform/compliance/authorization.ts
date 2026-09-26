import {
  isDevelopmentOpenPlatformAuthorization,
  isOpenPlatformRequestContext,
  type OpenPlatformAuthorizationPort,
  type OpenPlatformAuthorizationRequest,
  type OpenPlatformRequestContext,
} from "../authorization.js";
import { forbidden, validationError } from "../errors.js";
import type { MaybePromise, OpenPlatformEntityKind } from "../types.js";
import type { ComplianceDependencyReadiness } from "./types.js";

export const COMPLIANCE_AUTHORIZATION_ACTIONS = Object.freeze([
  "read",
  "create",
  "update",
  "record",
  "approve",
] as const);

export type ComplianceAuthorizationAction =
  (typeof COMPLIANCE_AUTHORIZATION_ACTIONS)[number];

export const COMPLIANCE_AUTHORIZATION_RESOURCES = Object.freeze([
  "dataAsset",
  "consentRecord",
  "privacyRequest",
  "retentionPolicy",
  "retentionExecution",
  "crossBorderAssessment",
  "vendor",
  "report",
] as const);

export type ComplianceAuthorizationResource =
  (typeof COMPLIANCE_AUTHORIZATION_RESOURCES)[number];

export type CompliancePermission =
  `${ComplianceAuthorizationResource}.${ComplianceAuthorizationAction}`;

export type DevelopmentCompliancePermissions = "all" | readonly CompliancePermission[];

export interface ComplianceAuthorizationRequest {
  readonly context: OpenPlatformRequestContext;
  readonly tenantId: string;
  readonly action: ComplianceAuthorizationAction;
  readonly resource: ComplianceAuthorizationResource;
  readonly resourceId?: string;
}

export interface ComplianceAuthorizationPort {
  readonly productionReady: boolean;
  readonly readiness?: ComplianceDependencyReadiness;
  authorize(
    request: ComplianceAuthorizationRequest,
  ): MaybePromise<boolean>;
}

export const COMPLIANCE_AUTHORIZATION_ENTITY_KINDS: Readonly<
  Record<ComplianceAuthorizationResource, OpenPlatformEntityKind>
> = Object.freeze({
  dataAsset: "tenant",
  consentRecord: "tenant",
  privacyRequest: "tenant",
  retentionPolicy: "tenant",
  retentionExecution: "tenant",
  crossBorderAssessment: "tenant",
  vendor: "tenant",
  report: "auditEvent",
});

export interface ComplianceAuthorizationAdapterOptions {
  readonly entityKinds?: Partial<
    Record<ComplianceAuthorizationResource, OpenPlatformEntityKind>
  >;
  readonly requireAuthenticatedAssurance?: boolean;
}

const developmentAuthorizers = new WeakSet<object>();
const unavailableAuthorizers = new WeakSet<object>();

export function createDevelopmentComplianceAuthorization(
  permissions: DevelopmentCompliancePermissions = "all",
): ComplianceAuthorizationPort {
  const allowed = normalizeDevelopmentPermissions(permissions);
  const authorizer: ComplianceAuthorizationPort = Object.freeze({
    productionReady: false,
    authorize(request: ComplianceAuthorizationRequest) {
      if (!isDevelopmentComplianceRequest(request)) return false;
      if (allowed === undefined) return true;
      return allowed.includes(compliancePermissionFor(request));
    },
  });
  developmentAuthorizers.add(authorizer);
  return authorizer;
}

export function createUnavailableComplianceAuthorization(): ComplianceAuthorizationPort {
  const authorizer: ComplianceAuthorizationPort = Object.freeze({
    productionReady: false,
    authorize(): boolean {
      return false;
    },
  });
  unavailableAuthorizers.add(authorizer);
  return authorizer;
}

export function isDevelopmentComplianceAuthorization(
  value: ComplianceAuthorizationPort,
): boolean {
  return developmentAuthorizers.has(value);
}

export function isUnavailableComplianceAuthorization(
  value: ComplianceAuthorizationPort,
): boolean {
  return unavailableAuthorizers.has(value);
}

export function compliancePermissionFor(
  request: ComplianceAuthorizationRequest,
): CompliancePermission {
  return `${request.resource}.${request.action}`;
}

export function isComplianceAuthorizationPort(
  value: unknown,
): value is ComplianceAuthorizationPort {
  return value !== null &&
    typeof value === "object" &&
    typeof (value as ComplianceAuthorizationPort).authorize === "function" &&
    typeof (value as ComplianceAuthorizationPort).productionReady === "boolean";
}

export function isComplianceAuthorizationProductionReady(
  value: ComplianceAuthorizationPort,
): boolean {
  return value.productionReady === true &&
    !isDevelopmentComplianceAuthorization(value) &&
    !isUnavailableComplianceAuthorization(value);
}

export function createComplianceAuthorizationAdapter(
  authorization: OpenPlatformAuthorizationPort,
  options: ComplianceAuthorizationAdapterOptions = {},
): ComplianceAuthorizationPort {
  if (
    authorization === null ||
    typeof authorization !== "object" ||
    typeof authorization.authorize !== "function"
  ) {
    throw validationError("Open platform authorization port is invalid");
  }
  const entityKinds: Readonly<
    Record<ComplianceAuthorizationResource, OpenPlatformEntityKind>
  > = Object.freeze({
    ...COMPLIANCE_AUTHORIZATION_ENTITY_KINDS,
    ...(options.entityKinds ?? {}),
  });
  const requireAuthenticated = options.requireAuthenticatedAssurance === true;
  return Object.freeze({
    productionReady: isComplianceAuthorizationProductionReadyAdapter(authorization),
    authorize(request: ComplianceAuthorizationRequest): MaybePromise<boolean> {
      if (!isComplianceRequest(request)) return false;
      if (requireAuthenticated && request.context.assurance !== "authenticated") {
        return false;
      }
      const forwarded: OpenPlatformAuthorizationRequest = {
        context: request.context,
        tenantId: request.tenantId,
        action: toPlatformAction(request.action),
        resource: entityKinds[request.resource],
        ...(request.resourceId === undefined ? {} : { resourceId: request.resourceId }),
      };
      return Promise.resolve(authorization.authorize(forwarded))
        .then((allowed) => allowed === true)
        .catch(() => false);
    },
  });
}

export function isComplianceAuthorizationProductionReadyAdapter(
  authorization: OpenPlatformAuthorizationPort,
): boolean {
  return authorization.productionReady === true &&
    !isDevelopmentOpenPlatformAuthorization(authorization);
}

export async function requireComplianceAuthorization(
  authorization: ComplianceAuthorizationPort,
  request: ComplianceAuthorizationRequest,
): Promise<OpenPlatformRequestContext> {
  if (
    !isComplianceAuthorizationPort(authorization) ||
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

function toPlatformAction(
  action: ComplianceAuthorizationAction,
): OpenPlatformAuthorizationRequest["action"] {
  switch (action) {
    case "read":
      return "read";
    case "create":
      return "create";
    case "update":
      return "update";
    case "record":
      return "record";
    case "approve":
      return "authorize";
  }
}

function isComplianceRequest(
  request: ComplianceAuthorizationRequest,
): request is ComplianceAuthorizationRequest {
  return request !== null &&
    typeof request === "object" &&
    isOpenPlatformRequestContext(request.context) &&
    (request.context.assurance === "development" ||
      request.context.assurance === "authenticated") &&
    request.context.tenantId === request.tenantId &&
    isComplianceAuthorizationAction(request.action) &&
    isComplianceAuthorizationResource(request.resource) &&
    (request.resourceId === undefined || isSafeComplianceResourceId(request.resourceId));
}

function isDevelopmentComplianceRequest(
  request: ComplianceAuthorizationRequest,
): request is ComplianceAuthorizationRequest {
  return isComplianceRequest(request) && request.context.assurance === "development";
}

function isComplianceAuthorizationAction(
  value: unknown,
): value is ComplianceAuthorizationAction {
  return typeof value === "string" &&
    (COMPLIANCE_AUTHORIZATION_ACTIONS as readonly string[]).includes(value);
}

function isComplianceAuthorizationResource(
  value: unknown,
): value is ComplianceAuthorizationResource {
  return typeof value === "string" &&
    (COMPLIANCE_AUTHORIZATION_RESOURCES as readonly string[]).includes(value);
}

function isSafeComplianceResourceId(value: unknown): boolean {
  if (typeof value !== "string") return false;
  const normalized = value.trim();
  return normalized.length >= 1 &&
    normalized.length <= 256 &&
    !/[\s\u0000-\u001f\u007f]/su.test(normalized);
}

function normalizeDevelopmentPermissions(
  permissions: DevelopmentCompliancePermissions,
): readonly CompliancePermission[] | undefined {
  if (permissions === "all") return undefined;
  if (!Array.isArray(permissions) || permissions.length === 0) {
    throw validationError("Development compliance permissions are invalid");
  }
  const normalized: CompliancePermission[] = [];
  for (const permission of permissions) {
    if (typeof permission !== "string" || !isCompliancePermission(permission)) {
      throw validationError("Development compliance permissions are invalid");
    }
    normalized.push(permission);
  }
  return Object.freeze([...new Set(normalized)]);
}

function isCompliancePermission(value: string): value is CompliancePermission {
  const separator = value.indexOf(".");
  if (separator < 1) return false;
  const resource = value.slice(0, separator);
  const action = value.slice(separator + 1);
  return isComplianceAuthorizationResource(resource) &&
    isComplianceAuthorizationAction(action);
}
