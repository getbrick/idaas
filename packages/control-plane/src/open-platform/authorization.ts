import { validationError } from "./errors.js";
import type {
  MaybePromise,
  OpenPlatformEntityKind,
  OpenPlatformLifecycleStatus,
} from "./types.js";
import { normalizeTenantKey } from "./validation.js";

declare const openPlatformRequestContextBrand: unique symbol;

export type OpenPlatformContextAssurance = "development" | "authenticated";

export interface OpenPlatformRequestContext {
  readonly [openPlatformRequestContextBrand]: true;
  readonly tenantId: string;
  readonly actorId: string;
  readonly requestId: string;
  readonly issuerId: string;
  readonly assurance: OpenPlatformContextAssurance;
  readonly issuedAt: string;
}

export interface OpenPlatformRequestContextInput {
  tenantId: string;
  actorId: string;
  requestId: string;
}

export interface OpenPlatformRequestContextIssuer {
  readonly issuerId: string;
  issueAuthenticated(input: OpenPlatformRequestContextInput): OpenPlatformRequestContext;
  issueDevelopment(input: OpenPlatformRequestContextInput): OpenPlatformRequestContext;
}

export const OPEN_PLATFORM_LIFECYCLE_AUTHORIZATION_ACTIONS = Object.freeze([
  "publish",
  "disable",
  "archive",
  "submitReview",
] as const);

export type OpenPlatformLifecycleAuthorizationAction =
  (typeof OPEN_PLATFORM_LIFECYCLE_AUTHORIZATION_ACTIONS)[number];

export const OPEN_PLATFORM_LIFECYCLE_AUTHORIZATION_ACTION_ALIASES = Object.freeze({
  republish: "publish",
  "submit-review": "submitReview",
} as const satisfies Readonly<
  Record<string, OpenPlatformLifecycleAuthorizationAction>
>);

export type OpenPlatformLifecycleAuthorizationActionAlias =
  keyof typeof OPEN_PLATFORM_LIFECYCLE_AUTHORIZATION_ACTION_ALIASES;

export type OpenPlatformAuthorizationAction =
  | "create"
  | "read"
  | "update"
  | "issue"
  | "rotate"
  | "revoke"
  | "grant"
  | "authorize"
  | "record"
  | OpenPlatformLifecycleAuthorizationAction
  | OpenPlatformLifecycleAuthorizationActionAlias;

export const OPEN_PLATFORM_AUTHORIZATION_ACTIONS: readonly OpenPlatformAuthorizationAction[] =
  Object.freeze([
    "create",
    "read",
    "update",
    "issue",
    "rotate",
    "revoke",
    "grant",
    "authorize",
    "record",
    ...OPEN_PLATFORM_LIFECYCLE_AUTHORIZATION_ACTIONS,
    ...Object.keys(
      OPEN_PLATFORM_LIFECYCLE_AUTHORIZATION_ACTION_ALIASES,
    ) as readonly OpenPlatformLifecycleAuthorizationActionAlias[],
  ]);

const LIFECYCLE_AUTHORIZATION_ACTIONS_BY_STATUS: Readonly<
  Record<
    OpenPlatformLifecycleStatus,
    OpenPlatformLifecycleAuthorizationAction | undefined
  >
> = Object.freeze({
  draft: undefined,
  published: "publish",
  disabled: "disable",
  archived: "archive",
});

const DEVELOPMENT_PERMISSION = /^[A-Za-z]+\.[A-Za-z](?:[A-Za-z-]*[A-Za-z])?$/u;
const DEVELOPMENT_PERMISSION_RESOURCE = /^[A-Za-z]+$/u;
const DEVELOPMENT_PERMISSION_ACTION = /^[A-Za-z](?:[A-Za-z-]*[A-Za-z])?$/u;

export function isOpenPlatformAuthorizationAction(
  value: unknown,
): value is OpenPlatformAuthorizationAction {
  return typeof value === "string" &&
    (OPEN_PLATFORM_AUTHORIZATION_ACTIONS as readonly string[]).includes(value);
}

export function isOpenPlatformLifecycleAuthorizationAction(
  value: unknown,
): value is OpenPlatformLifecycleAuthorizationAction {
  return typeof value === "string" &&
    (OPEN_PLATFORM_LIFECYCLE_AUTHORIZATION_ACTIONS as readonly string[]).includes(
      value,
    );
}

export function canonicalOpenPlatformAuthorizationAction(
  action: unknown,
): OpenPlatformAuthorizationAction | undefined {
  if (!isOpenPlatformAuthorizationAction(action)) return undefined;
  return Object.hasOwn(OPEN_PLATFORM_LIFECYCLE_AUTHORIZATION_ACTION_ALIASES, action)
    ? OPEN_PLATFORM_LIFECYCLE_AUTHORIZATION_ACTION_ALIASES[
      action as OpenPlatformLifecycleAuthorizationActionAlias
    ]
    : action;
}

export function openPlatformLifecycleAuthorizationActionForStatus(
  status: unknown,
): OpenPlatformLifecycleAuthorizationAction | undefined {
  if (typeof status !== "string") return undefined;
  if (!Object.hasOwn(LIFECYCLE_AUTHORIZATION_ACTIONS_BY_STATUS, status)) {
    return undefined;
  }
  return LIFECYCLE_AUTHORIZATION_ACTIONS_BY_STATUS[
    status as OpenPlatformLifecycleStatus
  ];
}

export type OpenPlatformPermission =
  `${OpenPlatformEntityKind}.${OpenPlatformAuthorizationAction}`;

export interface OpenPlatformAuthorizationRequest {
  context: OpenPlatformRequestContext;
  tenantId: string;
  action: OpenPlatformAuthorizationAction;
  resource: OpenPlatformEntityKind;
  resourceId?: string;
}

export interface OpenPlatformAuthorizationPort {
  readonly productionReady: boolean;
  authorize(
    request: OpenPlatformAuthorizationRequest,
  ): MaybePromise<boolean>;
}

export interface OpenPlatformRequestContextIssuerOptions {
  issuerId: string;
  attestation: object;
  clock?: () => Date;
}

export type DevelopmentOpenPlatformPermissions =
  | "all"
  | readonly OpenPlatformPermission[];

const trustedContexts = new WeakSet<object>();
const developmentAuthorizers = new WeakSet<object>();

export function createOpenPlatformRequestContextIssuer(
  options: OpenPlatformRequestContextIssuerOptions,
): OpenPlatformRequestContextIssuer {
  if (
    options === null ||
    typeof options !== "object" ||
    options.attestation === null ||
    typeof options.attestation !== "object"
  ) {
    throw validationError("Open platform context issuer configuration is invalid");
  }
  const issuerId = requireContextPart(options.issuerId, "issuerId");
  const clock = options.clock ?? (() => new Date());
  const attestation = options.attestation;
  return Object.freeze({
    issuerId,
    issueAuthenticated(input: OpenPlatformRequestContextInput) {
      return issueContext(issuerId, clock, attestation, input, "authenticated");
    },
    issueDevelopment(input: OpenPlatformRequestContextInput) {
      return issueContext(issuerId, clock, attestation, input, "development");
    },
  });
}

export function createDevelopmentOpenPlatformRequestContext(
  input: OpenPlatformRequestContextInput,
  options: { issuerId?: string; clock?: () => Date } = {},
): OpenPlatformRequestContext {
  const issuer = createOpenPlatformRequestContextIssuer({
    issuerId: options.issuerId ?? "open-platform-development",
    attestation: Object.freeze({ development: true }),
    ...(options.clock === undefined ? {} : { clock: options.clock }),
  });
  return issuer.issueDevelopment(input);
}

export function isOpenPlatformRequestContext(
  value: unknown,
): value is OpenPlatformRequestContext {
  if (
    value === null ||
    typeof value !== "object" ||
    !trustedContexts.has(value) ||
    !Object.isFrozen(value)
  ) {
    return false;
  }
  const context = value as OpenPlatformRequestContext;
  return context.assurance === "development" ||
    context.assurance === "authenticated";
}

export function createDevelopmentOpenPlatformAuthorization(
  permissions: DevelopmentOpenPlatformPermissions,
): OpenPlatformAuthorizationPort {
  if (permissions !== "all" && !Array.isArray(permissions)) {
    throw validationError("Development open platform permissions are invalid");
  }
  const allowed = permissions === "all"
    ? undefined
    : Object.freeze([
      ...new Set(
        permissions.map((permission) => {
          const normalized = normalizeDevelopmentPermission(permission);
          if (normalized === undefined) {
            throw validationError("Development open platform permissions are invalid");
          }
          return normalized;
        }),
      ),
    ]);
  const authorizer: OpenPlatformAuthorizationPort = Object.freeze({
    productionReady: false,
    authorize(request: OpenPlatformAuthorizationRequest) {
      if (
        !isOpenPlatformRequestContext(request.context) ||
        request.context.assurance !== "development" ||
        request.context.tenantId !== request.tenantId
      ) {
        return false;
      }
      if (allowed === undefined) return true;
      const permission = permissionFor(request);
      return allowed.includes(permission);
    },
  });
  developmentAuthorizers.add(authorizer);
  return authorizer;
}

export function isDevelopmentOpenPlatformAuthorization(
  value: OpenPlatformAuthorizationPort,
): boolean {
  return developmentAuthorizers.has(value);
}

export function permissionFor(
  request: OpenPlatformAuthorizationRequest,
): OpenPlatformPermission {
  const action = canonicalOpenPlatformAuthorizationAction(request.action) ??
    request.action;
  return `${request.resource}.${action}`;
}

function normalizeDevelopmentPermission(value: unknown): string | undefined {
  if (typeof value !== "string" || !DEVELOPMENT_PERMISSION.test(value)) {
    return undefined;
  }
  const separator = value.indexOf(".");
  const resource = value.slice(0, separator);
  const action = value.slice(separator + 1);
  if (
    !DEVELOPMENT_PERMISSION_RESOURCE.test(resource) ||
    !DEVELOPMENT_PERMISSION_ACTION.test(action)
  ) {
    return undefined;
  }
  return `${resource}.${canonicalOpenPlatformAuthorizationAction(action) ?? action}`;
}

function issueContext(
  issuerId: string,
  clock: () => Date,
  attestation: object,
  input: OpenPlatformRequestContextInput,
  assurance: OpenPlatformContextAssurance,
): OpenPlatformRequestContext {
  if (
    attestation === null ||
    typeof attestation !== "object" ||
    input === null ||
    typeof input !== "object"
  ) {
    throw validationError("Open platform request context is invalid");
  }
  const issuedAt = clock();
  if (!(issuedAt instanceof Date) || !Number.isFinite(issuedAt.getTime())) {
    throw validationError("Open platform context clock is invalid");
  }
  const context = Object.freeze({
    tenantId: normalizeTenantKey(input.tenantId),
    actorId: requireContextPart(input.actorId, "actorId"),
    requestId: requireContextPart(input.requestId, "requestId"),
    issuerId,
    assurance,
    issuedAt: issuedAt.toISOString(),
  }) as OpenPlatformRequestContext;
  trustedContexts.add(context);
  return context;
}

function requireContextPart(value: unknown, field: string): string {
  if (typeof value !== "string") {
    throw validationError("Open platform request context is invalid", { field });
  }
  const normalized = value.trim();
  if (
    normalized.length < 1 ||
    normalized.length > 128 ||
    /[\s\u0000-\u001f\u007f]/u.test(normalized)
  ) {
    throw validationError("Open platform request context is invalid", { field });
  }
  return normalized;
}
