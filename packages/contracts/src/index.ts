export type RequestId = string;

export const ERROR_CODES = {
  BAD_REQUEST: "BAD_REQUEST",
  INVALID_REQUEST: "INVALID_REQUEST",
  UNAUTHENTICATED: "UNAUTHENTICATED",
  UNAUTHORIZED: "UNAUTHORIZED",
  FORBIDDEN: "FORBIDDEN",
  NOT_FOUND: "NOT_FOUND",
  CONFLICT: "CONFLICT",
  VALIDATION_ERROR: "VALIDATION_ERROR",
  VALIDATION_FAILED: "VALIDATION_FAILED",
  RATE_LIMITED: "RATE_LIMITED",
  DEPENDENCY_UNAVAILABLE: "DEPENDENCY_UNAVAILABLE",
  SERVICE_UNAVAILABLE: "SERVICE_UNAVAILABLE",
  INTERNAL_ERROR: "INTERNAL_ERROR",
} as const;

export type StableErrorCode = (typeof ERROR_CODES)[keyof typeof ERROR_CODES];
export type ErrorCode = StableErrorCode;

export interface RequestContext {
  requestId?: RequestId;
}

export interface ErrorDetails {
  code: ErrorCode;
  message: string;
  details?: unknown;
}

export interface ErrorEnvelope extends ErrorDetails, RequestContext {
}

export interface ErrorResponse {
  error: ErrorDetails;
  requestId?: RequestId;
}

export interface CursorPaginationRequest {
  cursor?: string;
  limit?: string;
  pageSize?: string;
}

export interface CursorPagination {
  nextCursor?: string;
  previousCursor?: string;
  hasMore?: unknown;
  total?: unknown;
}

export interface CursorPage extends CursorPagination {
  items?: unknown;
  data?: unknown;
}

export interface Capabilities {
  [name: string]: unknown;
  enabled?: unknown;
  disabled?: unknown;
  available?: unknown;
  experimental?: unknown;
  metadata?: unknown;
}

export interface UserSummary {
  id: string;
  username?: string;
  displayName?: string;
  email?: string;
  phoneNumber?: string;
  avatarUrl?: string;
  status?: string;
  organizationId?: string;
  emailVerified?: unknown;
  roles?: unknown;
  permissions?: unknown;
  capabilities?: Capabilities;
  createdAt?: string;
  updatedAt?: string;
  lastLoginAt?: string;
}

export interface RoleSummary {
  id: string;
  code?: string;
  name?: string;
  description?: string;
  organizationId?: string;
  inheritedRoles?: unknown;
  permissions?: unknown;
  capabilities?: unknown;
  createdAt?: string;
  updatedAt?: string;
}

export interface PermissionSummary {
  id: string;
  key?: string;
  code?: string;
  name?: string;
  description?: string;
  resource?: string;
  action?: string;
  scope?: string;
}

export interface OrganizationSummary {
  id: string;
  name?: string;
  slug?: string;
  parentId?: string;
  path?: string;
  status?: string;
  memberCount?: unknown;
  roles?: unknown;
  permissions?: unknown;
  capabilities?: unknown;
  createdAt?: string;
  updatedAt?: string;
}

export interface SessionSummary {
  id: string;
  userId?: string;
  organizationId?: string;
  status?: string;
  device?: unknown;
  ipAddress?: string;
  userAgent?: string;
  createdAt?: string;
  lastActiveAt?: string;
  expiresAt?: string;
  revokedAt?: string;
  requestId?: RequestId;
}

export interface AuditEventSummary {
  id?: string;
  event: string;
  action?: string;
  userId?: string;
  actorId?: string;
  targetId?: string;
  organizationId?: string;
  requestId?: RequestId;
  outcome?: string;
  ipAddress?: string;
  userAgent?: string;
  detail?: unknown;
  occurredAt?: string;
  createdAt?: string;
}

export interface SystemInfo {
  name?: string;
  version?: string;
  build?: string;
  commit?: string;
  environment?: string;
  region?: string;
  status?: string;
  startedAt?: string;
  uptime?: string;
  capabilities?: Capabilities;
  requestId?: RequestId;
}

export interface ControlPlaneContext {
  requestId?: RequestId;
  capabilities?: Capabilities;
  user?: UserSummary;
  roles?: unknown;
  permissions?: unknown;
  organization?: OrganizationSummary;
  session?: SessionSummary;
  system?: SystemInfo;
}

export * from "./application-management.js";
export * from "./oidc.js";
export * from "./open-platform.js";
export * from "./open-platform-compliance.js";
