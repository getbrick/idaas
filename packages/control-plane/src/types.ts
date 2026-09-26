import type {
  AuditEventSummary as ContractAuditEventSummary,
  Capabilities as ContractCapabilities,
  RoleSummary as ContractRoleSummary,
  SessionSummary as ContractSessionSummary,
  SystemInfo as ContractSystemInfo,
  UserSummary as ContractUserSummary,
} from "@getbrick/idaas-contracts";

export const CONTROL_PLANE_BASE_PATH = "/api/idaas/v1";
export const CONTROL_PLANE_VERSION = "0.1.0";
export const CONTROL_PLANE_DEFAULT_LIMIT = 20;
export const CONTROL_PLANE_MAX_LIMIT = 100;
export const CONTROL_PLANE_DEFAULT_TENANT_ID = "default";

export type DateLike = string | number | Date;

export interface ControlPlaneUser {
  id: string;
  tenantId?: string;
  username?: string | null;
  displayName?: string | null;
  name?: string | null;
  email?: string | null;
  phoneNumber?: string | null;
  avatarUrl?: string | null;
  status?: string | null;
  role?: string | null;
  roles?: readonly string[] | null;
  emailVerified?: boolean | null;
  createdAt?: DateLike | null;
  updatedAt?: DateLike | null;
  lastLoginAt?: DateLike | null;
  [key: string]: unknown;
}

export interface ControlPlaneRole {
  id: string;
  tenantId?: string;
  code?: string | null;
  name?: string | null;
  description?: string | null;
  permissions?: readonly string[] | null;
  inheritedRoles?: readonly string[] | null;
  memberCount?: number | string | null;
  createdAt?: DateLike | null;
  updatedAt?: DateLike | null;
  [key: string]: unknown;
}

export interface ControlPlaneSession {
  id: string;
  tenantId?: string;
  userId?: string | null;
  organizationId?: string | null;
  status?: string | null;
  device?: string | null;
  ipAddress?: string | null;
  userAgent?: string | null;
  createdAt?: DateLike | null;
  lastActiveAt?: DateLike | null;
  expiresAt?: DateLike | null;
  revokedAt?: DateLike | null;
  requestId?: string | null;
  [key: string]: unknown;
}

export interface ControlPlaneAuditEvent {
  id?: string | null;
  tenantId?: string;
  event?: string | null;
  action?: string | null;
  userId?: string | null;
  actorId?: string | null;
  targetId?: string | null;
  organizationId?: string | null;
  requestId?: string | null;
  outcome?: string | null;
  ipAddress?: string | null;
  userAgent?: string | null;
  detail?: unknown;
  occurredAt?: DateLike | null;
  createdAt?: DateLike | null;
  [key: string]: unknown;
}

export type ControlPlaneUserRecord = ControlPlaneUser;
export type ControlPlaneRoleRecord = ControlPlaneRole;
export type ControlPlaneSessionRecord = ControlPlaneSession;
export type ControlPlaneAuditEventRecord = ControlPlaneAuditEvent;

export interface ControlPlanePageRequest {
  cursor?: string;
  limit?: number | string;
  pageSize?: number | string;
  page?: number | string;
  offset?: number | string;
}

export interface ControlPlaneUserQuery extends ControlPlanePageRequest {
  q?: string;
  search?: string;
  email?: string;
  status?: string;
  role?: string;
  id?: string;
  tenantId?: string;
}

export interface ControlPlaneRoleQuery extends ControlPlanePageRequest {
  q?: string;
  search?: string;
  code?: string;
  permission?: string;
  tenantId?: string;
}

export interface ControlPlaneSessionQuery extends ControlPlanePageRequest {
  userId?: string;
  status?: string;
  active?: boolean;
  from?: string;
  to?: string;
  tenantId?: string;
}

export interface ControlPlaneAuditEventQuery extends ControlPlanePageRequest {
  q?: string;
  search?: string;
  event?: string;
  action?: string;
  userId?: string;
  actorId?: string;
  targetId?: string;
  outcome?: string;
  from?: string;
  to?: string;
  tenantId?: string;
}

export interface ControlPlanePage<T> {
  items: T[];
  nextCursor?: string;
  hasMore: boolean;
  total: number;
}

export type UserPage = ControlPlanePage<ControlPlaneUser>;
export type RolePage = ControlPlanePage<ControlPlaneRole>;
export type SessionPage = ControlPlanePage<ControlPlaneSession>;
export type AuditEventPage = ControlPlanePage<ControlPlaneAuditEvent>;

export interface ControlPlaneRepositoryOptions {
  tenantId?: string;
  users?: readonly ControlPlaneUser[];
  roles?: readonly ControlPlaneRole[];
  sessions?: readonly ControlPlaneSession[];
  auditEvents?: readonly ControlPlaneAuditEvent[];
}

export interface ControlPlaneWriteContext {
  actorId?: string;
  requestId?: string;
  ipAddress?: string;
  userAgent?: string;
}

export interface ControlPlaneWriteRequest {
  requestId?: string;
  ipAddress?: string;
  userAgent?: string;
}

export interface ControlPlaneRevokeSessionsResult {
  userId: string;
  revokedCount: number;
  sessionIds: string[];
}

export type ControlPlaneRevokeSessionsDto = ControlPlaneRevokeSessionsResult;

export interface ControlPlaneRepository {
  readonly tenantId?: string;
  listUsers(query?: ControlPlaneUserQuery): ControlPlanePage<ControlPlaneUser> | Promise<ControlPlanePage<ControlPlaneUser>>;
  getUser(id: string): ControlPlaneUser | undefined | Promise<ControlPlaneUser | undefined>;
  listRoles(query?: ControlPlaneRoleQuery): ControlPlanePage<ControlPlaneRole> | Promise<ControlPlanePage<ControlPlaneRole>>;
  getRole(id: string): ControlPlaneRole | undefined | Promise<ControlPlaneRole | undefined>;
  listSessions(query?: ControlPlaneSessionQuery): ControlPlanePage<ControlPlaneSession> | Promise<ControlPlanePage<ControlPlaneSession>>;
  getSession(id: string): ControlPlaneSession | undefined | Promise<ControlPlaneSession | undefined>;
  listAuditEvents(query?: ControlPlaneAuditEventQuery): ControlPlanePage<ControlPlaneAuditEvent> | Promise<ControlPlanePage<ControlPlaneAuditEvent>>;
  getAuditEvent(id: string): ControlPlaneAuditEvent | undefined | Promise<ControlPlaneAuditEvent | undefined>;
  isReady?(): boolean | Promise<boolean>;
  hasOtherActiveUserWithRole?(id: string, role: string): boolean | Promise<boolean>;
  setUserStatus?(
    id: string,
    status: "active" | "disabled",
    context?: ControlPlaneWriteContext,
  ): ControlPlaneUser | Promise<ControlPlaneUser>;
  disableUser?(id: string, context?: ControlPlaneWriteContext): ControlPlaneUser | Promise<ControlPlaneUser>;
  enableUser?(id: string, context?: ControlPlaneWriteContext): ControlPlaneUser | Promise<ControlPlaneUser>;
  revokeSession?(id: string, context?: ControlPlaneWriteContext): ControlPlaneSession | Promise<ControlPlaneSession>;
  revokeUserSessions?(
    userId: string,
    context?: ControlPlaneWriteContext,
  ): ControlPlaneRevokeSessionsResult | Promise<ControlPlaneRevokeSessionsResult>;
  addAuditEvent?(event: ControlPlaneAuditEvent): ControlPlaneAuditEvent | Promise<ControlPlaneAuditEvent>;
  appendAuditEvent?(event: ControlPlaneAuditEvent): ControlPlaneAuditEvent | Promise<ControlPlaneAuditEvent>;
}

export interface ControlPlaneUserDto extends ContractUserSummary {
  name?: string;
  role?: string;
  roles: string[];
  emailVerified?: boolean;
}

export interface ControlPlaneRoleDto extends ContractRoleSummary {
  name: string;
  code?: string;
  permissions: string[];
  inheritedRoles: string[];
  memberCount?: number;
}

export interface ControlPlaneSessionDto extends ContractSessionSummary {
  id: string;
  status?: string;
  device?: string;
  ipAddress?: string;
  userAgent?: string;
}

export interface ControlPlaneAuditEventDto extends ContractAuditEventSummary {
  id: string;
  event: string;
  detail?: Record<string, unknown>;
  actor?: {
    id?: string;
    name?: string;
    email?: string;
  };
}

export interface ControlPlaneCapabilitiesDto extends ContractCapabilities {
  version: string;
  singleTenant: boolean;
  features: {
    users: boolean;
    roles: boolean;
    sessions: boolean;
    auditEvents: boolean;
    health: boolean;
  };
  pagination: {
    cursor: boolean;
    defaultLimit: number;
    maxLimit: number;
  };
  masking: boolean;
}

export interface ControlPlaneSystemInfoDto extends ContractSystemInfo {
  version: string;
  capabilities: ControlPlaneCapabilitiesDto;
  requestId?: string;
}

export interface ControlPlaneHealthDto {
  status: "ok" | "ready";
  service: "idaas-control-plane";
  version: string;
}

export interface ControlPlaneActor {
  user?: Record<string, unknown>;
  permissions?: readonly string[];
  roles?: readonly string[];
}

export interface ControlPlaneServiceOptions {
  requireActor?: boolean;
  adminRoles?: readonly string[];
  ownerRoles?: readonly string[];
  version?: string;
  defaultLimit?: number;
  maxLimit?: number;
  readiness?: () => boolean | Promise<boolean>;
}

export interface NormalizedPageQuery {
  cursor?: string;
  limit: number;
  offset?: number;
}

export interface NormalizedUserQuery extends NormalizedPageQuery {
  search?: string;
  q?: string;
  email?: string;
  status?: string;
  role?: string;
  id?: string;
}

export interface NormalizedRoleQuery extends NormalizedPageQuery {
  search?: string;
  q?: string;
  code?: string;
  permission?: string;
}

export interface NormalizedSessionQuery extends NormalizedPageQuery {
  userId?: string;
  status?: string;
  active?: boolean;
  from?: string;
  to?: string;
}

export interface NormalizedAuditEventQuery extends NormalizedPageQuery {
  search?: string;
  q?: string;
  event?: string;
  action?: string;
  userId?: string;
  actorId?: string;
  targetId?: string;
  outcome?: string;
  from?: string;
  to?: string;
}

export type {
  ContractAuditEventSummary,
  ContractCapabilities,
  ContractRoleSummary,
  ContractSessionSummary,
  ContractSystemInfo,
  ContractUserSummary,
};
