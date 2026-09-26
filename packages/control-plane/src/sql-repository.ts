import { randomUUID } from "node:crypto";
import {
  CONTROL_PLANE_DEFAULT_TENANT_ID,
  type ControlPlaneAuditEvent,
  type ControlPlaneAuditEventQuery,
  type ControlPlanePage,
  type ControlPlaneRepository,
  type ControlPlaneRevokeSessionsResult,
  type ControlPlaneRole,
  type ControlPlaneRoleQuery,
  type ControlPlaneSession,
  type ControlPlaneSessionQuery,
  type ControlPlaneUser,
  type ControlPlaneUserQuery,
  type ControlPlaneWriteContext,
} from "./types.js";
import { ControlPlaneSqlRollbackError, conflict, notFound } from "./errors.js";
import {
  parseAuditEventQuery,
  parseIdentifier,
  parseRoleQuery,
  parseSessionQuery,
  parseUserQuery,
} from "./validation.js";
import {
  auditScope,
  decodeCursor,
  encodeCursor,
  roleScope,
  sessionScope,
  userScope,
} from "./repository.js";
import {
  controlPlaneUserHasRole,
  controlPlaneUserRoles,
  isActiveControlPlaneSession,
  isActiveControlPlaneUser,
  normalizeControlPlaneStatus,
} from "./mutations.js";

export type ControlPlaneSqlQuery = (
  text: string,
  values: unknown[],
) => unknown | Promise<unknown>;

export interface ControlPlaneSqlExecutor {
  query: ControlPlaneSqlQuery;
  transaction?<T>(callback: (executor: ControlPlaneSqlExecutor) => Promise<T>): Promise<T>;
}

export type ControlPlaneQueryExecutor = ControlPlaneSqlExecutor;
export type SqlQueryExecutor = ControlPlaneSqlExecutor;

export interface ControlPlaneSqlTableNames {
  users: string;
  roles?: string;
  sessions: string;
  auditEvents: string;
  auditEvent?: string;
  user?: string;
  role?: string;
  session?: string;
  audit?: string;
}

export interface ControlPlaneSqlUserColumns {
  id: string;
  tenantId: string | null;
  username: string | null;
  displayName: string | null;
  name: string;
  email: string;
  phoneNumber: string | null;
  avatarUrl: string | null;
  status: string | null;
  role: string | null;
  roles: string | null;
  emailVerified: string;
  organizationId: string | null;
  createdAt: string;
  updatedAt: string;
  lastLoginAt: string | null;
}

export interface ControlPlaneSqlRoleColumns {
  id: string;
  tenantId: string | null;
  code: string;
  name: string;
  description: string;
  permissions: string;
  inheritedRoles: string;
  parents: string;
  memberCount: string;
  createdAt: string;
  updatedAt: string;
}

export interface ControlPlaneSqlSessionColumns {
  id: string;
  tenantId: string | null;
  userId: string;
  organizationId: string | null;
  status: string | null;
  device: string | null;
  ipAddress: string;
  userAgent: string;
  createdAt: string;
  lastActiveAt: string | null;
  expiresAt: string;
  revokedAt: string | null;
  requestId: string | null;
}

export interface ControlPlaneSqlAuditColumns {
  id: string;
  tenantId: string | null;
  event: string;
  action: string;
  userId: string;
  actorId: string;
  targetId: string;
  organizationId: string;
  requestId: string;
  outcome: string;
  ipAddress: string;
  userAgent: string;
  detail: string;
  occurredAt: string;
  createdAt: string;
}

export interface ControlPlaneSqlColumns {
  users?: Partial<ControlPlaneSqlUserColumns>;
  roles?: Partial<ControlPlaneSqlRoleColumns>;
  sessions?: Partial<ControlPlaneSqlSessionColumns>;
  auditEvents?: Partial<ControlPlaneSqlAuditColumns>;
}

export interface ControlPlaneSqlRepositoryOptions {
  executor?: ControlPlaneSqlExecutor;
  query?: ControlPlaneSqlQuery;
  tenantId?: string;
  tenantColumn?: string | null;
  tables?: Partial<ControlPlaneSqlTableNames>;
  tableNames?: Partial<ControlPlaneSqlTableNames>;
  usersTable?: string;
  userTable?: string;
  user?: string;
  rolesTable?: string;
  roleTable?: string;
  role?: string;
  sessionsTable?: string;
  sessionTable?: string;
  session?: string;
  auditEventsTable?: string;
  auditEventTable?: string;
  auditTable?: string;
  auditTableName?: string;
  auditEvent?: string;
  audit?: string;
  columns?: ControlPlaneSqlColumns;
  columnNames?: ControlPlaneSqlColumns;
  usersColumns?: Partial<ControlPlaneSqlUserColumns>;
  rolesColumns?: Partial<ControlPlaneSqlRoleColumns>;
  sessionsColumns?: Partial<ControlPlaneSqlSessionColumns>;
  auditEventsColumns?: Partial<ControlPlaneSqlAuditColumns>;
}

export type SqlControlPlaneRepositoryOptions = ControlPlaneSqlRepositoryOptions;
export type PostgresControlPlaneRepositoryOptions = ControlPlaneSqlRepositoryOptions;
export type PostgreSQLControlPlaneRepositoryOptions = ControlPlaneSqlRepositoryOptions;

type SqlRepositoryInput =
  | ControlPlaneSqlRepositoryOptions
  | ControlPlaneSqlExecutor
  | ControlPlaneSqlQuery;

type SqlRepositorySecondOptions = Omit<
  ControlPlaneSqlRepositoryOptions,
  "executor" | "query"
>;

type SqlRecord = Record<string, unknown>;

type NormalizedTables = {
  users: string;
  roles: string;
  sessions: string;
  auditEvents: string;
};

type NormalizedColumns = {
  users: ControlPlaneSqlUserColumns;
  roles: ControlPlaneSqlRoleColumns;
  sessions: ControlPlaneSqlSessionColumns;
  auditEvents: ControlPlaneSqlAuditColumns;
};

const DEFAULT_TABLES: NormalizedTables = {
  users: "users",
  roles: "roles",
  sessions: "sessions",
  auditEvents: "audit_events",
};

const DEFAULT_COLUMNS: NormalizedColumns = {
  users: {
    id: "id",
    tenantId: "tenantId",
    username: "username",
    displayName: "displayName",
    name: "name",
    email: "email",
    phoneNumber: "phoneNumber",
    avatarUrl: "avatarUrl",
    status: "status",
    role: "role",
    roles: "roles",
    emailVerified: "emailVerified",
    organizationId: "organizationId",
    createdAt: "createdAt",
    updatedAt: "updatedAt",
    lastLoginAt: "lastLoginAt",
  },
  roles: {
    id: "id",
    tenantId: "tenantId",
    code: "code",
    name: "name",
    description: "description",
    permissions: "permissions",
    inheritedRoles: "inheritedRoles",
    parents: "parents",
    memberCount: "memberCount",
    createdAt: "createdAt",
    updatedAt: "updatedAt",
  },
  sessions: {
    id: "id",
    tenantId: "tenantId",
    userId: "userId",
    organizationId: "organizationId",
    status: "status",
    device: "device",
    ipAddress: "ipAddress",
    userAgent: "userAgent",
    createdAt: "createdAt",
    lastActiveAt: "lastActiveAt",
    expiresAt: "expiresAt",
    revokedAt: "revokedAt",
    requestId: "requestId",
  },
  auditEvents: {
    id: "id",
    tenantId: "tenantId",
    event: "event",
    action: "action",
    userId: "userId",
    actorId: "actorId",
    targetId: "targetId",
    organizationId: "organizationId",
    requestId: "requestId",
    outcome: "outcome",
    ipAddress: "ipAddress",
    userAgent: "userAgent",
    detail: "detail",
    occurredAt: "occurredAt",
    createdAt: "createdAt",
  },
};

export const BETTER_AUTH_CONTROL_PLANE_TABLES = {
  users: "gb_idaas_user",
  sessions: "gb_idaas_session",
} as const;

export const BETTER_AUTH_CONTROL_PLANE_COLUMNS: ControlPlaneSqlColumns = {
  users: {
    id: "id",
    tenantId: null,
    username: null,
    displayName: "name",
    name: "name",
    email: "email",
    phoneNumber: null,
    avatarUrl: "image",
    status: null,
    role: null,
    roles: null,
    emailVerified: "emailVerified",
    organizationId: null,
    createdAt: "createdAt",
    updatedAt: "updatedAt",
    lastLoginAt: null,
  },
  sessions: {
    id: "id",
    tenantId: null,
    userId: "userId",
    organizationId: null,
    status: null,
    device: null,
    ipAddress: "ipAddress",
    userAgent: "userAgent",
    createdAt: "createdAt",
    lastActiveAt: null,
    expiresAt: "expiresAt",
    revokedAt: null,
    requestId: null,
  },
};

const USER_FIELDS: readonly (keyof ControlPlaneSqlUserColumns)[] = [
  "id",
  "tenantId",
  "username",
  "displayName",
  "name",
  "email",
  "phoneNumber",
  "avatarUrl",
  "status",
  "role",
  "roles",
  "emailVerified",
  "organizationId",
  "createdAt",
  "updatedAt",
  "lastLoginAt",
];

const ROLE_FIELDS: readonly (keyof ControlPlaneSqlRoleColumns)[] = [
  "id",
  "tenantId",
  "code",
  "name",
  "description",
  "permissions",
  "inheritedRoles",
  "parents",
  "memberCount",
  "createdAt",
  "updatedAt",
];

const SESSION_FIELDS: readonly (keyof ControlPlaneSqlSessionColumns)[] = [
  "id",
  "tenantId",
  "userId",
  "organizationId",
  "status",
  "device",
  "ipAddress",
  "userAgent",
  "createdAt",
  "lastActiveAt",
  "expiresAt",
  "revokedAt",
  "requestId",
];

const AUDIT_FIELDS: readonly (keyof ControlPlaneSqlAuditColumns)[] = [
  "id",
  "tenantId",
  "event",
  "action",
  "userId",
  "actorId",
  "targetId",
  "organizationId",
  "requestId",
  "outcome",
  "ipAddress",
  "userAgent",
  "detail",
  "occurredAt",
  "createdAt",
];

export class SqlControlPlaneRepository implements ControlPlaneRepository {
  readonly tenantId: string;
  private readonly executor: ControlPlaneSqlExecutor;
  private readonly tables: NormalizedTables;
  private readonly columns: NormalizedColumns;

  constructor(options: ControlPlaneSqlRepositoryOptions);
  constructor(executor: ControlPlaneSqlExecutor, options?: SqlRepositorySecondOptions);
  constructor(query: ControlPlaneSqlQuery, options?: SqlRepositorySecondOptions);
  constructor(
    input: SqlRepositoryInput,
    secondOptions: SqlRepositorySecondOptions = {},
  ) {
    const options = normalizeOptions(input, secondOptions);
    this.executor = normalizeExecutor(options);
    this.tenantId = normalizeTenantId(options.tenantId);
    this.tables = normalizeTables(options);
    this.columns = normalizeColumns(options);
  }

  async listUsers(query: ControlPlaneUserQuery = {}): Promise<ControlPlanePage<ControlPlaneUser>> {
    const normalized = parseUserQuery(query);
    const offset = cursorOffset("users", userScope(normalized), normalized.cursor, normalized.offset);
    const where = this.userWhere(normalized);
    const total = await this.count(`SELECT COUNT(*)::int AS "total" FROM ${this.usersTable()}${where.text}`, where.values);
    const rows = await this.queryRows(
      `SELECT ${this.select(this.columns.users, USER_FIELDS)} FROM ${this.usersTable()}${where.text} ORDER BY ${this.quote(this.columns.users.id)} ASC LIMIT $${where.values.length + 1} OFFSET $${where.values.length + 2}`,
      [...where.values, normalized.limit, offset],
    );
    const items = rows.map((row) => this.mapUser(row)).filter((user) => this.belongs(user));
    return this.page("users", normalized, items, total, userScope(normalized));
  }

  async getUser(id: string): Promise<ControlPlaneUser | undefined> {
    const identifier = parseIdentifier(id);
    const values: unknown[] = [];
    const clauses: string[] = [];
    this.addTenantClause("users", values, clauses);
    values.push(identifier);
    clauses.push(`${this.quote(this.columns.users.id)} = $${values.length}`);
    const rows = await this.queryRows(
      `SELECT ${this.select(this.columns.users, USER_FIELDS)} FROM ${this.usersTable()}${whereText(clauses)} LIMIT 1`,
      values,
    );
    if (rows.length === 0) return undefined;
    const user = this.mapUser(rows[0]);
    return this.belongs(user) ? user : undefined;
  }

  async listRoles(query: ControlPlaneRoleQuery = {}): Promise<ControlPlanePage<ControlPlaneRole>> {
    const normalized = parseRoleQuery(query);
    const offset = cursorOffset("roles", roleScope(normalized), normalized.cursor, normalized.offset);
    const values: unknown[] = [];
    const clauses: string[] = [];
    const columns = this.columns.roles;
    this.addTenantClause("roles", values, clauses);
    if (normalized.code !== undefined) {
      values.push(normalized.code);
      clauses.push(`${this.quote(columns.code)} = $${values.length}`);
    }
    if (normalized.permission !== undefined) {
      values.push(`%${normalized.permission}%`);
      clauses.push(`LOWER(COALESCE(${this.quote(columns.permissions)}::text, '')) LIKE LOWER($${values.length})`);
    }
    const search = normalized.search ?? normalized.q;
    if (search !== undefined) {
      values.push(`%${search}%`);
      clauses.push(`LOWER(COALESCE(${this.quote(columns.id)}, '')) LIKE LOWER($${values.length})`);
    }
    const where = whereText(clauses);
    const total = await this.count(`SELECT COUNT(*)::int AS "total" FROM ${this.rolesTable()}${where}`, values);
    const rows = await this.queryRows(
      `SELECT ${this.select(this.columns.roles, ROLE_FIELDS)} FROM ${this.rolesTable()}${where} ORDER BY ${this.quote(this.columns.roles.id)} ASC LIMIT $${values.length + 1} OFFSET $${values.length + 2}`,
      [...values, normalized.limit, offset],
    );
    const items = rows.map((row) => this.mapRole(row)).filter((role) => this.belongs(role));
    return this.page("roles", normalized, items, total, roleScope(normalized));
  }

  async getRole(id: string): Promise<ControlPlaneRole | undefined> {
    const identifier = parseIdentifier(id);
    const values: unknown[] = [];
    const clauses: string[] = [];
    this.addTenantClause("roles", values, clauses);
    values.push(identifier);
    const parameter = `$${values.length}`;
    clauses.push(`(${this.quote(this.columns.roles.id)} = ${parameter} OR ${this.quote(this.columns.roles.code)} = ${parameter})`);
    const rows = await this.queryRows(
      `SELECT ${this.select(this.columns.roles, ROLE_FIELDS)} FROM ${this.rolesTable()}${whereText(clauses)} LIMIT 1`,
      values,
    );
    if (rows.length === 0) return undefined;
    const role = this.mapRole(rows[0]);
    return this.belongs(role) ? role : undefined;
  }

  async listSessions(query: ControlPlaneSessionQuery = {}): Promise<ControlPlanePage<ControlPlaneSession>> {
    const normalized = parseSessionQuery(query);
    const offset = cursorOffset("sessions", sessionScope(normalized), normalized.cursor, normalized.offset);
    const where = this.sessionWhere(normalized);
    const total = await this.count(`SELECT COUNT(*)::int AS "total" FROM ${this.sessionsTable()}${where.text}`, where.values);
    const rows = await this.queryRows(
      `SELECT ${this.select(this.columns.sessions, SESSION_FIELDS)} FROM ${this.sessionsTable()}${where.text} ORDER BY ${this.quote(this.columns.sessions.id)} ASC LIMIT $${where.values.length + 1} OFFSET $${where.values.length + 2}`,
      [...where.values, normalized.limit, offset],
    );
    const items = rows.map((row) => this.mapSession(row)).filter((session) => this.belongs(session));
    return this.page("sessions", normalized, items, total, sessionScope(normalized));
  }

  async getSession(id: string): Promise<ControlPlaneSession | undefined> {
    const identifier = parseIdentifier(id);
    const values: unknown[] = [];
    const clauses: string[] = [];
    this.addTenantClause("sessions", values, clauses);
    values.push(identifier);
    clauses.push(`${this.quote(this.columns.sessions.id)} = $${values.length}`);
    const rows = await this.queryRows(
      `SELECT ${this.select(this.columns.sessions, SESSION_FIELDS)} FROM ${this.sessionsTable()}${whereText(clauses)} LIMIT 1`,
      values,
    );
    if (rows.length === 0) return undefined;
    const session = this.mapSession(rows[0]);
    return this.belongs(session) ? session : undefined;
  }

  async listAuditEvents(
    query: ControlPlaneAuditEventQuery = {},
  ): Promise<ControlPlanePage<ControlPlaneAuditEvent>> {
    const normalized = parseAuditEventQuery(query);
    const offset = cursorOffset("audit-events", auditScope(normalized), normalized.cursor, normalized.offset);
    const where = this.auditWhere(normalized);
    const total = await this.count(`SELECT COUNT(*)::int AS "total" FROM ${this.auditTable()}${where.text}`, where.values);
    const rows = await this.queryRows(
      `SELECT ${this.select(this.columns.auditEvents, AUDIT_FIELDS)} FROM ${this.auditTable()}${where.text} ORDER BY ${this.quote(this.columns.auditEvents.id)} ASC LIMIT $${where.values.length + 1} OFFSET $${where.values.length + 2}`,
      [...where.values, normalized.limit, offset],
    );
    const items = rows.map((row) => this.mapAudit(row)).filter((event) => this.belongs(event));
    return this.page("audit-events", normalized, items, total, auditScope(normalized));
  }

  async getAuditEvent(id: string): Promise<ControlPlaneAuditEvent | undefined> {
    const identifier = parseIdentifier(id);
    const values: unknown[] = [];
    const clauses: string[] = [];
    this.addTenantClause("auditEvents", values, clauses);
    values.push(identifier);
    clauses.push(`${this.quote(this.columns.auditEvents.id)} = $${values.length}`);
    const rows = await this.queryRows(
      `SELECT ${this.select(this.columns.auditEvents, AUDIT_FIELDS)} FROM ${this.auditTable()}${whereText(clauses)} LIMIT 1`,
      values,
    );
    if (rows.length === 0) return undefined;
    const event = this.mapAudit(rows[0]);
    return this.belongs(event) ? event : undefined;
  }

  async isReady(): Promise<boolean> {
    try {
      await this.queryRows(`SELECT 1 FROM ${this.usersTable()} LIMIT 0`, []);
      await this.queryRows(`SELECT 1 FROM ${this.rolesTable()} LIMIT 0`, []);
      await this.queryRows(`SELECT 1 FROM ${this.sessionsTable()} LIMIT 0`, []);
      await this.queryRows(`SELECT 1 FROM ${this.auditTable()} LIMIT 0`, []);
      return true;
    } catch {
      return false;
    }
  }

  async hasOtherActiveUserWithRole(id: string, role: string): Promise<boolean> {
    const target = await this.getUser(id);
    if (!target) return false;
    const values: unknown[] = [];
    const clauses: string[] = [];
    this.addTenantClause("users", values, clauses);
    if (this.columns.users.status !== null) {
      clauses.push(`LOWER(COALESCE(${this.quote(this.columns.users.status)}, 'active')) = 'active'`);
    }
    const rows = await this.queryRows(
      `SELECT ${this.select(this.columns.users, USER_FIELDS)} FROM ${this.usersTable()}${whereText(clauses)}`,
      values,
    );
    return rows
      .map((row) => this.mapUser(row))
      .filter((user) => this.belongs(user))
      .some((user) => user.id !== target.id && controlPlaneUserHasRole(user, role));
  }

  async setUserStatus(
    id: string,
    status: "active" | "disabled",
    context: ControlPlaneWriteContext = {},
  ): Promise<ControlPlaneUser> {
    const user = await this.getUser(id);
    if (!user) throw notFound("User not found");
    const currentStatus = normalizeControlPlaneStatus(user.status);
    if (status === "disabled" && currentStatus !== "active") {
      throw conflict("User is already disabled or cannot be disabled");
    }
    if (status === "active" && currentStatus !== "disabled") {
      throw conflict("User is already enabled or cannot be enabled");
    }
    if (status === "disabled") await this.assertNotLastPrivileged(user);
    const previousStatus = user.status ?? "active";
    const previousUpdatedAt = user.updatedAt ?? null;
    const updatedAt = new Date();
    return this.runMutation(async (executor) => {
      const statusColumn = this.requiredColumn(this.columns.users, "status");
      const updatedAtColumn = this.requiredColumn(this.columns.users, "updatedAt");
      const values: unknown[] = [status, updatedAt];
      const clauses: string[] = [];
      this.addTenantClause("users", values, clauses);
      values.push(user.id);
      clauses.push(`${this.quote(this.columns.users.id)} = $${values.length}`);
      values.push(currentStatus);
      clauses.push(`LOWER(COALESCE(${this.quote(statusColumn)}, 'active')) = LOWER($${values.length})`);
      const updatedCount = await this.queryAffected(
        `UPDATE ${this.usersTable()} SET ${this.quote(statusColumn)} = $1, ${this.quote(updatedAtColumn)} = $2${whereText(clauses)} RETURNING ${this.quote(this.columns.users.id)}`,
        values,
        executor,
      );
      if (updatedCount !== 1) {
        const current = await this.getUser(user.id);
        if (!current) throw notFound("User not found");
        throw conflict("User state changed");
      }
      const updated: ControlPlaneUser = {
        ...user,
        status,
        updatedAt,
      };
      try {
        await this.insertAudit(this.auditEventForUserMutation(user, status, context), executor);
      } catch (error) {
        if (this.supportsTransactions()) throw error;
        await this.rollbackAfterFailure(error, () =>
          this.restoreUserStatus(user.id, previousStatus, previousUpdatedAt, this.executor),
        );
      }
      return updated;
    });
  }

  async disableUser(id: string, context: ControlPlaneWriteContext = {}): Promise<ControlPlaneUser> {
    return this.setUserStatus(id, "disabled", context);
  }

  async enableUser(id: string, context: ControlPlaneWriteContext = {}): Promise<ControlPlaneUser> {
    return this.setUserStatus(id, "active", context);
  }

  async revokeSession(id: string, context: ControlPlaneWriteContext = {}): Promise<ControlPlaneSession> {
    const session = await this.getSession(id);
    if (!session) throw notFound("Session not found");
    if (!isActiveControlPlaneSession(session)) throw conflict("Session is already revoked or inactive");
    const revokedAt = new Date();
    return this.runMutation(async (executor) => {
      const statusColumn = this.requiredColumn(this.columns.sessions, "status");
      const revokedAtColumn = this.requiredColumn(this.columns.sessions, "revokedAt");
      const values: unknown[] = ["revoked", revokedAt];
      const clauses: string[] = [];
      this.addTenantClause("sessions", values, clauses);
      values.push(session.id);
      clauses.push(`${this.quote(this.columns.sessions.id)} = $${values.length}`);
      clauses.push(`LOWER(COALESCE(${this.quote(statusColumn)}, 'active')) = 'active'`);
      clauses.push(`${this.quote(revokedAtColumn)} IS NULL`);
      const updatedCount = await this.queryAffected(
        `UPDATE ${this.sessionsTable()} SET ${this.quote(statusColumn)} = $1, ${this.quote(revokedAtColumn)} = $2${whereText(clauses)} RETURNING ${this.quote(this.columns.sessions.id)}`,
        values,
        executor,
      );
      if (updatedCount !== 1) throw conflict("Session state changed");
      const updated: ControlPlaneSession = { ...session, status: "revoked", revokedAt };
      try {
        await this.insertAudit(this.auditEventForSessionMutation(session, context), executor);
      } catch (error) {
        if (this.supportsTransactions()) throw error;
        await this.rollbackAfterFailure(error, () =>
          this.restoreSession(session.id, session.status ?? "active", session.revokedAt ?? null, this.executor),
        );
      }
      return updated;
    });
  }

  async revokeUserSessions(
    userId: string,
    context: ControlPlaneWriteContext = {},
  ): Promise<ControlPlaneRevokeSessionsResult> {
    const user = await this.getUser(userId);
    if (!user) throw notFound("User not found");
    const sessions = await this.activeSessionsForUser(user.id);
    if (sessions.length === 0) throw conflict("User has no active sessions");
    const revokedAt = new Date();
    return this.runMutation(async (executor) => {
      const statusColumn = this.requiredColumn(this.columns.sessions, "status");
      const revokedAtColumn = this.requiredColumn(this.columns.sessions, "revokedAt");
      const values: unknown[] = ["revoked", revokedAt];
      const clauses: string[] = [];
      this.addTenantClause("sessions", values, clauses);
      values.push(user.id);
      clauses.push(`${this.quote(this.columns.sessions.userId)} = $${values.length}`);
      clauses.push(`LOWER(COALESCE(${this.quote(statusColumn)}, 'active')) = 'active'`);
      clauses.push(`${this.quote(revokedAtColumn)} IS NULL`);
      const updatedCount = await this.queryAffected(
        `UPDATE ${this.sessionsTable()} SET ${this.quote(statusColumn)} = $1, ${this.quote(revokedAtColumn)} = $2${whereText(clauses)} RETURNING ${this.quote(this.columns.sessions.id)}`,
        values,
        executor,
      );
      if (updatedCount !== sessions.length) {
        if (!this.supportsTransactions()) {
          await this.rollbackAfterFailure(
            conflict("Session state changed"),
            () => this.restoreSessions(sessions, this.executor),
          );
        }
        throw conflict("Session state changed");
      }
      const sessionIds = sessions.map((session) => session.id);
      try {
        await this.insertAudit(this.auditEventForUserSessionsMutation(user, sessionIds, context), executor);
      } catch (error) {
        if (this.supportsTransactions()) throw error;
        await this.rollbackAfterFailure(error, () => this.restoreSessions(sessions, this.executor));
      }
      return { userId: user.id, revokedCount: sessionIds.length, sessionIds };
    });
  }

  async deleteSession(id: string, context: ControlPlaneWriteContext = {}): Promise<ControlPlaneSession> {
    return this.revokeSession(id, context);
  }

  async revokeSessionsForUser(
    userId: string,
    context: ControlPlaneWriteContext = {},
  ): Promise<ControlPlaneRevokeSessionsResult> {
    return this.revokeUserSessions(userId, context);
  }

  private auditEventForUserMutation(
    user: ControlPlaneUser,
    status: "active" | "disabled",
    context: ControlPlaneWriteContext,
  ): ControlPlaneAuditEvent {
    const event = status === "disabled" ? "user.disabled" : "user.enabled";
    return {
      tenantId: this.tenantId,
      event,
      action: event,
      userId: user.id,
      actorId: contextValue(context.actorId),
      targetId: user.id,
      organizationId: contextValue(user.organizationId),
      requestId: contextValue(context.requestId),
      ipAddress: contextValue(context.ipAddress),
      userAgent: contextValue(context.userAgent),
      outcome: "success",
      detail: { status },
      occurredAt: new Date(),
      createdAt: new Date(),
    };
  }

  private auditEventForSessionMutation(
    session: ControlPlaneSession,
    context: ControlPlaneWriteContext,
  ): ControlPlaneAuditEvent {
    return {
      tenantId: this.tenantId,
      event: "session.revoked",
      action: "session.revoked",
      userId: contextValue(session.userId),
      actorId: contextValue(context.actorId),
      targetId: session.id,
      organizationId: contextValue(session.organizationId),
      requestId: contextValue(context.requestId),
      ipAddress: contextValue(context.ipAddress),
      userAgent: contextValue(context.userAgent),
      outcome: "success",
      detail: { status: "revoked" },
      occurredAt: new Date(),
      createdAt: new Date(),
    };
  }

  private auditEventForUserSessionsMutation(
    user: ControlPlaneUser,
    sessionIds: string[],
    context: ControlPlaneWriteContext,
  ): ControlPlaneAuditEvent {
    return {
      tenantId: this.tenantId,
      event: "user.sessions.revoked",
      action: "user.sessions.revoked",
      userId: user.id,
      actorId: contextValue(context.actorId),
      targetId: user.id,
      organizationId: contextValue(user.organizationId),
      requestId: contextValue(context.requestId),
      ipAddress: contextValue(context.ipAddress),
      userAgent: contextValue(context.userAgent),
      outcome: "success",
      detail: { revokedCount: sessionIds.length, sessionIds },
      occurredAt: new Date(),
      createdAt: new Date(),
    };
  }

  private async activeSessionsForUser(userId: string): Promise<ControlPlaneSession[]> {
    const values: unknown[] = [];
    const clauses: string[] = [];
    this.addTenantClause("sessions", values, clauses);
    values.push(userId);
    clauses.push(`${this.quote(this.columns.sessions.userId)} = $${values.length}`);
    if (this.columns.sessions.status !== null) {
      clauses.push(`LOWER(COALESCE(${this.quote(this.columns.sessions.status)}, 'active')) = 'active'`);
    }
    if (this.columns.sessions.revokedAt !== null) {
      clauses.push(`${this.quote(this.columns.sessions.revokedAt)} IS NULL`);
    }
    if (this.columns.sessions.status === null && this.columns.sessions.revokedAt === null) {
      clauses.push(`${this.quote(this.columns.sessions.expiresAt)} > CURRENT_TIMESTAMP`);
    }
    const rows = await this.queryRows(
      `SELECT ${this.select(this.columns.sessions, SESSION_FIELDS)} FROM ${this.sessionsTable()}${whereText(clauses)} ORDER BY ${this.quote(this.columns.sessions.id)} ASC`,
      values,
    );
    return rows.map((row) => this.mapSession(row)).filter((session) => this.belongs(session));
  }

  private async assertNotLastPrivileged(user: ControlPlaneUser): Promise<void> {
    for (const role of controlPlaneUserRoles(user)) {
      const normalized = role.toLowerCase();
      if (normalized !== "admin" && normalized !== "administrator" && normalized !== "owner") continue;
      const values: unknown[] = [];
      const clauses: string[] = [];
      this.addTenantClause("users", values, clauses);
      if (this.columns.users.status !== null) {
        clauses.push(`LOWER(COALESCE(${this.quote(this.columns.users.status)}, 'active')) = 'active'`);
      }
      const rows = await this.queryRows(
        `SELECT ${this.select(this.columns.users, USER_FIELDS)} FROM ${this.usersTable()}${whereText(clauses)}`,
        values,
      );
      const users = rows.map((row) => this.mapUser(row)).filter((item) => this.belongs(item));
      if (!users.some((item) => item.id !== user.id && controlPlaneUserHasRole(item, normalized))) {
        throw conflict(`Cannot disable the last ${normalized}`);
      }
    }
  }

  private async restoreUserStatus(
    id: string,
    status: unknown,
    updatedAt: unknown,
    executor: ControlPlaneSqlExecutor = this.executor,
  ): Promise<void> {
    const statusColumn = this.requiredColumn(this.columns.users, "status");
    const updatedAtColumn = this.requiredColumn(this.columns.users, "updatedAt");
    const values: unknown[] = [status, updatedAt];
    const clauses: string[] = [];
    this.addTenantClause("users", values, clauses);
    values.push(id);
    clauses.push(`${this.quote(this.columns.users.id)} = $${values.length}`);
    await this.queryRollback(
      `UPDATE ${this.usersTable()} SET ${this.quote(statusColumn)} = $1, ${this.quote(updatedAtColumn)} = $2${whereText(clauses)}`,
      values,
      executor,
    );
  }

  private async restoreSession(
    id: string,
    status: unknown,
    revokedAt: unknown,
    executor: ControlPlaneSqlExecutor = this.executor,
  ): Promise<void> {
    const statusColumn = this.requiredColumn(this.columns.sessions, "status");
    const revokedAtColumn = this.requiredColumn(this.columns.sessions, "revokedAt");
    const values: unknown[] = [status, revokedAt];
    const clauses: string[] = [];
    this.addTenantClause("sessions", values, clauses);
    values.push(id);
    clauses.push(`${this.quote(this.columns.sessions.id)} = $${values.length}`);
    await this.queryRollback(
      `UPDATE ${this.sessionsTable()} SET ${this.quote(statusColumn)} = $1, ${this.quote(revokedAtColumn)} = $2${whereText(clauses)}`,
      values,
      executor,
    );
  }

  private async restoreSessions(
    sessions: readonly ControlPlaneSession[],
    executor: ControlPlaneSqlExecutor = this.executor,
  ): Promise<void> {
    for (const session of sessions) {
      await this.restoreSession(session.id, session.status ?? "active", session.revokedAt ?? null, executor);
    }
  }

  async addAuditEvent(event: ControlPlaneAuditEvent): Promise<ControlPlaneAuditEvent> {
    return this.insertAudit(event);
  }

  async appendAuditEvent(event: ControlPlaneAuditEvent): Promise<ControlPlaneAuditEvent> {
    return this.insertAudit(event);
  }

  private async insertAudit(
    event: ControlPlaneAuditEvent,
    executor: ControlPlaneSqlExecutor = this.executor,
  ): Promise<ControlPlaneAuditEvent> {
    const id = typeof event.id === "string" && event.id.length > 0 ? event.id : randomUUID();
    const detail = event.detail === undefined ? null : safeJson(event.detail);
    const occurredAt = event.occurredAt ?? event.createdAt ?? new Date();
    const createdAt = event.createdAt ?? event.occurredAt ?? new Date();
    const valueByField: Record<string, unknown> = {
      id,
      tenantId: event.tenantId ?? this.tenantId,
      event: event.event ?? null,
      action: event.action ?? null,
      userId: event.userId ?? null,
      actorId: event.actorId ?? null,
      targetId: event.targetId ?? null,
      organizationId: event.organizationId ?? null,
      requestId: event.requestId ?? null,
      outcome: event.outcome ?? null,
      ipAddress: event.ipAddress ?? null,
      userAgent: event.userAgent ?? null,
      detail,
      occurredAt,
      createdAt,
    };
    const fields = AUDIT_FIELDS.filter((field) => this.columns.auditEvents[field] !== null);
    const columns = fields.map((field) => this.quote(this.columns.auditEvents[field] as string));
    const values = fields.map((field) => valueByField[field]);
    const placeholders = values.map((_value, index) => `$${index + 1}`);
    const insertedCount = await this.queryAffected(
      `INSERT INTO ${this.auditTable()} (${columns.join(", ")}) VALUES (${placeholders.join(", ")}) RETURNING ${this.quote(this.columns.auditEvents.id)}`,
      values,
      executor,
    );
    if (insertedCount !== 1) throw new Error("Control-plane SQL audit write failed");
    return {
      ...event,
      id,
      tenantId: this.columns.auditEvents.tenantId === null
        ? this.tenantId
        : String(event.tenantId ?? this.tenantId),
      detail: event.detail,
    };
  }

  private async queryRollback(
    text: string,
    values: readonly unknown[],
    executor: ControlPlaneSqlExecutor = this.executor,
  ): Promise<void> {
    let result: unknown;
    try {
      result = await executor.query(text, [...values]);
    } catch (error) {
      throw sqlQueryError(error);
    }
    if (isRecord(result) && typeof result.rowCount === "number" && Number.isSafeInteger(result.rowCount)) {
      if (result.rowCount > 0) return;
      throw new Error("Control-plane SQL rollback did not affect a row");
    }
    if (isRecord(result) && typeof result.rowCount === "bigint" && result.rowCount >= 0n) {
      if (result.rowCount > 0n && Number.isSafeInteger(Number(result.rowCount))) return;
      throw new Error("Control-plane SQL rollback did not affect a row");
    }
    if (resultRows(result) === undefined) throw new Error("Control-plane SQL rollback result failed");
  }

  private async queryAffected(
    text: string,
    values: readonly unknown[],
    executor: ControlPlaneSqlExecutor = this.executor,
  ): Promise<number> {
    let result: unknown;
    try {
      result = await executor.query(text, [...values]);
    } catch (error) {
      throw sqlQueryError(error);
    }
    if (isRecord(result) && typeof result.rowCount === "number" && Number.isSafeInteger(result.rowCount) && result.rowCount >= 0) {
      return result.rowCount;
    }
    if (isRecord(result) && typeof result.rowCount === "bigint" && result.rowCount >= 0n) {
      const count = Number(result.rowCount);
      if (Number.isSafeInteger(count)) return count;
    }
    const rows = resultRows(result);
    if (rows !== undefined) return rows.length;
    throw new Error("Control-plane SQL result failed");
  }

  private async count(text: string, values: readonly unknown[]): Promise<number> {
    const rows = await this.queryRows(text, values);
    if (rows.length === 0) return 0;
    const raw = rows[0]?.total ?? rows[0]?.count;
    if (typeof raw === "number" && Number.isSafeInteger(raw) && raw >= 0) return raw;
    if (typeof raw === "bigint" && raw >= 0n && Number.isSafeInteger(Number(raw))) return Number(raw);
    if (typeof raw === "string" && /^\d+$/u.test(raw)) return Number(raw);
    return rows.length;
  }

  private async queryRows(
    text: string,
    values: readonly unknown[],
    executor: ControlPlaneSqlExecutor = this.executor,
  ): Promise<SqlRecord[]> {
    let result: unknown;
    try {
      result = await executor.query(text, [...values]);
    } catch (error) {
      throw sqlQueryError(error);
    }
    const rows = resultRows(result);
    if (rows === undefined) throw new Error("Control-plane SQL result failed");
    return rows.map((row) => {
      if (!isRecord(row)) throw new Error("Control-plane SQL row failed");
      return row;
    });
  }

  private page<T>(
    kind: string,
    query: { cursor?: string; limit: number; offset?: number },
    items: T[],
    total: number,
    scope: string,
  ): ControlPlanePage<T> {
    const offset = cursorOffset(kind, scope, query.cursor, query.offset);
    const page: ControlPlanePage<T> = {
      items,
      hasMore: offset + items.length < total,
      total,
    };
    if (page.hasMore) page.nextCursor = encodeCursor({ version: 1, kind, offset: offset + items.length, scope });
    return page;
  }

  private userWhere(query: ReturnType<typeof parseUserQuery>): { text: string; values: unknown[] } {
    const values: unknown[] = [];
    const columns = this.columns.users;
    const clauses: string[] = [];
    this.addTenantClause("users", values, clauses);
    if (query.id !== undefined) {
      values.push(query.id);
      clauses.push(`${this.quote(columns.id)} = $${values.length}`);
    }
    if (query.email !== undefined) {
      values.push(query.email);
      clauses.push(`LOWER(${this.quote(columns.email)}) = LOWER($${values.length})`);
    }
    if (query.status !== undefined && columns.status !== null) {
      values.push(query.status);
      clauses.push(`LOWER(COALESCE(${this.quote(columns.status)}, 'active')) = LOWER($${values.length})`);
    }
    if (query.role !== undefined && (columns.role !== null || columns.roles !== null)) {
      values.push(query.role);
      const parameter = `$${values.length}`;
      const roleConditions: string[] = [];
      if (columns.role !== null) {
        roleConditions.push(`LOWER(COALESCE(${this.quote(columns.role)}, '')) = LOWER(${parameter})`);
      }
      if (columns.roles !== null) {
        roleConditions.push(`LOWER(COALESCE(${this.quote(columns.roles)}::text, '')) LIKE LOWER(${parameter})`);
      }
      clauses.push(`(${roleConditions.join(" OR ")})`);
    }
    const search = query.search ?? query.q;
    if (search !== undefined) {
      const searchColumns = [
        columns.id,
        columns.username,
        columns.displayName,
        columns.name,
        columns.email,
        columns.role,
      ].filter((column): column is string => column !== null);
      if (searchColumns.length > 0) {
        values.push(`%${search}%`);
        const parameter = `$${values.length}`;
        clauses.push(`(${searchColumns.map((column) => `LOWER(COALESCE(${this.quote(column)}, '')) LIKE LOWER(${parameter})`).join(" OR ")})`);
      }
    }
    return { text: whereText(clauses), values };
  }

  private sessionWhere(query: ReturnType<typeof parseSessionQuery>): { text: string; values: unknown[] } {
    const values: unknown[] = [];
    const columns = this.columns.sessions;
    const clauses: string[] = [];
    this.addTenantClause("sessions", values, clauses);
    if (query.userId !== undefined) {
      values.push(query.userId);
      clauses.push(`${this.quote(columns.userId)} = $${values.length}`);
    }
    if (query.status !== undefined && columns.status !== null) {
      values.push(query.status);
      clauses.push(`LOWER(${this.quote(columns.status)}) = LOWER($${values.length})`);
    }
    if (query.active !== undefined) {
      const activeConditions: string[] = [];
      const inactiveConditions: string[] = [];
      if (columns.status !== null) {
        const status = this.quote(columns.status);
        activeConditions.push(`LOWER(COALESCE(${status}, 'active')) = 'active'`);
        inactiveConditions.push(`LOWER(COALESCE(${status}, 'active')) <> 'active'`);
      }
      if (columns.revokedAt !== null) {
        const revokedAt = this.quote(columns.revokedAt);
        activeConditions.push(`${revokedAt} IS NULL`);
        inactiveConditions.push(`${revokedAt} IS NOT NULL`);
      }
      if (activeConditions.length === 0) {
        const expiresAt = this.quote(columns.expiresAt);
        activeConditions.push(`${expiresAt} > CURRENT_TIMESTAMP`);
        inactiveConditions.push(`${expiresAt} <= CURRENT_TIMESTAMP`);
      }
      clauses.push(query.active
        ? `(${activeConditions.join(" AND ")})`
        : `(${inactiveConditions.join(" OR ")})`);
    }
    const activityColumn = columns.lastActiveAt ?? columns.createdAt;
    if (query.from !== undefined) {
      values.push(query.from);
      clauses.push(`COALESCE(${this.quote(activityColumn)}, ${this.quote(columns.createdAt)}) >= $${values.length}`);
    }
    if (query.to !== undefined) {
      values.push(query.to);
      clauses.push(`COALESCE(${this.quote(activityColumn)}, ${this.quote(columns.createdAt)}) <= $${values.length}`);
    }
    return { text: whereText(clauses), values };
  }

  private auditWhere(query: ReturnType<typeof parseAuditEventQuery>): { text: string; values: unknown[] } {
    const values: unknown[] = [];
    const columns = this.columns.auditEvents;
    const clauses: string[] = [];
    this.addTenantClause("auditEvents", values, clauses);
    const add = (column: string, value: unknown): void => {
      values.push(value);
      clauses.push(`LOWER(COALESCE(${this.quote(column)}, '')) = LOWER($${values.length})`);
    };
    if (query.event !== undefined) add(columns.event, query.event);
    if (query.action !== undefined) add(columns.action, query.action);
    if (query.userId !== undefined) add(columns.userId, query.userId);
    if (query.actorId !== undefined) add(columns.actorId, query.actorId);
    if (query.targetId !== undefined) add(columns.targetId, query.targetId);
    if (query.outcome !== undefined) add(columns.outcome, query.outcome);
    const search = query.search ?? query.q;
    if (search !== undefined) {
      values.push(`%${search}%`);
      const parameter = `$${values.length}`;
      clauses.push(`(${[
        columns.id,
        columns.event,
        columns.action,
        columns.userId,
        columns.actorId,
        columns.targetId,
        columns.outcome,
      ].map((column) => `LOWER(COALESCE(${this.quote(column)}, '')) LIKE LOWER(${parameter})`).join(" OR ")})`);
    }
    if (query.from !== undefined) {
      values.push(query.from);
      clauses.push(`COALESCE(${this.quote(columns.occurredAt)}, ${this.quote(columns.createdAt)}) >= $${values.length}`);
    }
    if (query.to !== undefined) {
      values.push(query.to);
      clauses.push(`COALESCE(${this.quote(columns.occurredAt)}, ${this.quote(columns.createdAt)}) <= $${values.length}`);
    }
    return { text: whereText(clauses), values };
  }

  private supportsTransactions(): boolean {
    return typeof this.executor.transaction === "function";
  }

  private runMutation<T>(operation: (executor: ControlPlaneSqlExecutor) => Promise<T>): Promise<T> {
    if (!this.supportsTransactions()) return operation(this.executor);
    return this.executor.transaction!(operation);
  }

  private async rollbackAfterFailure(
    originalError: unknown,
    rollback: () => Promise<void>,
  ): Promise<never> {
    try {
      await rollback();
    } catch (rollbackError) {
      throw new ControlPlaneSqlRollbackError(originalError, rollbackError);
    }
    throw originalError;
  }

  private requiredColumn<T extends object>(columns: T, field: keyof T & string): string {
    const column = columns[field];
    if (typeof column !== "string") throw new TypeError(`SQL column ${field} is not configured`);
    return column;
  }

  private addTenantClause(
    table: keyof NormalizedColumns,
    values: unknown[],
    clauses: string[],
  ): void {
    const column = this.columns[table].tenantId;
    if (column === null) return;
    values.push(this.tenantId);
    clauses.push(`${this.quote(column)} = $${values.length}`);
  }

  private select<T extends object>(columns: T, fields: readonly (keyof T & string)[]): string {
    return fields.flatMap((field) => {
      const column = columns[field];
      return typeof column === "string" ? [`${this.quote(column)} AS ${this.quote(field)}`] : [];
    }).join(", ");
  }

  private mapUser(row: SqlRecord): ControlPlaneUser {
    const value = (key: string): unknown => rowValue(row, key);
    const id = requiredString(value("id"), "user");
    const user: ControlPlaneUser = { id, tenantId: this.rowTenant(row, "users") };
    assignText(user, "username", value("username"));
    assignText(user, "displayName", value("displayName"));
    assignText(user, "name", value("name"));
    assignText(user, "email", value("email"));
    assignText(user, "phoneNumber", value("phoneNumber"));
    assignText(user, "avatarUrl", value("avatarUrl"));
    assignText(user, "status", value("status"));
    assignText(user, "role", value("role"));
    const roles = roleValues(value("roles"));
    if (roles.length > 0) user.roles = roles;
    const emailVerified = booleanValue(value("emailVerified"));
    if (emailVerified !== undefined) user.emailVerified = emailVerified;
    assignText(user, "organizationId", value("organizationId"));
    assignDate(user, "createdAt", value("createdAt"));
    assignDate(user, "updatedAt", value("updatedAt"));
    assignDate(user, "lastLoginAt", value("lastLoginAt"));
    return user;
  }

  private mapRole(row: SqlRecord): ControlPlaneRole {
    const value = (key: string): unknown => rowValue(row, key);
    const id = requiredString(value("id"), "role");
    const role: ControlPlaneRole = { id, tenantId: this.rowTenant(row, "roles") };
    assignText(role, "code", value("code"));
    assignText(role, "name", value("name"));
    assignText(role, "description", value("description"));
    const permissions = roleValues(value("permissions"));
    if (permissions.length > 0) role.permissions = permissions;
    const inherited = roleValues(value("inheritedRoles") ?? value("parents"));
    if (inherited.length > 0) role.inheritedRoles = inherited;
    const memberCount = value("memberCount");
    if (typeof memberCount === "number") role.memberCount = memberCount;
    else if (typeof memberCount === "string" && /^\d+$/u.test(memberCount)) role.memberCount = Number(memberCount);
    assignDate(role, "createdAt", value("createdAt"));
    assignDate(role, "updatedAt", value("updatedAt"));
    return role;
  }

  private mapSession(row: SqlRecord): ControlPlaneSession {
    const value = (key: string): unknown => rowValue(row, key);
    const id = requiredString(value("id"), "session");
    const session: ControlPlaneSession = { id, tenantId: this.rowTenant(row, "sessions") };
    assignText(session, "userId", value("userId"));
    assignText(session, "organizationId", value("organizationId"));
    assignText(session, "status", value("status"));
    assignText(session, "device", value("device"));
    assignText(session, "ipAddress", value("ipAddress"));
    assignText(session, "userAgent", value("userAgent"));
    assignDate(session, "createdAt", value("createdAt"));
    assignDate(session, "lastActiveAt", value("lastActiveAt"));
    assignDate(session, "expiresAt", value("expiresAt"));
    assignDate(session, "revokedAt", value("revokedAt"));
    assignText(session, "requestId", value("requestId"));
    return session;
  }

  private mapAudit(row: SqlRecord): ControlPlaneAuditEvent {
    const value = (key: string): unknown => rowValue(row, key);
    const event: ControlPlaneAuditEvent = { id: requiredString(value("id"), "audit event"), tenantId: this.rowTenant(row, "auditEvents") };
    assignText(event, "event", value("event"));
    assignText(event, "action", value("action"));
    assignText(event, "userId", value("userId"));
    assignText(event, "actorId", value("actorId"));
    assignText(event, "targetId", value("targetId"));
    assignText(event, "organizationId", value("organizationId"));
    assignText(event, "requestId", value("requestId"));
    assignText(event, "outcome", value("outcome"));
    assignText(event, "ipAddress", value("ipAddress"));
    assignText(event, "userAgent", value("userAgent"));
    const detail = value("detail");
    if (detail !== undefined && detail !== null) event.detail = parseJsonValue(detail);
    assignDate(event, "occurredAt", value("occurredAt"));
    assignDate(event, "createdAt", value("createdAt"));
    return event;
  }

  private rowTenant(row: SqlRecord, table: keyof NormalizedColumns): string {
    if (this.columns[table].tenantId === null) return this.tenantId;
    return textValue(rowValue(row, "tenantId")) ?? this.tenantId;
  }

  private belongs(record: { tenantId?: string }): boolean {
    return record.tenantId === undefined || record.tenantId === this.tenantId;
  }

  private usersTable(): string {
    return this.quote(this.tables.users);
  }

  private rolesTable(): string {
    return this.quote(this.tables.roles);
  }

  private sessionsTable(): string {
    return this.quote(this.tables.sessions);
  }

  private auditTable(): string {
    return this.quote(this.tables.auditEvents);
  }

  private quote(value: string): string {
    return quoteControlPlaneSqlIdentifier(value);
  }
}

export { SqlControlPlaneRepository as PostgresControlPlaneRepository };
export { SqlControlPlaneRepository as PostgreSQLControlPlaneRepository };

function contextValue(value: unknown): string | undefined {
  return textValue(value);
}

function normalizeOptions(
  input: SqlRepositoryInput,
  secondOptions: SqlRepositorySecondOptions,
): ControlPlaneSqlRepositoryOptions {
  if (typeof input === "function") return { ...secondOptions, query: input };
  if (isExecutor(input) && !hasRepositoryOptionProperties(input)) return { ...secondOptions, executor: input };
  return { ...input, ...secondOptions };
}

function hasRepositoryOptionProperties(value: object): boolean {
  return [
    "tenantId",
    "tenantColumn",
    "tables",
    "tableNames",
    "usersTable",
    "userTable",
    "user",
    "rolesTable",
    "roleTable",
    "role",
    "sessionsTable",
    "sessionTable",
    "session",
    "auditEventsTable",
    "auditEventTable",
    "auditTable",
    "auditTableName",
    "auditEvent",
    "audit",
    "columns",
    "columnNames",
    "usersColumns",
    "rolesColumns",
    "sessionsColumns",
    "auditEventsColumns",
  ].some((key) => Object.prototype.hasOwnProperty.call(value, key));
}

function normalizeExecutor(options: ControlPlaneSqlRepositoryOptions): ControlPlaneSqlExecutor {
  if (options.executor && typeof options.executor.query === "function") return options.executor;
  if (typeof options.query === "function") return { query: options.query };
  throw new TypeError("A SQL query executor is required");
}

function normalizeTenantId(value: unknown): string {
  if (value === undefined) return CONTROL_PLANE_DEFAULT_TENANT_ID;
  if (typeof value !== "string") throw new TypeError("tenantId must be a string");
  const normalized = value.trim();
  if (normalized.length === 0 || normalized.length > 256 || /[\u0000-\u001f\u007f]/u.test(normalized)) {
    throw new TypeError("Invalid tenantId");
  }
  return normalized;
}

function normalizeTenantColumn(value: unknown): string | null {
  if (value === null) return null;
  if (typeof value !== "string") throw new TypeError("tenantColumn must be a string or null");
  return validateControlPlaneSqlIdentifier(value, "tenantColumn");
}

function normalizeTables(options: ControlPlaneSqlRepositoryOptions): NormalizedTables {
  const tables = {
    ...DEFAULT_TABLES,
    ...(options.tables ?? {}),
    ...(options.tableNames ?? {}),
    ...(options.usersTable === undefined ? {} : { users: options.usersTable }),
    ...(options.userTable === undefined ? {} : { users: options.userTable }),
    ...(options.user === undefined ? {} : { users: options.user }),
    ...(options.rolesTable === undefined ? {} : { roles: options.rolesTable }),
    ...(options.roleTable === undefined ? {} : { roles: options.roleTable }),
    ...(options.role === undefined ? {} : { roles: options.role }),
    ...(options.sessionsTable === undefined ? {} : { sessions: options.sessionsTable }),
    ...(options.sessionTable === undefined ? {} : { sessions: options.sessionTable }),
    ...(options.session === undefined ? {} : { sessions: options.session }),
    ...(options.auditEventsTable === undefined ? {} : { auditEvents: options.auditEventsTable }),
    ...(options.auditEventTable === undefined ? {} : { auditEvents: options.auditEventTable }),
    ...(options.auditTable === undefined ? {} : { auditEvents: options.auditTable }),
    ...(options.auditTableName === undefined ? {} : { auditEvents: options.auditTableName }),
    ...(options.auditEvent === undefined ? {} : { auditEvents: options.auditEvent }),
    ...(options.audit === undefined ? {} : { auditEvents: options.audit }),

  };
  return {
    users: validateControlPlaneSqlIdentifier(tables.users, "users table"),
    roles: validateControlPlaneSqlIdentifier(tables.roles, "roles table"),
    sessions: validateControlPlaneSqlIdentifier(tables.sessions, "sessions table"),
    auditEvents: validateControlPlaneSqlIdentifier(tables.auditEvents, "audit events table"),
  };
}

function normalizeColumns(options: ControlPlaneSqlRepositoryOptions): NormalizedColumns {
  const columns: NormalizedColumns = {
    users: mergeColumns(DEFAULT_COLUMNS.users, options.columns?.users, options.columnNames?.users, options.usersColumns),
    roles: mergeColumns(DEFAULT_COLUMNS.roles, options.columns?.roles, options.columnNames?.roles, options.rolesColumns),
    sessions: mergeColumns(DEFAULT_COLUMNS.sessions, options.columns?.sessions, options.columnNames?.sessions, options.sessionsColumns),
    auditEvents: mergeColumns(DEFAULT_COLUMNS.auditEvents, options.columns?.auditEvents, options.columnNames?.auditEvents, options.auditEventsColumns),
  };
  if (options.tenantColumn !== undefined) {
    const tenantColumn = normalizeTenantColumn(options.tenantColumn);
    columns.users.tenantId = tenantColumn;
    columns.roles.tenantId = tenantColumn;
    columns.sessions.tenantId = tenantColumn;
    columns.auditEvents.tenantId = tenantColumn;
  }
  return columns;
}

function mergeColumns<T extends object>(
  base: T,
  ...sources: Array<Partial<T> | undefined>
): T {
  const output: Record<string, string | null> = { ...base } as Record<string, string | null>;
  for (const source of sources) {
    if (!source) continue;
    for (const [key, value] of Object.entries(source)) {
      if (value === null) {
        output[key] = null;
      } else if (typeof value === "string") {
        output[key] = validateControlPlaneSqlIdentifier(value, `column ${key}`);
      }
    }
  }
  return output as T;
}

export function validateControlPlaneSqlIdentifier(value: unknown, field = "identifier"): string {
  if (typeof value !== "string") throw new TypeError(`${field} must be a string`);
  const normalized = value.trim();
  if (normalized !== value) throw new TypeError(`Invalid SQL identifier for ${field}`);
  const segments = normalized.split(".");
  if (
    segments.length < 1 ||
    segments.length > 2 ||
    segments.some((segment) => !/^[A-Za-z_][A-Za-z0-9_]*$/u.test(segment) || segment.length > 63)
  ) {
    throw new TypeError(`Invalid SQL identifier for ${field}`);
  }
  return segments.join(".");
}

export function quoteControlPlaneSqlIdentifier(value: unknown, field = "identifier"): string {
  const normalized = validateControlPlaneSqlIdentifier(value, field);
  return normalized.split(".").map((segment) => `"${segment}"`).join(".");
}

function isExecutor(value: unknown): value is ControlPlaneSqlExecutor {
  return isRecord(value) && typeof value.query === "function";
}

function resultRows(value: unknown): unknown[] | undefined {
  if (Array.isArray(value)) return value;
  if (!isRecord(value)) return undefined;
  return Array.isArray(value.rows) ? value.rows : undefined;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function requiredString(value: unknown, kind: string): string {
  if (typeof value !== "string" || value.trim().length === 0) throw new Error(`Invalid SQL ${kind} row`);
  return value;
}

function rowValue(row: SqlRecord, key: string): unknown {
  const snake = key.replace(/[A-Z]/gu, (letter) => `_${letter.toLowerCase()}`);
  for (const candidate of [key, snake]) {
    if (Object.prototype.hasOwnProperty.call(row, candidate)) return row[candidate];
  }
  return undefined;
}

function textValue(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  const normalized = value.trim();
  return normalized.length > 0 && !/[\u0000-\u001f\u007f]/u.test(normalized) ? normalized : undefined;
}

function assignText<T extends object>(target: T, key: string, value: unknown): void {
  const normalized = textValue(value);
  if (normalized !== undefined) (target as Record<string, unknown>)[key] = normalized;
}

function assignDate<T extends object>(target: T, key: string, value: unknown): void {
  if (value instanceof Date) {
    if (!Number.isNaN(value.getTime())) (target as Record<string, unknown>)[key] = new Date(value.getTime());
    return;
  }
  if (typeof value === "string" && value.length <= 128 && !Number.isNaN(new Date(value).getTime())) {
    (target as Record<string, unknown>)[key] = value;
  }
}

function roleValues(value: unknown): string[] {
  if (Array.isArray(value)) return value.filter((item): item is string => typeof item === "string" && item.trim().length > 0).map((item) => item.trim());
  if (typeof value !== "string") return [];
  const normalized = value.trim();
  if (normalized.startsWith("[")) {
    try {
      return roleValues(JSON.parse(normalized));
    } catch {
      return [normalized];
    }
  }
  return normalized.length > 0 ? [normalized] : [];
}

function booleanValue(value: unknown): boolean | undefined {
  if (typeof value === "boolean") return value;
  if (value === "true") return true;
  if (value === "false") return false;
  return undefined;
}

function parseJsonValue(value: unknown): unknown {
  if (typeof value !== "string") return value;
  try {
    return JSON.parse(value);
  } catch {
    return value;
  }
}

function safeJson(value: unknown): string {
  try {
    return JSON.stringify(value) ?? "null";
  } catch {
    return "null";
  }
}

function cursorOffset(
  kind: string,
  scope: string,
  cursor: string | undefined,
  offset: number | undefined,
): number {
  return cursor === undefined ? offset ?? 0 : decodeCursor(cursor, kind, scope);
}

function whereText(clauses: readonly string[]): string {
  return clauses.length === 0 ? "" : ` WHERE ${clauses.join(" AND ")}`;
}

function sqlQueryError(cause: unknown): Error {
  const error = new Error("Control-plane SQL query failed");
  Object.defineProperty(error, "cause", {
    configurable: true,
    enumerable: false,
    value: cause,
    writable: false,
  });
  return error;
}
