import {
  CONTROL_PLANE_DEFAULT_TENANT_ID,
  type ControlPlaneAuditEvent,
  type ControlPlaneAuditEventQuery,
  type ControlPlanePage,
  type ControlPlaneRepository,
  type ControlPlaneRepositoryOptions,
  type ControlPlaneRole,
  type ControlPlaneRoleQuery,
  type ControlPlaneSession,
  type ControlPlaneSessionQuery,
  type ControlPlaneUser,
  type ControlPlaneUserQuery,
  type ControlPlaneWriteContext,
  type ControlPlaneRevokeSessionsResult,
} from "./types.js";
import { conflict, invalidRequest, notFound } from "./errors.js";
import { parseIdentifier, parsePageQuery } from "./validation.js";
import {
  controlPlaneUserHasRole,
  controlPlaneUserRoles,
  isActiveControlPlaneSession,
  isActiveControlPlaneUser,
  normalizeControlPlaneStatus,
} from "./mutations.js";

interface CursorPayload {
  version: 1;
  kind: string;
  offset: number;
  scope: string;
}

type AnyRecord = Record<string, unknown>;

export class InMemoryControlPlaneRepository implements ControlPlaneRepository {
  readonly tenantId: string;
  private readonly users = new Map<string, ControlPlaneUser>();
  private readonly roles = new Map<string, ControlPlaneRole>();
  private readonly sessions = new Map<string, ControlPlaneSession>();
  private readonly auditEvents = new Map<string, ControlPlaneAuditEvent>();
  private auditSequence = 0;

  constructor(options: ControlPlaneRepositoryOptions | readonly ControlPlaneUser[] = {}) {
    const normalized: ControlPlaneRepositoryOptions = Array.isArray(options)
      ? { users: options as readonly ControlPlaneUser[] }
      : options as ControlPlaneRepositoryOptions;
    this.tenantId = normalized.tenantId ?? CONTROL_PLANE_DEFAULT_TENANT_ID;
    this.seedUsers(normalized.users ?? []);
    this.seedRoles(normalized.roles ?? []);
    this.seedSessions(normalized.sessions ?? []);
    this.seedAuditEvents(normalized.auditEvents ?? []);
  }

  async listUsers(query: ControlPlaneUserQuery = {}): Promise<ControlPlanePage<ControlPlaneUser>> {
    return this.listUsersSync(query);
  }

  listUsersSync(query: ControlPlaneUserQuery = {}): ControlPlanePage<ControlPlaneUser> {
    const page = parsePageQuery(query);
    const filtered = [...this.users.values()].filter((user) => {
      if (!this.belongs(user, query.tenantId)) return false;
      if (query.id !== undefined && !equalsText(user.id, query.id)) return false;
      if (query.email !== undefined && !equalsText(user.email, query.email)) return false;
      if (query.status !== undefined && !equalsText(user.status ?? "active", query.status)) return false;
      if (query.role !== undefined && !hasRole(user, query.role)) return false;
      const search = query.search ?? query.q;
      if (search !== undefined && !matchesUserSearch(user, search)) return false;
      return true;
    });
    return this.paginate("users", page, filtered, userScope(query));
  }

  async getUser(id: string): Promise<ControlPlaneUser | undefined> {
    return this.getUserSync(id);
  }

  getUserSync(id: string): ControlPlaneUser | undefined {
    const user = this.users.get(id);
    if (!user || !this.belongs(user)) return undefined;
    return cloneRecord(user);
  }

  async listRoles(query: ControlPlaneRoleQuery = {}): Promise<ControlPlanePage<ControlPlaneRole>> {
    return this.listRolesSync(query);
  }

  listRolesSync(query: ControlPlaneRoleQuery = {}): ControlPlanePage<ControlPlaneRole> {
    const page = parsePageQuery(query);
    const filtered = [...this.roles.values()].filter((role) => {
      if (!this.belongs(role, query.tenantId)) return false;
      if (query.code !== undefined && !equalsText(role.code ?? role.id, query.code)) return false;
      if (query.permission !== undefined && !stringArray(role.permissions).includes(query.permission)) return false;
      const search = query.search ?? query.q;
      if (search !== undefined && !matchesRoleSearch(role, search)) return false;
      return true;
    });
    return this.paginate("roles", page, filtered, roleScope(query));
  }

  async getRole(id: string): Promise<ControlPlaneRole | undefined> {
    return this.getRoleSync(id);
  }

  getRoleSync(id: string): ControlPlaneRole | undefined {
    const role = this.roles.get(id) ?? [...this.roles.values()].find((item) => item.code === id);
    if (!role || !this.belongs(role)) return undefined;
    return cloneRecord(role);
  }

  async listSessions(query: ControlPlaneSessionQuery = {}): Promise<ControlPlanePage<ControlPlaneSession>> {
    return this.listSessionsSync(query);
  }

  listSessionsSync(query: ControlPlaneSessionQuery = {}): ControlPlanePage<ControlPlaneSession> {
    const page = parsePageQuery(query);
    const filtered = [...this.sessions.values()].filter((session) => {
      if (!this.belongs(session, query.tenantId)) return false;
      if (query.userId !== undefined && !equalsText(session.userId, query.userId)) return false;
      if (query.status !== undefined && !equalsText(session.status, query.status)) return false;
      if (query.active !== undefined) {
        const active = isActiveControlPlaneSession(session);
        if (active !== query.active) return false;
      }
      if (!inDateRange(session.lastActiveAt ?? session.createdAt, query.from, query.to)) return false;
      return true;
    });
    return this.paginate("sessions", page, filtered, sessionScope(query));
  }

  async getSession(id: string): Promise<ControlPlaneSession | undefined> {
    return this.getSessionSync(id);
  }

  getSessionSync(id: string): ControlPlaneSession | undefined {
    const session = this.sessions.get(id);
    if (!session || !this.belongs(session)) return undefined;
    return cloneRecord(session);
  }

  async listAuditEvents(
    query: ControlPlaneAuditEventQuery = {},
  ): Promise<ControlPlanePage<ControlPlaneAuditEvent>> {
    return this.listAuditEventsSync(query);
  }

  listAuditEventsSync(
    query: ControlPlaneAuditEventQuery = {},
  ): ControlPlanePage<ControlPlaneAuditEvent> {
    const page = parsePageQuery(query);
    const filtered = [...this.auditEvents.values()].filter((event) => {
      if (!this.belongs(event, query.tenantId)) return false;
      if (query.event !== undefined && !equalsText(event.event, query.event)) return false;
      if (query.action !== undefined && !equalsText(event.action, query.action)) return false;
      if (query.userId !== undefined && !equalsText(event.userId, query.userId)) return false;
      if (query.actorId !== undefined && !equalsText(event.actorId ?? event.userId, query.actorId)) return false;
      if (query.targetId !== undefined && !equalsText(event.targetId, query.targetId)) return false;
      if (query.outcome !== undefined && !equalsText(event.outcome, query.outcome)) return false;
      const search = query.search ?? query.q;
      if (search !== undefined && !matchesAuditSearch(event, search)) return false;
      if (!inDateRange(event.occurredAt ?? event.createdAt, query.from, query.to)) return false;
      return true;
    });
    return this.paginate("audit-events", page, filtered, auditScope(query));
  }

  async getAuditEvent(id: string): Promise<ControlPlaneAuditEvent | undefined> {
    return this.getAuditEventSync(id);
  }

  getAuditEventSync(id: string): ControlPlaneAuditEvent | undefined {
    const event = this.auditEvents.get(id);
    if (!event || !this.belongs(event)) return undefined;
    return cloneRecord(event);
  }

  hasOtherActiveUserWithRole(id: string, role: string): boolean {
    const target = this.users.get(id);
    if (!target || !this.belongs(target)) return false;
    return [...this.users.values()].some(
      (user) => user.id !== id && this.belongs(user) && isActiveControlPlaneUser(user) && controlPlaneUserHasRole(user, role),
    );
  }

  async setUserStatus(
    id: string,
    status: "active" | "disabled",
    context: ControlPlaneWriteContext = {},
  ): Promise<ControlPlaneUser> {
    const identifier = parseIdentifier(id);
    const user = this.users.get(identifier);
    if (!user || !this.belongs(user)) throw notFound("User not found");
    const currentStatus = normalizeControlPlaneStatus(user.status);
    if (status === "disabled" && currentStatus !== "active") {
      throw conflict("User is already disabled or cannot be disabled");
    }
    if (status === "active" && currentStatus !== "disabled") {
      throw conflict("User is already enabled or cannot be enabled");
    }
    if (status === "disabled") this.assertNotLastPrivileged(user);
    const previous = cloneRecord(user);
    const previousAudit = new Map(this.auditEvents);
    const previousSequence = this.auditSequence;
    const updated = cloneRecord(user);
    updated.status = status;
    updated.updatedAt = new Date();
    this.users.set(identifier, updated);
    try {
      await this.addAuditEvent(this.auditEventForUserMutation(user, status, context));
    } catch (error) {
      this.users.set(identifier, previous);
      this.auditEvents.clear();
      for (const [eventId, event] of previousAudit) this.auditEvents.set(eventId, event);
      this.auditSequence = previousSequence;
      throw error;
    }
    return cloneRecord(updated);
  }

  async disableUser(id: string, context: ControlPlaneWriteContext = {}): Promise<ControlPlaneUser> {
    return this.setUserStatus(id, "disabled", context);
  }

  async enableUser(id: string, context: ControlPlaneWriteContext = {}): Promise<ControlPlaneUser> {
    return this.setUserStatus(id, "active", context);
  }

  async revokeSession(id: string, context: ControlPlaneWriteContext = {}): Promise<ControlPlaneSession> {
    const identifier = parseIdentifier(id);
    const session = this.sessions.get(identifier);
    if (!session || !this.belongs(session)) throw notFound("Session not found");
    if (!isActiveControlPlaneSession(session)) throw conflict("Session is already revoked or inactive");
    const previous = cloneRecord(session);
    const previousAudit = new Map(this.auditEvents);
    const previousSequence = this.auditSequence;
    const updated = cloneRecord(session);
    updated.status = "revoked";
    updated.revokedAt = new Date();
    this.sessions.set(identifier, updated);
    try {
      await this.addAuditEvent(this.auditEventForSessionMutation(session, context));
    } catch (error) {
      this.sessions.set(identifier, previous);
      this.auditEvents.clear();
      for (const [eventId, event] of previousAudit) this.auditEvents.set(eventId, event);
      this.auditSequence = previousSequence;
      throw error;
    }
    return cloneRecord(updated);
  }

  async revokeUserSessions(
    userId: string,
    context: ControlPlaneWriteContext = {},
  ): Promise<ControlPlaneRevokeSessionsResult> {
    const identifier = parseIdentifier(userId);
    const user = this.users.get(identifier);
    if (!user || !this.belongs(user)) throw notFound("User not found");
    const sessions = [...this.sessions.values()].filter(
      (session) => this.belongs(session) && session.userId === identifier && isActiveControlPlaneSession(session),
    );
    if (sessions.length === 0) throw conflict("User has no active sessions");
    const previousSessions = sessions.map((session) => [session.id, cloneRecord(session)] as const);
    const previousAudit = new Map(this.auditEvents);
    const previousSequence = this.auditSequence;
    const revokedAt = new Date();
    const revokedIds: string[] = [];
    for (const session of sessions) {
      const updated = cloneRecord(session);
      updated.status = "revoked";
      updated.revokedAt = revokedAt;
      this.sessions.set(session.id, updated);
      revokedIds.push(session.id);
    }
    try {
      await this.addAuditEvent(this.auditEventForUserSessionsMutation(user, revokedIds, context));
    } catch (error) {
      for (const [sessionId, session] of previousSessions) this.sessions.set(sessionId, session);
      this.auditEvents.clear();
      for (const [eventId, event] of previousAudit) this.auditEvents.set(eventId, event);
      this.auditSequence = previousSequence;
      throw error;
    }
    return { userId: identifier, revokedCount: revokedIds.length, sessionIds: revokedIds };
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

  private assertNotLastPrivileged(user: ControlPlaneUser): void {
    for (const role of controlPlaneUserRoles(user)) {
      const normalized = role.toLowerCase();
      if (normalized !== "admin" && normalized !== "administrator" && normalized !== "owner") continue;
      if (!this.hasOtherActiveUserWithRole(user.id, normalized)) {
        throw conflict(`Cannot disable the last ${normalized}`);
      }
    }
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
      organizationId: contextValue((user as Record<string, unknown>).organizationId),
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
      organizationId: contextValue((user as Record<string, unknown>).organizationId),
      requestId: contextValue(context.requestId),
      ipAddress: contextValue(context.ipAddress),
      userAgent: contextValue(context.userAgent),
      outcome: "success",
      detail: { revokedCount: sessionIds.length, sessionIds },
      occurredAt: new Date(),
      createdAt: new Date(),
    };
  }

  seedUsers(users: readonly ControlPlaneUser[]): void {
    for (const user of users) {
      if (typeof user.id !== "string" || user.id.length === 0) continue;
      this.users.set(user.id, cloneRecord(user));
    }
  }

  seedRoles(roles: readonly ControlPlaneRole[]): void {
    for (const role of roles) {
      if (typeof role.id !== "string" || role.id.length === 0) continue;
      this.roles.set(role.id, cloneRecord(role));
    }
  }

  seedSessions(sessions: readonly ControlPlaneSession[]): void {
    for (const session of sessions) {
      if (typeof session.id !== "string" || session.id.length === 0) continue;
      this.sessions.set(session.id, cloneRecord(session));
    }
  }

  seedAuditEvents(events: readonly ControlPlaneAuditEvent[]): void {
    for (const event of events) {
      const id = this.auditId(event);
      this.auditEvents.set(id, cloneRecord({ ...event, id }));
    }
  }

  addUser(user: ControlPlaneUser): ControlPlaneUser {
    if (typeof user.id !== "string" || user.id.length === 0) throw invalidRequest("Invalid user");
    this.users.set(user.id, cloneRecord(user));
    return cloneRecord(user);
  }

  addRole(role: ControlPlaneRole): ControlPlaneRole {
    if (typeof role.id !== "string" || role.id.length === 0) throw invalidRequest("Invalid role");
    this.roles.set(role.id, cloneRecord(role));
    return cloneRecord(role);
  }

  addSession(session: ControlPlaneSession): ControlPlaneSession {
    if (typeof session.id !== "string" || session.id.length === 0) throw invalidRequest("Invalid session");
    this.sessions.set(session.id, cloneRecord(session));
    return cloneRecord(session);
  }

  addAuditEvent(event: ControlPlaneAuditEvent): ControlPlaneAuditEvent {
    const id = this.auditId(event);
    const stored = cloneRecord({ ...event, id });
    this.auditEvents.set(id, stored);
    return cloneRecord(stored);
  }

  appendAuditEvent(event: ControlPlaneAuditEvent): ControlPlaneAuditEvent {
    return this.addAuditEvent(event);
  }

  isReady(): boolean {
    return true;
  }

  clear(): void {
    this.users.clear();
    this.roles.clear();
    this.sessions.clear();
    this.auditEvents.clear();
  }

  snapshot(): {
    users: ControlPlaneUser[];
    roles: ControlPlaneRole[];
    sessions: ControlPlaneSession[];
    auditEvents: ControlPlaneAuditEvent[];
  } {
    return {
      users: [...this.users.values()].map((item) => cloneRecord(item)),
      roles: [...this.roles.values()].map((item) => cloneRecord(item)),
      sessions: [...this.sessions.values()].map((item) => cloneRecord(item)),
      auditEvents: [...this.auditEvents.values()].map((item) => cloneRecord(item)),
    };
  }

  private auditId(event: ControlPlaneAuditEvent): string {
    if (typeof event.id === "string" && event.id.length > 0) return event.id;
    let id: string;
    do {
      this.auditSequence += 1;
      id = `audit-${this.auditSequence}`;
    } while (this.auditEvents.has(id));
    return id;
  }

  private belongs(record: { tenantId?: string }, requestedTenant?: string): boolean {
    if (requestedTenant !== undefined && requestedTenant !== this.tenantId) return false;
    return record.tenantId === undefined || record.tenantId === this.tenantId;
  }

  private paginate<T>(
    kind: string,
    query: ReturnType<typeof parsePageQuery>,
    records: T[],
    scope: string,
  ): ControlPlanePage<T> {
    const offset = query.cursor === undefined
      ? query.offset ?? 0
      : decodeCursor(query.cursor, kind, scope);
    const items = records.slice(offset, offset + query.limit).map((item) => cloneValue(item) as T);
    const nextOffset = offset + items.length;
    const hasMore = nextOffset < records.length;
    const page: ControlPlanePage<T> = {
      items,
      hasMore,
      total: records.length,
    };
    if (hasMore) page.nextCursor = encodeCursor({ version: 1, kind, offset: nextOffset, scope });
    return page;
  }
}

export function encodeCursor(payload: CursorPayload): string {
  return Buffer.from(JSON.stringify(payload), "utf8").toString("base64url");
}

export function decodeCursor(cursor: string, kind: string, scope: string): number {
  try {
    const parsed = JSON.parse(Buffer.from(cursor, "base64url").toString("utf8")) as Partial<CursorPayload>;
    if (
      parsed.version !== 1 ||
      parsed.kind !== kind ||
      parsed.scope !== scope ||
      !Number.isSafeInteger(parsed.offset) ||
      (parsed.offset ?? -1) < 0
    ) {
      throw new Error("invalid cursor");
    }
    return parsed.offset as number;
  } catch {
    throw invalidRequest("Invalid pagination cursor", { field: "cursor" });
  }
}

function contextValue(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  const normalized = value.trim();
  if (normalized.length === 0 || normalized.length > 512 || /[\u0000-\u001f\u007f]/u.test(normalized)) return undefined;
  return normalized;
}

export function userScope(query: ControlPlaneUserQuery): string {
  return JSON.stringify([query.id ?? "", query.email ?? "", query.status ?? "", query.role ?? "", query.search ?? query.q ?? ""]);
}

export function roleScope(query: ControlPlaneRoleQuery): string {
  return JSON.stringify([query.code ?? "", query.permission ?? "", query.search ?? query.q ?? ""]);
}

export function sessionScope(query: ControlPlaneSessionQuery): string {
  return JSON.stringify([query.userId ?? "", query.status ?? "", query.active ?? "", query.from ?? "", query.to ?? ""]);
}

export function auditScope(query: ControlPlaneAuditEventQuery): string {
  return JSON.stringify([
    query.event ?? "",
    query.action ?? "",
    query.userId ?? "",
    query.actorId ?? "",
    query.targetId ?? "",
    query.outcome ?? "",
    query.search ?? query.q ?? "",
    query.from ?? "",
    query.to ?? "",
  ]);
}

function matchesUserSearch(user: ControlPlaneUser, value: string): boolean {
  const normalized = value.toLowerCase();
  return [user.id, user.username, user.displayName, user.name, user.email, user.role]
    .some((item) => textValue(item)?.toLowerCase().includes(normalized) === true);
}

function matchesRoleSearch(role: ControlPlaneRole, value: string): boolean {
  const normalized = value.toLowerCase();
  return [role.id, role.code, role.name, role.description]
    .some((item) => textValue(item)?.toLowerCase().includes(normalized) === true);
}

function matchesAuditSearch(event: ControlPlaneAuditEvent, value: string): boolean {
  const normalized = value.toLowerCase();
  return [event.id, event.event, event.action, event.userId, event.actorId, event.targetId, event.outcome]
    .some((item) => textValue(item)?.toLowerCase().includes(normalized) === true);
}

function hasRole(user: ControlPlaneUser, role: string): boolean {
  if (equalsText(user.role, role)) return true;
  return stringArray(user.roles).some((item) => equalsText(item, role));
}

function inDateRange(value: unknown, from: string | undefined, to: string | undefined): boolean {
  if (from === undefined && to === undefined) return true;
  if (value === undefined || value === null) return false;
  const date = new Date(value as string | number | Date);
  if (Number.isNaN(date.getTime())) return false;
  const timestamp = date.getTime();
  const start = from === undefined ? undefined : new Date(from).getTime();
  const end = to === undefined ? undefined : new Date(to).getTime();
  return (start === undefined || timestamp >= start) && (end === undefined || timestamp <= end);
}

function equalsText(left: unknown, right: string): boolean {
  const value = textValue(left);
  return value !== undefined && value.toLowerCase() === right.toLowerCase();
}

function textValue(value: unknown): string | undefined {
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

function stringArray(value: unknown): string[] {
  if (typeof value === "string") return [value];
  if (!Array.isArray(value)) return [];
  return value.filter((item): item is string => typeof item === "string" && item.length > 0);
}

function cloneRecord<T extends AnyRecord>(value: T): T {
  return cloneValue(value) as T;
}

function cloneValue(value: unknown, ancestors: Set<object> = new Set()): unknown {
  if (value === null || typeof value !== "object") return value;
  if (value instanceof Date) return new Date(value.getTime());
  if (ancestors.has(value)) return undefined;
  ancestors.add(value);
  try {
    if (Array.isArray(value)) {
      return value.map((item) => cloneValue(item, ancestors)).filter((item) => item !== undefined);
    }
    const output: AnyRecord = {};
    for (const key of Object.keys(value)) {
      if (key === "__proto__" || key === "prototype" || key === "constructor") continue;
      const item = cloneValue((value as AnyRecord)[key], ancestors);
      if (item !== undefined) output[key] = item;
    }
    return output;
  } finally {
    ancestors.delete(value);
  }
}
