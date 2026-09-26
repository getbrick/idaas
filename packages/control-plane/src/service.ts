import {
  CONTROL_PLANE_DEFAULT_LIMIT,
  CONTROL_PLANE_MAX_LIMIT,
  CONTROL_PLANE_VERSION,
  type ControlPlaneActor,
  type ControlPlaneAuditEventDto,
  type ControlPlaneCapabilitiesDto,
  type ControlPlaneHealthDto,
  type ControlPlanePage,
  type ControlPlaneRepository,
  type ControlPlaneRevokeSessionsResult,
  type ControlPlaneRoleDto,
  type ControlPlaneServiceOptions,
  type ControlPlaneSessionDto,
  type ControlPlaneSystemInfoDto,
  type ControlPlaneUser,
  type ControlPlaneUserDto,
  type ControlPlaneWriteContext,
  type ControlPlaneWriteRequest,
} from "./types.js";
import {
  ControlPlaneError,
  conflict,
  forbidden,
  internalError,
  notFound,
  unauthenticated,
} from "./errors.js";
import {
  parseAuditEventQuery,
  parseIdentifier,
  parseRoleQuery,
  parseSessionQuery,
  parseUserQuery,
  parseWriteBody,
} from "./validation.js";
import {
  toAuditEventDto,
  toCapabilitiesDto,
  toLiveHealthDto,
  toReadyHealthDto,
  toRoleDto,
  toSessionDto,
  toSystemInfoDto,
  toUserDto,
} from "./dto.js";
import {
  controlPlaneUserHasRole,
  isActiveControlPlaneSession,
  normalizeControlPlaneStatus,
} from "./mutations.js";

export const CONTROL_PLANE_PERMISSIONS = {
  capabilities: "control-plane:read",
  users: "users:read",
  roles: "roles:read",
  sessions: "sessions:read",
  auditEvents: "audit:read",
  usersWrite: "users:write",
  sessionsWrite: "sessions:write",
} as const;

export const CONTROL_PLANE_PERMISSION = CONTROL_PLANE_PERMISSIONS;

export class ControlPlaneService {
  private readonly repository: ControlPlaneRepository;
  private readonly options: Required<Pick<ControlPlaneServiceOptions, "requireActor" | "adminRoles" | "ownerRoles" | "version" | "defaultLimit" | "maxLimit">>;
  private readonly readiness?: () => boolean | Promise<boolean>;

  constructor(
    repository: ControlPlaneRepository,
    options: ControlPlaneServiceOptions = {},
  ) {
    this.repository = repository;
    this.readiness = options.readiness;
    this.options = {
      requireActor: options.requireActor ?? true,
      adminRoles: options.adminRoles ?? ["admin"],
      ownerRoles: options.ownerRoles ?? ["owner"],
      version: options.version ?? CONTROL_PLANE_VERSION,
      defaultLimit: options.defaultLimit ?? CONTROL_PLANE_DEFAULT_LIMIT,
      maxLimit: options.maxLimit ?? CONTROL_PLANE_MAX_LIMIT,
    };
  }

  async getCapabilities(actor?: ControlPlaneActor): Promise<ControlPlaneCapabilitiesDto> {
    const normalizedActor = normalizeActor(actor);
    this.authorize(CONTROL_PLANE_PERMISSIONS.capabilities, normalizedActor);
    return toCapabilitiesDto(this.options.version);
  }

  async capabilities(actor?: ControlPlaneActor): Promise<ControlPlaneCapabilitiesDto> {
    return this.getCapabilities(actor);
  }

  async listUsers(
    queryOrActor: unknown = {},
    maybeActor?: ControlPlaneActor,
  ): Promise<ControlPlanePage<ControlPlaneUserDto>> {
    const invocation = resolveInvocation(queryOrActor, maybeActor);
    this.authorize(CONTROL_PLANE_PERMISSIONS.users, invocation.actor);
    const query = parseUserQuery(invocation.query, this.pageOptions());
    return this.execute(async () => {
      const result = await this.repository.listUsers(query);
      return mapPage(result, toUserDto);
    });
  }

  async getUsers(
    queryOrActor: unknown = {},
    maybeActor?: ControlPlaneActor,
  ): Promise<ControlPlanePage<ControlPlaneUserDto>> {
    return this.listUsers(queryOrActor, maybeActor);
  }

  async users(
    queryOrActor: unknown = {},
    maybeActor?: ControlPlaneActor,
  ): Promise<ControlPlanePage<ControlPlaneUserDto>> {
    return this.listUsers(queryOrActor, maybeActor);
  }

  async getUser(id: unknown, actor?: ControlPlaneActor): Promise<ControlPlaneUserDto> {
    const invocation = resolveIdentifierInvocation(id, actor);
    this.authorize(CONTROL_PLANE_PERMISSIONS.users, invocation.actor);
    const identifier = parseIdentifier(invocation.id);
    return this.execute(async () => {
      const result = await this.repository.getUser(identifier);
      if (result === undefined || result === null) throw notFound("User not found");
      return toUserDto(result);
    });
  }

  async listRoles(
    queryOrActor: unknown = {},
    maybeActor?: ControlPlaneActor,
  ): Promise<ControlPlanePage<ControlPlaneRoleDto>> {
    const invocation = resolveInvocation(queryOrActor, maybeActor);
    this.authorize(CONTROL_PLANE_PERMISSIONS.roles, invocation.actor);
    const query = parseRoleQuery(invocation.query, this.pageOptions());
    return this.execute(async () => {
      const result = await this.repository.listRoles(query);
      return mapPage(result, toRoleDto);
    });
  }

  async getRoles(
    queryOrActor: unknown = {},
    maybeActor?: ControlPlaneActor,
  ): Promise<ControlPlanePage<ControlPlaneRoleDto>> {
    return this.listRoles(queryOrActor, maybeActor);
  }

  async roles(
    queryOrActor: unknown = {},
    maybeActor?: ControlPlaneActor,
  ): Promise<ControlPlanePage<ControlPlaneRoleDto>> {
    return this.listRoles(queryOrActor, maybeActor);
  }

  async getRole(id: unknown, actor?: ControlPlaneActor): Promise<ControlPlaneRoleDto> {
    const invocation = resolveIdentifierInvocation(id, actor);
    this.authorize(CONTROL_PLANE_PERMISSIONS.roles, invocation.actor);
    const identifier = parseIdentifier(invocation.id);
    return this.execute(async () => {
      const result = await this.repository.getRole(identifier);
      if (result === undefined || result === null) throw notFound("Role not found");
      return toRoleDto(result);
    });
  }

  async listSessions(
    queryOrActor: unknown = {},
    maybeActor?: ControlPlaneActor,
  ): Promise<ControlPlanePage<ControlPlaneSessionDto>> {
    const invocation = resolveInvocation(queryOrActor, maybeActor);
    this.authorize(CONTROL_PLANE_PERMISSIONS.sessions, invocation.actor);
    const query = parseSessionQuery(invocation.query, this.pageOptions());
    return this.execute(async () => {
      const result = await this.repository.listSessions(query);
      return mapPage(result, toSessionDto);
    });
  }

  async getSessions(
    queryOrActor: unknown = {},
    maybeActor?: ControlPlaneActor,
  ): Promise<ControlPlanePage<ControlPlaneSessionDto>> {
    return this.listSessions(queryOrActor, maybeActor);
  }

  async listAuditEvents(
    queryOrActor: unknown = {},
    maybeActor?: ControlPlaneActor,
  ): Promise<ControlPlanePage<ControlPlaneAuditEventDto>> {
    const invocation = resolveInvocation(queryOrActor, maybeActor);
    this.authorize(CONTROL_PLANE_PERMISSIONS.auditEvents, invocation.actor);
    const query = parseAuditEventQuery(invocation.query, this.pageOptions());
    return this.execute(async () => {
      const result = await this.repository.listAuditEvents(query);
      return mapPage(result, toAuditEventDto);
    });
  }

  async getAuditEvents(
    queryOrActor: unknown = {},
    maybeActor?: ControlPlaneActor,
  ): Promise<ControlPlanePage<ControlPlaneAuditEventDto>> {
    return this.listAuditEvents(queryOrActor, maybeActor);
  }

  async auditEvents(
    queryOrActor: unknown = {},
    maybeActor?: ControlPlaneActor,
  ): Promise<ControlPlanePage<ControlPlaneAuditEventDto>> {
    return this.listAuditEvents(queryOrActor, maybeActor);
  }

  async getAuditEvent(id: unknown, actor?: ControlPlaneActor): Promise<ControlPlaneAuditEventDto> {
    const invocation = resolveIdentifierInvocation(id, actor);
    this.authorize(CONTROL_PLANE_PERMISSIONS.auditEvents, invocation.actor);
    const identifier = parseIdentifier(invocation.id);
    return this.execute(async () => {
      const result = await this.repository.getAuditEvent(identifier);
      if (result === undefined || result === null) throw notFound("Audit event not found");
      return toAuditEventDto(result);
    });
  }

  async disableUser(
    id: unknown,
    bodyOrActor: unknown = {},
    actorOrRequest?: unknown,
    request?: ControlPlaneWriteRequest,
  ): Promise<ControlPlaneUserDto> {
    return this.changeUserStatus("disabled", id, bodyOrActor, actorOrRequest, request);
  }

  async enableUser(
    id: unknown,
    bodyOrActor: unknown = {},
    actorOrRequest?: unknown,
    request?: ControlPlaneWriteRequest,
  ): Promise<ControlPlaneUserDto> {
    return this.changeUserStatus("active", id, bodyOrActor, actorOrRequest, request);
  }

  async revokeSession(
    id: unknown,
    bodyOrActor: unknown = {},
    actorOrRequest?: unknown,
    request?: ControlPlaneWriteRequest,
  ): Promise<ControlPlaneSessionDto> {
    const invocation = resolveWriteInvocation(bodyOrActor, actorOrRequest, request);
    this.authorize(CONTROL_PLANE_PERMISSIONS.sessionsWrite, invocation.actor);
    const identifier = parseIdentifier(id);
    parseWriteBody(invocation.body);
    const context = writeContext(invocation.actor, invocation.request);
    return this.execute(async () => {
      const session = await this.repository.getSession(identifier);
      if (session === undefined || session === null) throw notFound("Session not found");
      if (!isActiveControlPlaneSession(session)) throw conflict("Session is already revoked or inactive");
      const repository = this.repository;
      if (typeof repository.revokeSession !== "function") throw internalError();
      const result = await repository.revokeSession(identifier, context);
      const resolved = result ?? await this.repository.getSession(identifier);
      if (resolved === undefined || resolved === null) throw internalError();
      return toSessionDto(resolved);
    });
  }

  async deleteSession(
    id: unknown,
    bodyOrActor: unknown = {},
    actorOrRequest?: unknown,
    request?: ControlPlaneWriteRequest,
  ): Promise<ControlPlaneSessionDto> {
    return this.revokeSession(id, bodyOrActor, actorOrRequest, request);
  }

  async revokeUserSessions(
    userId: unknown,
    bodyOrActor: unknown = {},
    actorOrRequest?: unknown,
    request?: ControlPlaneWriteRequest,
  ): Promise<ControlPlaneRevokeSessionsResult> {
    const invocation = resolveWriteInvocation(bodyOrActor, actorOrRequest, request);
    this.authorize(CONTROL_PLANE_PERMISSIONS.sessionsWrite, invocation.actor);
    const identifier = parseIdentifier(userId);
    parseWriteBody(invocation.body);
    const context = writeContext(invocation.actor, invocation.request);
    return this.execute(async () => {
      const user = await this.repository.getUser(identifier);
      if (user === undefined || user === null) throw notFound("User not found");
      const page = await this.repository.listSessions({
        userId: identifier,
        active: true,
        limit: this.options.maxLimit,
        offset: 0,
      });
      if (page.total > page.items.length) throw conflict("Unable to verify active sessions");
      if (page.items.length === 0) throw conflict("User has no active sessions");
      const repository = this.repository;
      if (typeof repository.revokeUserSessions !== "function") throw internalError();
      const result = await repository.revokeUserSessions(identifier, context);
      return normalizeRevokeResult(result, identifier, page.items.map((item) => item.id));
    });
  }

  async revokeSessionsForUser(
    userId: unknown,
    bodyOrActor: unknown = {},
    actorOrRequest?: unknown,
    request?: ControlPlaneWriteRequest,
  ): Promise<ControlPlaneRevokeSessionsResult> {
    return this.revokeUserSessions(userId, bodyOrActor, actorOrRequest, request);
  }

  private async changeUserStatus(
    status: "active" | "disabled",
    id: unknown,
    bodyOrActor: unknown,
    actorOrRequest?: unknown,
    request?: ControlPlaneWriteRequest,
  ): Promise<ControlPlaneUserDto> {
    const invocation = resolveWriteInvocation(bodyOrActor, actorOrRequest, request);
    this.authorize(CONTROL_PLANE_PERMISSIONS.usersWrite, invocation.actor);
    const identifier = parseIdentifier(id);
    parseWriteBody(invocation.body);
    const context = writeContext(invocation.actor, invocation.request);
    return this.execute(async () => {
      const user = await this.repository.getUser(identifier);
      if (user === undefined || user === null) throw notFound("User not found");
      const currentStatus = normalizeControlPlaneStatus(user.status);
      if (status === "disabled" && currentStatus !== "active") {
        throw conflict("User is already disabled or cannot be disabled");
      }
      if (status === "active" && currentStatus !== "disabled") {
        throw conflict("User is already enabled or cannot be enabled");
      }
      if (status === "disabled") await this.assertNotLastPrivileged(user);
      const repository = this.repository;
      let result: unknown;
      if (status === "disabled" && typeof repository.disableUser === "function") {
        result = await repository.disableUser(identifier, context);
      } else if (status === "active" && typeof repository.enableUser === "function") {
        result = await repository.enableUser(identifier, context);
      } else if (typeof repository.setUserStatus === "function") {
        result = await repository.setUserStatus(identifier, status, context);
      } else {
        throw internalError();
      }
      const resolved = unwrapUserResult(result) ?? await this.repository.getUser(identifier);
      if (resolved === undefined || resolved === null) throw internalError();
      return toUserDto(resolved);
    });
  }

  private async assertNotLastPrivileged(user: ControlPlaneUser): Promise<void> {
    const roles = new Set<string>();
    for (const role of this.options.adminRoles) {
      const normalized = role.trim().toLowerCase();
      if (normalized.length > 0) roles.add(normalized);
    }
    for (const role of this.options.ownerRoles) {
      const normalized = role.trim().toLowerCase();
      if (normalized.length > 0) roles.add(normalized);
    }
    for (const role of roles) {
      if (!controlPlaneUserHasRole(user, role)) continue;
      const checker = this.repository.hasOtherActiveUserWithRole;
      if (typeof checker === "function") {
        if (!(await checker.call(this.repository, user.id, role))) throw conflict(`Cannot disable the last ${role}`);
        continue;
      }
      const page = await this.repository.listUsers({
        status: "active",
        limit: this.options.maxLimit,
        offset: 0,
      });
      if (page.total > page.items.length) throw conflict("Unable to verify privileged users");
      if (!page.items.some((item) => item.id !== user.id && controlPlaneUserHasRole(item, role))) {
        throw conflict(`Cannot disable the last ${role}`);
      }
    }
  }

  async getSystemInfo(
    actor?: ControlPlaneActor,
    requestId?: string,
  ): Promise<ControlPlaneSystemInfoDto> {
    this.authorize(CONTROL_PLANE_PERMISSIONS.capabilities, actor);
    return toSystemInfoDto(this.options.version, requestId);
  }

  async systemInfo(
    actor?: ControlPlaneActor,
    requestId?: string,
  ): Promise<ControlPlaneSystemInfoDto> {
    return this.getSystemInfo(actor, requestId);
  }

  async healthLive(): Promise<ControlPlaneHealthDto> {
    return toLiveHealthDto(this.options.version);
  }

  async live(): Promise<ControlPlaneHealthDto> {
    return this.healthLive();
  }

  async healthReady(): Promise<ControlPlaneHealthDto> {
    const repository = this.repository as ControlPlaneRepository & { isReady?: () => boolean | Promise<boolean> };
    if (typeof repository.isReady === "function") {
      try {
        if (!(await repository.isReady())) {
          throw new ControlPlaneError("SERVICE_UNAVAILABLE", "Service unavailable", { statusCode: 503 });
        }
      } catch (error) {
        if (error instanceof ControlPlaneError) throw error;
        throw new ControlPlaneError("SERVICE_UNAVAILABLE", "Service unavailable", { statusCode: 503 });
      }
    }
    if (this.readiness) {
      try {
        if (!(await this.readiness())) {
          throw new ControlPlaneError("SERVICE_UNAVAILABLE", "Service unavailable", { statusCode: 503 });
        }
      } catch (error) {
        if (error instanceof ControlPlaneError) throw error;
        throw new ControlPlaneError("SERVICE_UNAVAILABLE", "Service unavailable", { statusCode: 503 });
      }
    }
    return toReadyHealthDto(this.options.version);
  }

  async ready(): Promise<ControlPlaneHealthDto> {
    return this.healthReady();
  }

  private pageOptions(): { defaultLimit: number; maxLimit: number } {
    return { defaultLimit: this.options.defaultLimit, maxLimit: this.options.maxLimit };
  }

  private authorize(permission: string, actor: ControlPlaneActor | undefined): void {
    this.authenticate(actor);
    if (!this.options.requireActor) return;
    const permissions = Array.isArray(actor?.permissions)
      ? actor.permissions.filter((value): value is string => typeof value === "string")
      : [];
    if (permissions.some((granted) => permissionSatisfies(granted, permission))) return;
    const actorRoles = actor?.roles;
    const roles = Array.isArray(actorRoles)
      ? actorRoles.filter((value): value is string => typeof value === "string")
      : actor?.user ? rolesFromUser(actor.user) : [];
    if (roles.some((role) => this.options.adminRoles.some((adminRole) => adminRole.trim().toLowerCase() === role.trim().toLowerCase()))) return;
    throw forbidden();
  }

  private authenticate(actor: ControlPlaneActor | undefined): void {
    if (this.options.requireActor && (!actor || !isRecord(actor.user))) throw unauthenticated();
  }

  private async execute<T>(operation: () => Promise<T>): Promise<T> {
    try {
      return await operation();
    } catch (error) {
      if (error instanceof ControlPlaneError) throw error;
      throw internalError();
    }
  }
}

function mapPage<T>(
  page: ControlPlanePage<unknown>,
  mapper: (value: unknown) => T,
): ControlPlanePage<T> {
  if (!isRecord(page) || !Array.isArray(page.items)) throw internalError();
  const items = page.items.map((item) => mapper(item));
  const output: ControlPlanePage<T> = {
    items,
    hasMore: page.hasMore === true,
    total: isFiniteNumber(page.total) && page.total >= 0 ? Math.floor(page.total) : items.length,
  };
  if (isSafeCursor(page.nextCursor)) output.nextCursor = page.nextCursor;
  return output;
}

function resolveInvocation(
  queryOrActor: unknown,
  maybeActor?: ControlPlaneActor,
): { query: unknown; actor?: ControlPlaneActor } {
  if (maybeActor !== undefined) return { query: queryOrActor, actor: normalizeActor(maybeActor) };
  if (isActorLike(queryOrActor)) return { query: {}, actor: normalizeActor(queryOrActor) };
  return { query: queryOrActor, actor: undefined };
}

function resolveIdentifierInvocation(
  idOrActor: unknown,
  actor?: ControlPlaneActor,
): { id: unknown; actor?: ControlPlaneActor } {
  if (actor === undefined && isActorLike(idOrActor)) {
    return { id: undefined, actor: normalizeActor(idOrActor) };
  }
  return { id: idOrActor, actor: normalizeActor(actor) };
}

function resolveWriteInvocation(
  bodyOrActor: unknown,
  actorOrRequest?: unknown,
  request?: ControlPlaneWriteRequest,
): { body: unknown; actor?: ControlPlaneActor; request?: ControlPlaneWriteRequest } {
  if (isActorLike(bodyOrActor)) {
    return {
      body: {},
      actor: normalizeActor(bodyOrActor),
      request: isWriteRequest(actorOrRequest)
        ? actorOrRequest
        : typeof actorOrRequest === "string"
          ? { requestId: actorOrRequest }
          : request,
    };
  }
  return {
    body: bodyOrActor,
    actor: isActorLike(actorOrRequest) ? normalizeActor(actorOrRequest) : undefined,
    request: isWriteRequest(actorOrRequest)
      ? actorOrRequest
      : typeof actorOrRequest === "string"
        ? { requestId: actorOrRequest }
        : request,
  };
}

function isWriteRequest(value: unknown): value is ControlPlaneWriteRequest {
  return isRecord(value) && (
    "requestId" in value ||
    "ipAddress" in value ||
    "userAgent" in value
  );
}

function writeContext(
  actor: ControlPlaneActor | undefined,
  request: ControlPlaneWriteRequest | undefined,
): ControlPlaneWriteContext {
  const userId = actor?.user?.id;
  return {
    actorId: safeContextValue(userId),
    requestId: safeContextValue(request?.requestId),
    ipAddress: safeContextValue(request?.ipAddress),
    userAgent: safeContextValue(request?.userAgent),
  };
}

function safeContextValue(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  const normalized = value.trim();
  if (normalized.length === 0 || normalized.length > 512 || /[\u0000-\u001f\u007f]/u.test(normalized) || /(?:secret|token|password|private[-_]?key|credential|authorization|cookie|vault:\/\/)/iu.test(normalized)) return undefined;
  return normalized;
}

function unwrapUserResult(value: unknown): unknown {
  if (!isRecord(value)) return value;
  return isRecord(value.user) ? value.user : value;
}

function normalizeRevokeResult(
  value: unknown,
  userId: string,
  fallbackSessionIds: string[],
): ControlPlaneRevokeSessionsResult {
  if (!isRecord(value) || value.userId !== userId) throw internalError();
  const sessionIds = Array.isArray(value.sessionIds)
    ? value.sessionIds.filter((item): item is string => typeof item === "string" && item.length > 0)
    : [...fallbackSessionIds];
  const revokedCount = typeof value.revokedCount === "number" && Number.isSafeInteger(value.revokedCount) && value.revokedCount >= 0
    ? value.revokedCount
    : sessionIds.length;
  if (revokedCount !== sessionIds.length) throw internalError();
  return { userId, revokedCount, sessionIds };
}

function normalizeActor(value: unknown): ControlPlaneActor | undefined {
  if (!isRecord(value)) return undefined;
  if (isRecord(value.user) || value.user === undefined) {
    const user = isRecord(value.user) ? value.user : undefined;
    const roles = roleValues(value.roles);
    return {
      user,
      permissions: stringArray(value.permissions),
      roles: roles.length > 0 ? roles : user === undefined ? [] : rolesFromUser(user),
    };
  }
  return { user: value, permissions: [], roles: rolesFromUser(value) };
}

function isActorLike(value: unknown): boolean {
  if (!isRecord(value)) return false;
  return isRecord(value.user) || Array.isArray(value.permissions) || Array.isArray(value.roles);
}

function rolesFromUser(user: Record<string, unknown>): string[] {
  const roles = [...roleValues(user.roles), ...roleValues(user.role)];
  return roles.filter((role, index, values) => values.indexOf(role) === index);
}

function roleValues(value: unknown): string[] {
  const values = typeof value === "string" ? [value] : stringArray(value);
  return values
    .map((role) => role.trim())
    .filter((role) => role.length > 0);
}

function stringArray(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value.filter((item): item is string => typeof item === "string" && item.length > 0);
}

function permissionSatisfies(granted: string, required: string): boolean {
  const grantedParts = granted.split(":");
  const requiredParts = required.split(":");
  if (grantedParts.length < 2 || grantedParts.length > 3 || requiredParts.length < 2 || requiredParts.length > 3) {
    return false;
  }
  if (!segmentMatches(grantedParts[0], requiredParts[0]) || !segmentMatches(grantedParts[1], requiredParts[1])) {
    return false;
  }
  const requiredScope = requiredParts[2];
  if (requiredScope === undefined) return true;
  const grantedScope = grantedParts[2] ?? "all";
  return grantedScope === "*" || grantedScope === "all" || grantedScope === requiredScope;
}

function segmentMatches(granted: string, required: string): boolean {
  return granted === "*" || required === "*" || granted === required;
}

function isSafeCursor(value: unknown): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= 1024 && !/[\u0000-\u001f\u007f]/u.test(value);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isFiniteNumber(value: unknown): value is number {
  return typeof value === "number" && Number.isFinite(value);
}
