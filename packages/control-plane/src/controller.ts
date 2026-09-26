import {
  Body,
  Controller,
  Delete,
  Get,
  HttpCode,
  Inject,
  Optional,
  Param,
  Post,
  Query,
  Req,
  UseFilters,
} from "@nestjs/common";
import {
  CurrentUser,
  EffectivePermissions,
  GETBRICK_TRUST_PROXY,
  GetbrickPermissions,
  Public,
} from "@getbrick/idaas-nestjs";
import { parseWriteBody } from "./validation.js";
import { ControlPlaneExceptionFilter } from "./filter.js";
import { CONTROL_PLANE_BASE_PATH, type ControlPlaneActor } from "./types.js";
import {
  CONTROL_PLANE_PERMISSIONS,
  ControlPlaneService,
} from "./service.js";

@Controller(CONTROL_PLANE_BASE_PATH)
@UseFilters(ControlPlaneExceptionFilter)
export class ControlPlaneController {
  constructor(
    @Inject(ControlPlaneService) private readonly service: ControlPlaneService,
    @Optional() @Inject(GETBRICK_TRUST_PROXY) private readonly trustProxy = false,
  ) {}

  @Get("capabilities")
  @GetbrickPermissions(CONTROL_PLANE_PERMISSIONS.capabilities)
  capabilities(
    @CurrentUser() user: Record<string, unknown> | undefined,
    @EffectivePermissions() permissions: string[],
  ) {
    return this.service.getCapabilities(actor(user, permissions));
  }

  @Get("users")
  @GetbrickPermissions(CONTROL_PLANE_PERMISSIONS.users)
  listUsers(
    @Query() query: unknown,
    @CurrentUser() user: Record<string, unknown> | undefined,
    @EffectivePermissions() permissions: string[],
  ) {
    return this.service.listUsers(query, actor(user, permissions));
  }

  @Get("users/:id")
  @GetbrickPermissions(CONTROL_PLANE_PERMISSIONS.users)
  getUser(
    @Param("id") id: string,
    @CurrentUser() user: Record<string, unknown> | undefined,
    @EffectivePermissions() permissions: string[],
  ) {
    return this.service.getUser(id, actor(user, permissions));
  }

  @Post("users/:id/disable")
  @HttpCode(200)
  @GetbrickPermissions(CONTROL_PLANE_PERMISSIONS.usersWrite)
  disableUser(
    @Param("id") id: string,
    @Body() body: unknown,
    @Query() query: unknown,
    @CurrentUser() user: Record<string, unknown> | undefined,
    @EffectivePermissions() permissions: string[],
    @Req() request: ControlPlaneRequest,
  ) {
    parseWriteBody(query);
    return this.service.disableUser(id, body, actor(user, permissions), requestContext(request, this.trustProxy));
  }

  @Post("users/:id/enable")
  @HttpCode(200)
  @GetbrickPermissions(CONTROL_PLANE_PERMISSIONS.usersWrite)
  enableUser(
    @Param("id") id: string,
    @Body() body: unknown,
    @Query() query: unknown,
    @CurrentUser() user: Record<string, unknown> | undefined,
    @EffectivePermissions() permissions: string[],
    @Req() request: ControlPlaneRequest,
  ) {
    parseWriteBody(query);
    return this.service.enableUser(id, body, actor(user, permissions), requestContext(request, this.trustProxy));
  }

  @Delete("sessions/:id")
  @HttpCode(200)
  @GetbrickPermissions(CONTROL_PLANE_PERMISSIONS.sessionsWrite)
  revokeSession(
    @Param("id") id: string,
    @Body() body: unknown,
    @Query() query: unknown,
    @CurrentUser() user: Record<string, unknown> | undefined,
    @EffectivePermissions() permissions: string[],
    @Req() request: ControlPlaneRequest,
  ) {
    parseWriteBody(query);
    return this.service.revokeSession(id, body, actor(user, permissions), requestContext(request, this.trustProxy));
  }

  @Post("users/:id/sessions/revoke")
  @HttpCode(200)
  @GetbrickPermissions(CONTROL_PLANE_PERMISSIONS.sessionsWrite)
  revokeUserSessions(
    @Param("id") userId: string,
    @Body() body: unknown,
    @Query() query: unknown,
    @CurrentUser() user: Record<string, unknown> | undefined,
    @EffectivePermissions() permissions: string[],
    @Req() request: ControlPlaneRequest,
  ) {
    parseWriteBody(query);
    return this.service.revokeUserSessions(userId, body, actor(user, permissions), requestContext(request, this.trustProxy));
  }

  @Get("roles")
  @GetbrickPermissions(CONTROL_PLANE_PERMISSIONS.roles)
  listRoles(
    @Query() query: unknown,
    @CurrentUser() user: Record<string, unknown> | undefined,
    @EffectivePermissions() permissions: string[],
  ) {
    return this.service.listRoles(query, actor(user, permissions));
  }

  @Get("sessions")
  @GetbrickPermissions(CONTROL_PLANE_PERMISSIONS.sessions)
  listSessions(
    @Query() query: unknown,
    @CurrentUser() user: Record<string, unknown> | undefined,
    @EffectivePermissions() permissions: string[],
  ) {
    return this.service.listSessions(query, actor(user, permissions));
  }

  @Get("audit-events")
  @GetbrickPermissions(CONTROL_PLANE_PERMISSIONS.auditEvents)
  listAuditEvents(
    @Query() query: unknown,
    @CurrentUser() user: Record<string, unknown> | undefined,
    @EffectivePermissions() permissions: string[],
  ) {
    return this.service.listAuditEvents(query, actor(user, permissions));
  }

  @Get("audit-events/:id")
  @GetbrickPermissions(CONTROL_PLANE_PERMISSIONS.auditEvents)
  getAuditEvent(
    @Param("id") id: string,
    @CurrentUser() user: Record<string, unknown> | undefined,
    @EffectivePermissions() permissions: string[],
  ) {
    return this.service.getAuditEvent(id, actor(user, permissions));
  }

  @Get("system/info")
  @GetbrickPermissions(CONTROL_PLANE_PERMISSIONS.capabilities)
  systemInfo(
    @CurrentUser() user: Record<string, unknown> | undefined,
    @EffectivePermissions() permissions: string[],
    @Req() request: ControlPlaneRequest,
  ) {
    return this.service.getSystemInfo(actor(user, permissions), requestId(request));
  }

  @Get("health/live")
  @Public()
  healthLive() {
    return this.service.healthLive();
  }

  @Get("health/ready")
  @Public()
  healthReady() {
    return this.service.healthReady();
  }
}

function actor(
  user: Record<string, unknown> | undefined,
  permissions: string[],
): ControlPlaneActor {
  return {
    user,
    permissions,
    roles: rolesFromUser(user),
  };
}

interface ControlPlaneRequest {
  headers?: Record<string, unknown>;
  id?: unknown;
  ip?: unknown;
  ips?: unknown;
}

function requestContext(request: ControlPlaneRequest = {}, trustProxy = false): {
  requestId?: string;
  ipAddress?: string;
  userAgent?: string;
} {
  const headers = request.headers ?? {};
  const shouldTrustProxy = trustProxy === true;
  const userAgent = headerValue(headers, "user-agent");
  const forwarded = shouldTrustProxy ? headerValue(headers, "x-forwarded-for") : undefined;
  const ip = forwarded?.split(",")[0]?.trim() ?? textValue(request.ip) ?? (shouldTrustProxy
    ? textValue(Array.isArray(request.ips) ? request.ips[0] : undefined)
    : undefined);
  const requestIdValue = requestId(request);
  return {
    ...(requestIdValue === undefined ? {} : { requestId: requestIdValue }),
    ...(ip === undefined ? {} : { ipAddress: ip }),
    ...(userAgent === undefined ? {} : { userAgent }),
  };
}

function requestId(request: ControlPlaneRequest = {}): string | undefined {
  const values = [
    request.headers?.["x-request-id"],
    request.headers?.["x-correlation-id"],
    request.id,
  ];
  for (const value of values) {
    if (typeof value !== "string") continue;
    const normalized = value.trim();
    if (normalized.length === 0 || normalized.length > 128 || /[\u0000-\u001f\u007f]/u.test(normalized) || /(?:secret|token|password|private[-_]?key|credential|authorization|cookie|vault:\/\/)/iu.test(normalized)) continue;
    return normalized;
  }
  return undefined;
}

function headerValue(headers: Record<string, unknown>, name: string): string | undefined {
  const entry = Object.entries(headers).find(([key]) => key.toLowerCase() === name);
  return textValue(Array.isArray(entry?.[1]) ? entry[1][0] : entry?.[1]);
}

function textValue(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  const normalized = value.trim();
  if (normalized.length === 0 || normalized.length > 512 || /[\u0000-\u001f\u007f]/u.test(normalized)) return undefined;
  return normalized;
}

function rolesFromUser(user: Record<string, unknown> | undefined): string[] {
  if (!user) return [];
  const roles = [
    ...(Array.isArray(user.roles) ? user.roles : []),
    ...(Array.isArray(user.role) ? user.role : typeof user.role === "string" ? [user.role] : []),
  ];
  return [...new Set(roles.filter((role): role is string => typeof role === "string"))];
}
