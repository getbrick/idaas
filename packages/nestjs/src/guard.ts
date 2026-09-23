import { ForbiddenException, Inject, Injectable, Optional, UnauthorizedException } from "@nestjs/common";
import { Reflector } from "@nestjs/core";
import type { CanActivate, ExecutionContext } from "@nestjs/common";
import {
  DEFAULT_ROLE_GRAPH,
  hasAllPermissions,
  resolveDataScope,
  resolveEffectivePermissions,
  rolesFromUser,
  type RoleGraph,
} from "@getbrick/idaas-core";
import { GETBRICK_AUTH, GETBRICK_PERMISSIONS, GETBRICK_RBAC, GETBRICK_ROLES, type GetbrickAuthLike } from "./tokens.js";
import { getSessionFromRequest, headersFromRequest } from "./request.js";

@Injectable()
export class GetbrickAuthGuard implements CanActivate {
  constructor(
    @Inject(GETBRICK_AUTH) private readonly auth: GetbrickAuthLike,
    @Inject(Reflector) private readonly reflector: Reflector,
    @Optional() @Inject(GETBRICK_RBAC) private readonly roleGraph?: RoleGraph,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const req = context.switchToHttp().getRequest<Record<string, any>>();
    const session = await getSessionFromRequest(this.auth, req);
    if (!session?.user) {
      throw new UnauthorizedException();
    }
    req.getbrickSession = session;

    const activeOrgId = session.session?.activeOrganizationId;
    if (activeOrgId && typeof activeOrgId === "string") {
      const headers = headersFromRequest(req);
      try {
        const [member, organization] = await Promise.all([
          this.auth.api.getActiveMember?.({ headers }),
          this.auth.api.getFullOrganization?.({ headers }),
        ]);
        if (member && typeof member === "object") session.member = member as Record<string, unknown>;
        if (organization && typeof organization === "object") session.organization = organization as Record<string, unknown>;
      } catch {
        // organization enrichment is best-effort; guards must not fail on it
      }
    }

    const graph = this.roleGraph ?? DEFAULT_ROLE_GRAPH;
    const userRoles = rolesFromUser(session.user);
    const memberRole = typeof session.member?.role === "string" ? session.member.role : undefined;
    if (memberRole) userRoles.push(memberRole);
    const effectivePermissions = new Set<string>();
    for (const role of userRoles) {
      for (const permission of resolveEffectivePermissions(graph, role)) {
        effectivePermissions.add(permission);
      }
    }

    const requiredRoles = this.reflector.getAllAndOverride<string[] | undefined>(
      GETBRICK_ROLES,
      [context.getHandler(), context.getClass()],
    );
    if (requiredRoles && requiredRoles.length > 0) {
      const ok = requiredRoles.some((r) => userRoles.includes(r));
      if (!ok) throw new ForbiddenException("insufficient role");
    }

    const requiredPermissions = this.reflector.getAllAndOverride<string[] | undefined>(
      GETBRICK_PERMISSIONS,
      [context.getHandler(), context.getClass()],
    );
    if (requiredPermissions && requiredPermissions.length > 0) {
      if (!hasAllPermissions([...effectivePermissions], requiredPermissions)) {
        throw new ForbiddenException("insufficient permission");
      }
    }

    req.getbrickPermissions = [...effectivePermissions];
    req.getbrickDataScopes = new Proxy({}, {
      get: (_target, resource: string) => resolveDataScope([...effectivePermissions], resource),
    });
    return true;
  }
}
