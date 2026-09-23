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
import { getSessionFromRequest } from "./request.js";

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

    const graph = this.roleGraph ?? DEFAULT_ROLE_GRAPH;
    const userRoles = rolesFromUser(session.user);
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
