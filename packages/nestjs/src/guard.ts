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
import {
  GETBRICK_AUTH,
  GETBRICK_ORGANIZATION_REQUIRED,
  GETBRICK_PERMISSIONS,
  GETBRICK_PUBLIC,
  GETBRICK_RBAC,
  GETBRICK_ROLES,
  type GetbrickAuthLike,
} from "./tokens.js";
import { getSessionFromRequest, headersFromRequest, isRecord, type GetbrickSession } from "./request.js";

@Injectable()
export class GetbrickAuthGuard implements CanActivate {
  constructor(
    @Inject(GETBRICK_AUTH) private readonly auth: GetbrickAuthLike,
    @Inject(Reflector) private readonly reflector: Reflector,
    @Optional() @Inject(GETBRICK_RBAC) private readonly roleGraph?: RoleGraph,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const metadataTargets = [context.getHandler(), context.getClass()];
    const isPublic = this.reflector.getAllAndOverride<boolean | undefined>(
      GETBRICK_PUBLIC,
      metadataTargets,
    );
    if (isPublic === true) return true;

    const req = context.switchToHttp().getRequest<Record<string, unknown>>();
    delete req.getbrickSession;
    delete req.getbrickPermissions;
    delete req.getbrickDataScopes;

    let session: GetbrickSession | null;
    try {
      session = await getSessionFromRequest(this.auth, req);
    } catch {
      throw new UnauthorizedException();
    }
    if (!session?.user) throw new UnauthorizedException();

    req.getbrickSession = session;
    const requireOrganization =
      this.reflector.getAllAndOverride<boolean | undefined>(
        GETBRICK_ORGANIZATION_REQUIRED,
        metadataTargets,
      ) === true;
    await this.enrichOrganization(req, session, requireOrganization);

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
      metadataTargets,
    );
    if (requiredRoles && requiredRoles.length > 0) {
      const ok = requiredRoles.some((role) => userRoles.includes(role));
      if (!ok) throw new ForbiddenException("insufficient role");
    }

    const requiredPermissions = this.reflector.getAllAndOverride<string[] | undefined>(
      GETBRICK_PERMISSIONS,
      metadataTargets,
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

  private async enrichOrganization(
    req: Record<string, unknown>,
    session: GetbrickSession,
    failClosed: boolean,
  ): Promise<void> {
    const activeOrganizationId = session.session?.activeOrganizationId;
    const hasExistingContext = isRecord(session.member) && isRecord(session.organization);
    if (typeof activeOrganizationId !== "string" || activeOrganizationId.length === 0) {
      if (failClosed && !hasExistingContext) {
        throw new ForbiddenException("organization context required");
      }
      return;
    }

    try {
      const headers = headersFromRequest(req);
      const [member, organization] = await Promise.all([
        this.auth.api.getActiveMember
          ? this.auth.api.getActiveMember({ headers })
          : Promise.resolve(session.member),
        this.auth.api.getFullOrganization
          ? this.auth.api.getFullOrganization({ headers })
          : Promise.resolve(session.organization),
      ]);
      const hasMember = isRecord(member);
      const hasOrganization = isRecord(organization);
      if (hasMember) session.member = member;
      if (hasOrganization) session.organization = organization;
      if (failClosed && (!hasMember || !hasOrganization)) {
        throw new ForbiddenException("organization context unavailable");
      }
    } catch {
      if (failClosed) {
        delete session.member;
        delete session.organization;
        throw new ForbiddenException("organization context unavailable");
      }
    }
  }
}
