import { Injectable, UnauthorizedException, Inject } from "@nestjs/common";
import { Reflector } from "@nestjs/core";
import type { CanActivate, ExecutionContext } from "@nestjs/common";
import { GETBRICK_AUTH, GETBRICK_ROLES, type GetbrickAuthLike } from "./tokens.js";
import { getSessionFromRequest } from "./request.js";

@Injectable()
export class GetbrickAuthGuard implements CanActivate {
  constructor(
    @Inject(GETBRICK_AUTH) private readonly auth: GetbrickAuthLike,
    @Inject(Reflector) private readonly reflector: Reflector,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const req = context.switchToHttp().getRequest<Record<string, any>>();
    const session = await getSessionFromRequest(this.auth, req);
    if (!session?.user) {
      throw new UnauthorizedException();
    }
    req.getbrickSession = session;

    const requiredRoles = this.reflector.getAllAndOverride<string[] | undefined>(
      GETBRICK_ROLES,
      [context.getHandler(), context.getClass()],
    );
    if (requiredRoles && requiredRoles.length > 0) {
      const role = session.user.role;
      const roles = Array.isArray(role) ? role : role ? [String(role)] : [];
      const ok = requiredRoles.some((r) => roles.includes(r));
      if (!ok) throw new UnauthorizedException("insufficient role");
    }
    return true;
  }
}
