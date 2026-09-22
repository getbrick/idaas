import { createParamDecorator, SetMetadata, type ExecutionContext } from "@nestjs/common";
import { GETBRICK_ROLES } from "./tokens.js";

export const GetbrickRoles = (...roles: string[]) => SetMetadata(GETBRICK_ROLES, roles);

export const CurrentUser = createParamDecorator(
  (_data: unknown, ctx: ExecutionContext): Record<string, unknown> | undefined => {
    const req = ctx.switchToHttp().getRequest<Record<string, any>>();
    return req.getbrickSession?.user;
  },
);

export const CurrentSession = createParamDecorator(
  (_data: unknown, ctx: ExecutionContext): Record<string, unknown> | undefined => {
    return ctx.switchToHttp().getRequest<Record<string, any>>().getbrickSession;
  },
);
