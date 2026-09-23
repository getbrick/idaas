import { createParamDecorator, SetMetadata, type ExecutionContext } from "@nestjs/common";
import { resolveDataScope, type DataScope as DataScopeValue } from "@getbrick/idaas-core";
import { GETBRICK_PERMISSIONS, GETBRICK_ROLES } from "./tokens.js";

export const GetbrickRoles = (...roles: string[]) => SetMetadata(GETBRICK_ROLES, roles);

export const GetbrickPermissions = (...permissions: string[]) =>
  SetMetadata(GETBRICK_PERMISSIONS, permissions);

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

export const EffectivePermissions = createParamDecorator(
  (_data: unknown, ctx: ExecutionContext): string[] => {
    return ctx.switchToHttp().getRequest<Record<string, any>>().getbrickPermissions ?? [];
  },
);

export const CurrentOrganization = createParamDecorator(
  (_data: unknown, ctx: ExecutionContext): Record<string, unknown> | undefined => {
    return ctx.switchToHttp().getRequest<Record<string, any>>().getbrickSession?.organization;
  },
);

export const CurrentMember = createParamDecorator(
  (_data: unknown, ctx: ExecutionContext): Record<string, unknown> | undefined => {
    return ctx.switchToHttp().getRequest<Record<string, any>>().getbrickSession?.member;
  },
);

export const GetDataScope = createParamDecorator(
  (resource: string, ctx: ExecutionContext): DataScopeValue => {
    const req = ctx.switchToHttp().getRequest<Record<string, any>>();
    return resolveDataScope(req.getbrickPermissions ?? [], resource);
  },
);

export type { DataScopeValue as DataScope };
