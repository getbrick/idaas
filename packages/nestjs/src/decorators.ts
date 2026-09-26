import { createParamDecorator, SetMetadata, type ExecutionContext } from "@nestjs/common";
import { resolveDataScope, type DataScope as DataScopeValue } from "@getbrick/idaas-core";
import {
  GETBRICK_ORGANIZATION_REQUIRED,
  GETBRICK_PERMISSIONS,
  GETBRICK_PUBLIC,
  GETBRICK_ROLES,
} from "./tokens.js";
import { sanitizeGetbrickSession, type GetbrickSession } from "./request.js";

export const GetbrickRoles = (...roles: string[]) => SetMetadata(GETBRICK_ROLES, roles);

export const GetbrickPermissions = (...permissions: string[]) =>
  SetMetadata(GETBRICK_PERMISSIONS, permissions);

export const Public = (enabled = true) => SetMetadata(GETBRICK_PUBLIC, enabled);

export interface OrganizationContextOptions {
  failClosed?: boolean;
}

export const RequireOrganization = (
  enabled: boolean | OrganizationContextOptions = true,
) => SetMetadata(GETBRICK_ORGANIZATION_REQUIRED, isOrganizationRequired(enabled));

export const OrganizationContext = RequireOrganization;
export const RequireOrganizationContext = RequireOrganization;
export const GetbrickOrganization = RequireOrganization;

function currentSession(ctx: ExecutionContext): GetbrickSession | undefined {
  const req = ctx.switchToHttp().getRequest<Record<string, unknown>>();
  return sanitizeGetbrickSession(req.getbrickSession) ?? undefined;
}

export const CurrentUser = createParamDecorator(
  (_data: unknown, ctx: ExecutionContext): Record<string, unknown> | undefined => {
    return currentSession(ctx)?.user;
  },
);

export const CurrentSession = createParamDecorator(
  (_data: unknown, ctx: ExecutionContext): GetbrickSession | undefined => {
    return currentSession(ctx);
  },
);

export const EffectivePermissions = createParamDecorator(
  (_data: unknown, ctx: ExecutionContext): string[] => {
    const req = ctx.switchToHttp().getRequest<Record<string, unknown>>();
    return (req.getbrickPermissions as string[] | undefined) ?? [];
  },
);

export const CurrentOrganization = createParamDecorator(
  (_data: unknown, ctx: ExecutionContext): Record<string, unknown> | undefined => {
    return currentSession(ctx)?.organization;
  },
);

export const CurrentMember = createParamDecorator(
  (_data: unknown, ctx: ExecutionContext): Record<string, unknown> | undefined => {
    return currentSession(ctx)?.member;
  },
);

export const GetDataScope = createParamDecorator(
  (resource: string, ctx: ExecutionContext): DataScopeValue => {
    const req = ctx.switchToHttp().getRequest<Record<string, unknown>>();
    const permissions = (req.getbrickPermissions as string[] | undefined) ?? [];
    return resolveDataScope(permissions, resource);
  },
);

function isOrganizationRequired(value: boolean | OrganizationContextOptions): boolean {
  return typeof value === "boolean" ? value : value.failClosed !== false;
}

export type { DataScopeValue as DataScope };
