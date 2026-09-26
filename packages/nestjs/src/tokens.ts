export const GETBRICK_AUTH = "GETBRICK_AUTH";
export const GETBRICK_AUTH_BASE_PATH = "GETBRICK_AUTH_BASE_PATH";
export const GETBRICK_AUTH_BASE_URL = "GETBRICK_AUTH_BASE_URL";
export const GETBRICK_TRUST_PROXY = "GETBRICK_TRUST_PROXY";
export const GETBRICK_ROLES = "getbrick:roles";
export const GETBRICK_PERMISSIONS = "getbrick:permissions";
export const GETBRICK_PUBLIC = "getbrick:public";
export const GETBRICK_ORGANIZATION_REQUIRED = "getbrick:organization-required";
export const GETBRICK_RBAC = "GETBRICK_RBAC";
export const GETBRICK_OIDC_RUNTIME = "GETBRICK_OIDC_RUNTIME";
export const GETBRICK_OIDC_AUTH = "GETBRICK_OIDC_AUTH";
export const GETBRICK_OIDC_LOGIN_URL = "GETBRICK_OIDC_LOGIN_URL";
export const GETBRICK_OIDC_PLATFORM_LOGIN_HANDLER = "GETBRICK_OIDC_PLATFORM_LOGIN_HANDLER";
export const GETBRICK_OIDC_READINESS = "GETBRICK_OIDC_READINESS";
export const AUTH_BASE_PATH = "/api/auth";

export interface GetbrickAuthLike {
  options?: {
    basePath?: string;
    baseURL?: unknown;
    secret?: unknown;
  };
  api: {
    getSession(args: { headers: Headers; query?: Record<string, string> }): Promise<unknown>;
    getActiveMember?(args: { headers: Headers; query?: Record<string, string> }): Promise<unknown>;
    getFullOrganization?(args: { headers: Headers; query?: Record<string, string> }): Promise<unknown>;
  };
  handler(request: Request): Promise<Response>;
}
