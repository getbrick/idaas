export const GETBRICK_AUTH = "GETBRICK_AUTH";
export const GETBRICK_ROLES = "getbrick:roles";
export const GETBRICK_PERMISSIONS = "getbrick:permissions";
export const GETBRICK_RBAC = "GETBRICK_RBAC";

export interface GetbrickAuthLike {
  api: {
    getSession(args: { headers: Headers; query?: Record<string, string> }): Promise<unknown>;
    getActiveMember?(args: { headers: Headers; query?: Record<string, string> }): Promise<unknown>;
    getFullOrganization?(args: { headers: Headers; query?: Record<string, string> }): Promise<unknown>;
  };
  handler(request: Request): Promise<Response>;
}
