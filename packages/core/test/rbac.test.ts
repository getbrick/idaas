import { describe, expect, it } from "vitest";
import {
  DEFAULT_ROLE_GRAPH,
  buildRoleGraph,
  defineIdaasConfig,
  hasAllPermissions,
  hasPermission,
  permissionSatisfies,
  resolveDataScope,
  resolveEffectivePermissions,
  rolesFromUser,
  type RoleGraph,
} from "../src/index.js";

describe("rbac", () => {
  it("resolves inherited permissions through the chain", () => {
    const graph: RoleGraph = {
      viewer: { permissions: ["project:read"] },
      editor: { extends: ["viewer"], permissions: ["project:write"] },
      admin: { extends: ["editor"], permissions: ["*:*"] },
    };
    expect(resolveEffectivePermissions(graph, "editor")).toEqual([
      "project:write",
      "project:read",
    ]);
    expect(resolveEffectivePermissions(graph, "admin")).toContain("project:read");
    expect(resolveEffectivePermissions(graph, "admin")).toContain("*:*");
  });

  it("rejects unknown parent roles and cycles", () => {
    const config = defineIdaasConfig({ rbac: { roles: { ghost: { extends: ["missing"] } } } });
    expect(() => buildRoleGraph(config)).toThrow(/extends unknown role/);

    const cyclic: RoleGraph = {
      a: { extends: ["b"] },
      b: { extends: ["a"] },
    };
    expect(() => buildRoleGraph({ rbac: { roles: cyclic } } as never)).toThrow(/cycle/);
  });

  it("merges custom roles over the default graph", () => {
    const config = defineIdaasConfig({
      rbac: { roles: { support: { extends: ["user"], permissions: ["ticket:read"] } } },
    });
    const graph = buildRoleGraph(config);
    expect(graph.admin.extends).toEqual(["user"]);
    expect(resolveEffectivePermissions(graph, "support")).toEqual(["ticket:read"]);
    expect(DEFAULT_ROLE_GRAPH.user.permissions).toEqual([]);
  });

  it("matches wildcards per segment", () => {
    expect(permissionSatisfies("*:*", "project:write")).toBe(true);
    expect(permissionSatisfies("project:*", "project:write")).toBe(true);
    expect(permissionSatisfies("project:*", "other:write")).toBe(false);
    expect(permissionSatisfies("project:write", "project:read")).toBe(false);
    expect(hasPermission(["project:*"], "project:delete")).toBe(true);
    expect(hasAllPermissions(["project:read", "project:write"], ["project:write"])).toBe(true);
    expect(hasAllPermissions(["project:read"], ["project:read", "project:write"])).toBe(false);
  });

  it("scopes permissions to own/all", () => {
    expect(permissionSatisfies("project:read:own", "project:read:own")).toBe(true);
    expect(permissionSatisfies("project:read", "project:read:own")).toBe(true);
    expect(permissionSatisfies("project:read:own", "project:read")).toBe(true);
    expect(permissionSatisfies("project:read:own", "project:read:all")).toBe(false);

    expect(resolveDataScope(["project:read"], "project")).toBe("all");
    expect(resolveDataScope(["project:read:own"], "project")).toBe("own");
    expect(resolveDataScope(["project:read:own", "project:write:all"], "project")).toBe("all");
    expect(resolveDataScope(["ticket:read"], "project")).toBe("none");
    expect(resolveDataScope(["*:*:own"], "project")).toBe("own");
  });

  it("reads roles from a session user", () => {
    expect(rolesFromUser({ role: "admin" })).toEqual(["admin"]);
    expect(rolesFromUser({ role: ["admin", "support"] })).toEqual(["admin", "support"]);
    expect(rolesFromUser({})).toEqual(["user"]);
    expect(rolesFromUser(undefined)).toEqual(["user"]);
  });
});
