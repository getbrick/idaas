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

  it("accepts shared parents in a role DAG", () => {
    const config = defineIdaasConfig({
      rbac: {
        roles: {
          base: { permissions: ["project:read"] },
          left: { extends: ["base"] },
          right: { extends: ["base"], permissions: ["ticket:read"] },
          root: { extends: ["left", "right"], permissions: ["project:write"] },
        },
      },
    });

    const graph = buildRoleGraph(config);
    expect(resolveEffectivePermissions(graph, "root")).toEqual([
      "project:write",
      "project:read",
      "ticket:read",
    ]);
  });

  it("rejects dangerous role and permission names", () => {
    const dangerousRoles = JSON.parse('{"__proto__":{"permissions":["project:read"]}}');
    expect(() => buildRoleGraph({ rbac: { roles: dangerousRoles } } as never)).toThrow(/dangerous role/);
    expect(() =>
      buildRoleGraph({ rbac: { roles: { __proto__: { permissions: ["project:read"] } } } } as never),
    ).toThrow(/dangerous role/);
    expect(() =>
      buildRoleGraph({ rbac: { roles: { unsafe: { permissions: ["constructor:read"] } } } } as never),
    ).toThrow(/dangerous permission/);
    expect(() =>
      buildRoleGraph({ rbac: { roles: { unsafe: { permissions: ["project:read:unknown:extra"] } } } } as never),
    ).toThrow(/invalid permission/);
  });

  it("protects permission resolution from cycles and deep graphs", () => {
    const cyclic: RoleGraph = {
      first: { extends: ["second"], permissions: ["first:read"] },
      second: { extends: ["first"], permissions: ["second:read"] },
    };
    expect(resolveEffectivePermissions(cyclic, "first")).toEqual(["first:read", "second:read"]);

    const deep: RoleGraph = {};
    for (let index = 0; index < 2000; index++) {
      deep[`role${index}`] = {
        extends: index === 0 ? [] : [`role${index - 1}`],
        permissions: [`resource${index}:read`],
      };
    }
    expect(resolveEffectivePermissions(deep, "role1999")).toHaveLength(2000);
  });

  it("reads roles from a session user", () => {
    expect(rolesFromUser({ role: "admin" })).toEqual(["admin"]);
    expect(rolesFromUser({ role: ["admin", "support"] })).toEqual(["admin", "support"]);
    expect(rolesFromUser({})).toEqual(["user"]);
    expect(rolesFromUser(undefined)).toEqual(["user"]);
  });
});
