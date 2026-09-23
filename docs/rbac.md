# RBAC: Role Inheritance, Permissions & Data Scope

## Model

- Roles are defined in config (`getbrick.config.ts`), with `extends` (single inheritance DAG, cycle-checked) and `permissions`.
- Permissions are strings: `resource:action[:scope]` — e.g. `project:read`, `project:write:own`, wildcard `*` per segment (`*:*`, `project:*`).
- Built-in graph: `user` (no permissions) ← `admin` (`*:*`). Custom roles merge on top.
- User roles live on the `user.role` column, managed by the better-auth admin plugin (`/api/auth/admin/set-role`, ban, impersonation...). The first admin must be bootstrapped directly in the database or via `extraOptions.plugins` with `admin({ adminUserIds })`.

## Config

```ts
export const idaas = defineIdaasConfig({
  appName: "My App",
  rbac: {
    roles: {
      viewer:  { permissions: ["project:read"] },
      member:  { extends: ["viewer"], permissions: ["project:write:own"] },
      owner:   { extends: ["member"], permissions: ["project:write", "member:manage"] },
      // admin is built-in: extends user, "*:*"
    },
  },
});
```

## NestJS

```ts
GetbrickIdaasModule.forRoot({ auth, rbac: buildRoleGraph(defineIdaasConfig(...)) })
```

`rbac` is optional — defaults to the built-in graph.

```ts
@GetbrickRoles("admin")                    // 403 if user role not in list
@GetbrickPermissions("project:write")      // 403 unless effective permissions cover it
@Get("projects")
list(@GetDataScope("project") scope, @CurrentUser() user) {
  // scope: "all" | "own" | "none" — controller filters rows accordingly
}
```

Semantics:

- A route requiring an **unscoped** permission (`project:read`) passes for users with any scope of that action (`project:read`, `project:read:own`) — row filtering is the controller's job via `GetDataScope`.
- A route requiring a **scoped** permission (`project:read:all`) passes only for grants that imply `all`.
- Wildcards: `*` matches per segment; `project:*` grants everything under `project`.
- Insufficient role/permission → **403 Forbidden** (breaking change from 0.1: was 401).

## Data scope

`GetDataScope("project")` resolves to `"all"` if any grant is unscoped or `:all`, `"own"` if only `:own` grants exist, `"none"` otherwise. Use it to filter queries:

```ts
if (scope === "own") return this.repo.find({ where: { ownerId: user.id } });
return this.repo.find();
```

## Doctor / validation

`buildRoleGraph` throws on unknown parent roles and inheritance cycles at app start (fail-fast, before serving traffic).
