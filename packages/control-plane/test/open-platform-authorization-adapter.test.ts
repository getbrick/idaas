import { describe, expect, it, vi } from "vitest";
import {
  createOpenPlatformRequestContextIssuer,
  type OpenPlatformAuthorizationRequest,
  type OpenPlatformRequestContext,
} from "../src/open-platform/authorization.js";
import {
  createDevelopmentOpenPlatformActorResolver,
  createDevelopmentOpenPlatformAuthorizationAdapter,
  createProductionOpenPlatformAuthorizationAdapter,
  isDevelopmentOpenPlatformActorResolver,
  openPlatformLifecycleRbacPermission,
  OPEN_PLATFORM_LIFECYCLE_RBAC_ACTIONS,
  OPEN_PLATFORM_LIFECYCLE_RBAC_PERMISSIONS,
  toOpenPlatformRbacPermission,
  type OpenPlatformPermissionCache,
  type OpenPlatformTrustedActorResolution,
  type OpenPlatformTrustedActorResolver,
} from "../src/open-platform/adapters/authorization/index.js";

const fixedNow = new Date("2026-01-01T00:00:00.000Z");

const contextIssuer = createOpenPlatformRequestContextIssuer({
  issuerId: "authorization-adapter-test",
  attestation: Object.freeze({ trusted: true }),
  clock: () => fixedNow,
});

function authenticatedContext(
  tenantId = "tenant-a",
  actorId = "actor-a",
): OpenPlatformRequestContext {
  return contextIssuer.issueAuthenticated({
    tenantId,
    actorId,
    requestId: `request-${tenantId}-${actorId}`,
  });
}

function request(
  overrides: Partial<OpenPlatformAuthorizationRequest> = {},
): OpenPlatformAuthorizationRequest {
  return {
    context: authenticatedContext(),
    tenantId: "tenant-a",
    action: "read",
    resource: "application",
    resourceId: "app_12345678-1234-4123-8123-123456789abc",
    ...overrides,
  };
}

function trustedResolver(
  resolution: OpenPlatformTrustedActorResolution,
): OpenPlatformTrustedActorResolver {
  return Object.freeze({
    productionReady: true,
    resolve: vi.fn(async () => resolution),
  });
}

describe("production open platform RBAC authorization adapter", () => {
  it("allows a tenant actor through async trusted resolution and scoped role permissions", async () => {
    const resolver = trustedResolver({
      actor: {
        user: { id: "actor-a" },
        roles: ["tenant-application-reader"],
        permissions: [],
      },
      tenantIds: ["tenant-a"],
      tenantRoles: {
        "tenant-a": ["tenant-application-reader"],
      },
    });
    const rolePermissions = vi.fn(async () => ["open:application:read"]);
    const adapter = createProductionOpenPlatformAuthorizationAdapter({
      resolver,
      rolePermissions,
    });

    expect(adapter.productionReady).toBe(true);
    expect(toOpenPlatformRbacPermission(request())).toBe("open:application:read");
    await expect(adapter.authorize(request())).resolves.toBe(true);
    expect(resolver.resolve).toHaveBeenCalledWith({
      actorId: "actor-a",
      tenantId: "tenant-a",
    });
    expect(rolePermissions).toHaveBeenCalledWith(expect.objectContaining({
      role: "tenant-application-reader",
      scope: { kind: "tenant", tenantId: "tenant-a" },
      requiredPermission: "open:application:read",
    }));
  });

  it("denies missing and unknown permissions", async () => {
    const resolver = trustedResolver({
      actor: {
        user: { id: "actor-a" },
        roles: [],
        permissions: ["open:application:write", "open:unknown:read", "users:read"],
      },
      tenantIds: ["tenant-a"],
    });
    const adapter = createProductionOpenPlatformAuthorizationAdapter({ resolver });

    await expect(adapter.authorizeWithReason(request())).resolves.toEqual({
      allowed: false,
      reason: "permission-denied",
    });
    await expect(adapter.authorizeWithReason(request({
      resource: "unknown" as "application",
    }))).resolves.toEqual({
      allowed: false,
      reason: "unknown-permission",
    });
  });

  it("denies tenant mismatches before resolving an actor and exposes only a safe reason", async () => {
    const resolver = trustedResolver({
      actor: { user: { id: "actor-a" }, permissions: ["open:*:*"] },
      tenantIds: ["tenant-b"],
    });
    const reasons: string[] = [];
    const adapter = createProductionOpenPlatformAuthorizationAdapter({
      resolver,
      onDenied: (reason) => {
        reasons.push(reason);
      },
    });

    await expect(adapter.authorize(request({ tenantId: "tenant-b" }))).resolves.toBe(false);
    expect(resolver.resolve).not.toHaveBeenCalled();
    expect(reasons).toEqual(["tenant-mismatch"]);
    expect(JSON.stringify(reasons)).not.toContain("tenant-b");
    expect(JSON.stringify(reasons)).not.toContain("actor-a");
  });

  it("keeps platform roles outside tenant authority unless the platform boundary is explicit", async () => {
    const resolver = trustedResolver({
      actor: {
        user: { id: "platform-actor" },
        roles: ["platform-operator"],
        permissions: ["open:*:*"],
      },
      tenantIds: [],
      platformRoles: ["platform-operator"],
    });
    const rolePermissions = vi.fn(async () => ["open:tenant:read"]);
    const deniedAdapter = createProductionOpenPlatformAuthorizationAdapter({
      resolver,
      rolePermissions,
    });
    const allowedAdapter = createProductionOpenPlatformAuthorizationAdapter({
      resolver,
      rolePermissions,
      platformPermissions: ["open:tenant:read"],
    });
    const platformRequest = request({
      context: authenticatedContext("tenant-a", "platform-actor"),
      resource: "tenant",
    });

    await expect(deniedAdapter.authorizeWithReason(platformRequest)).resolves.toEqual({
      allowed: false,
      reason: "platform-boundary",
    });
    await expect(allowedAdapter.authorize(platformRequest)).resolves.toBe(true);
    expect(rolePermissions).toHaveBeenCalledWith(expect.objectContaining({
      role: "platform-operator",
      scope: { kind: "platform" },
      requiredPermission: "open:tenant:read",
    }));
  });

  it("uses the optional asynchronous permission cache without caching direct actor permissions", async () => {
    const values = new Map<string, readonly string[]>();
    let sets = 0;
    const permissionCache: OpenPlatformPermissionCache = {
      get: async (key) => values.get(key),
      set: async (key, permissions) => {
        sets += 1;
        values.set(key, permissions);
      },
      delete: async (key) => {
        values.delete(key);
      },
      invalidate: async () => {},
    };
    const resolver = trustedResolver({
      actor: {
        user: { id: "actor-a" },
        roles: ["tenant-reader"],
        permissions: [],
      },
      tenantIds: ["tenant-a"],
      tenantRoles: { "tenant-a": ["tenant-reader"] },
    });
    const rolePermissions = vi.fn(async () => ["open:application:read"]);
    const adapter = createProductionOpenPlatformAuthorizationAdapter({
      resolver,
      rolePermissions,
      permissionCache,
    });

    await expect(adapter.authorize(request())).resolves.toBe(true);
    await expect(adapter.authorize(request())).resolves.toBe(true);
    expect(rolePermissions).toHaveBeenCalledTimes(1);
    expect(sets).toBe(1);
  });

  it("does not reuse a cached allow across normalized resource ids", async () => {
    const values = new Map<string, readonly string[]>();
    const permissionCache: OpenPlatformPermissionCache = {
      get: async (key) => values.get(key),
      set: async (key, permissions) => {
        values.set(key, permissions);
      },
      delete: async (key) => {
        values.delete(key);
      },
      invalidate: async () => {},
    };
    const resolver = trustedResolver({
      actor: {
        user: { id: "actor-a" },
        roles: ["tenant-reader"],
        permissions: [],
      },
      tenantIds: ["tenant-a"],
      tenantRoles: { "tenant-a": ["tenant-reader"] },
    });
    const resourceA = "app_12345678-1234-4123-8123-123456789abc";
    const resourceB = "app_87654321-4321-4321-8321-cba987654321";
    const rolePermissions = vi.fn(async ({ resourceId }) =>
      resourceId === resourceA ? ["open:application:read"] : []
    );
    const adapter = createProductionOpenPlatformAuthorizationAdapter({
      resolver,
      rolePermissions,
      permissionCache,
    });

    await expect(adapter.authorize(request({ resourceId: ` ${resourceA} ` }))).resolves.toBe(true);
    await expect(adapter.authorize(request({ resourceId: resourceA }))).resolves.toBe(true);
    await expect(adapter.authorize(request({ resourceId: resourceB }))).resolves.toBe(false);
    expect(rolePermissions).toHaveBeenCalledTimes(2);
    expect(rolePermissions).toHaveBeenNthCalledWith(
      1,
      expect.objectContaining({ resourceId: resourceA }),
    );
    expect(rolePermissions).toHaveBeenNthCalledWith(
      2,
      expect.objectContaining({ resourceId: resourceB }),
    );
    expect([...values.keys()].some((key) => key.includes(resourceA))).toBe(true);
    expect([...values.keys()].some((key) => key.includes(resourceB))).toBe(true);
    expect([...values.keys()].some((key) => key.includes(` ${resourceA} `))).toBe(false);
  });

  it("revokes cached permissions immediately when the trusted permission version changes", async () => {
    const values = new Map<string, readonly string[]>();
    const permissionCache: OpenPlatformPermissionCache = {
      get: async (key) => values.get(key),
      set: async (key, permissions) => {
        values.set(key, permissions);
      },
      delete: async (key) => {
        values.delete(key);
      },
      invalidate: async () => {},
    };
    let permissionVersion = "v1";
    let granted = true;
    const resolver: OpenPlatformTrustedActorResolver = Object.freeze({
      productionReady: true,
      resolve: async () => ({
        actor: {
          user: { id: "actor-a" },
          roles: ["tenant-reader"],
          permissions: [],
        },
        tenantIds: ["tenant-a"],
        tenantRoles: { "tenant-a": ["tenant-reader"] },
        permissionVersion,
      }),
    });
    const rolePermissions = vi.fn(async () =>
      granted ? ["open:application:read"] : []
    );
    const adapter = createProductionOpenPlatformAuthorizationAdapter({
      resolver,
      rolePermissions,
      permissionCache,
    });

    await expect(adapter.authorize(request())).resolves.toBe(true);
    permissionVersion = "v2";
    granted = false;
    await expect(adapter.authorize(request())).resolves.toBe(false);
    expect(rolePermissions).toHaveBeenCalledTimes(2);
    expect([...values.values()].flat()).not.toContain("open:application:read");
  });

  it("supports explicit cache and local version invalidation", async () => {
    const values = new Map<string, readonly string[]>();
    const permissionCache: OpenPlatformPermissionCache = {
      get: async (key) => values.get(key),
      set: async (key, permissions) => {
        values.set(key, permissions);
      },
      delete: async (key) => {
        values.delete(key);
      },
      invalidate: async () => {},
    };
    const resolver = trustedResolver({
      actor: {
        user: { id: "actor-a" },
        roles: ["tenant-reader"],
        permissions: [],
      },
      tenantIds: ["tenant-a"],
      tenantRoles: { "tenant-a": ["tenant-reader"] },
    });
    let granted = true;
    const rolePermissions = vi.fn(async () =>
      granted ? ["open:application:read"] : []
    );
    const adapter = createProductionOpenPlatformAuthorizationAdapter({
      resolver,
      rolePermissions,
      permissionCache,
    });

    await expect(adapter.authorize(request())).resolves.toBe(true);
    await expect(adapter.authorize(request())).resolves.toBe(true);
    granted = false;
    await expect(adapter.invalidate({
      actorId: "actor-a",
      tenantId: "tenant-a",
      resourceKind: "application",
      resourceId: "app_12345678-1234-4123-8123-123456789abc",
    })).resolves.toBe(true);
    await expect(adapter.authorize(request())).resolves.toBe(false);
    expect(rolePermissions).toHaveBeenCalledTimes(2);

    granted = true;
    await expect(adapter.invalidateVersion({
      actorId: "actor-a",
      tenantId: "tenant-a",
    })).resolves.toBe(true);
    await expect(adapter.authorize(request())).resolves.toBe(true);
    expect(rolePermissions).toHaveBeenCalledTimes(3);
  });

  it("fails closed when a production resource policy returns a non-boolean", async () => {
    const resolver = trustedResolver({
      actor: {
        user: { id: "actor-a" },
        permissions: ["open:application:read"],
      },
      tenantIds: ["tenant-a"],
    });
    const adapter = createProductionOpenPlatformAuthorizationAdapter({
      resolver,
      resourcePolicy: async () => "true",
    });

    const decision = await adapter.authorizeWithReason(request());
    expect(decision).toEqual({
      allowed: false,
      reason: "invalid-policy-result",
    });
    await expect(adapter.authorize(request())).resolves.toBe(false);
  });

  it("fails closed and sanitizes resolver failures", async () => {
    const reasons: string[] = [];
    const resolver: OpenPlatformTrustedActorResolver = Object.freeze({
      productionReady: true,
      resolve: async () => {
        throw new Error("secret resolver detail");
      },
    });
    const adapter = createProductionOpenPlatformAuthorizationAdapter({
      resolver,
      onDenied: (reason) => {
        reasons.push(reason);
      },
    });

    await expect(adapter.authorize(request())).resolves.toBe(false);
    expect(reasons).toEqual(["resolver-unavailable"]);
    expect(JSON.stringify(reasons)).not.toContain("secret");
  });

  it("keeps development helpers non-production and rejects them in the production factory", () => {
    const resolver = createDevelopmentOpenPlatformActorResolver([{
      actorId: "actor-a",
      actor: {
        user: { id: "actor-a" },
        roles: [],
        permissions: ["open:application:read"],
      },
      tenantIds: ["tenant-a"],
    }]);
    const developmentAdapter = createDevelopmentOpenPlatformAuthorizationAdapter({
      resolver,
    });

    expect(isDevelopmentOpenPlatformActorResolver(resolver)).toBe(true);
    expect(developmentAdapter.productionReady).toBe(false);
    expect(() => createProductionOpenPlatformAuthorizationAdapter({
      resolver: resolver as never,
    })).toThrow(TypeError);
  });

  it("rejects development assurance in the production adapter", async () => {
    const resolver = trustedResolver({
      actor: { user: { id: "actor-a" }, permissions: ["open:application:read"] },
      tenantIds: ["tenant-a"],
    });
    const adapter = createProductionOpenPlatformAuthorizationAdapter({ resolver });
    const developmentContext = contextIssuer.issueDevelopment({
      tenantId: "tenant-a",
      actorId: "actor-a",
      requestId: "development-request",
    });

    await expect(adapter.authorizeWithReason(request({
      context: developmentContext,
    }))).resolves.toEqual({
      allowed: false,
      reason: "untrusted-context",
    });
  });

  it("maps every webhook operation to a stable webhook permission", async () => {
    const resolver = trustedResolver({
      actor: {
        user: { id: "actor-a" },
        roles: ["tenant-webhook-operator"],
        permissions: [],
      },
      tenantIds: ["tenant-a"],
      tenantRoles: { "tenant-a": ["tenant-webhook-operator"] },
    });
    const rolePermissions = vi.fn(async ({ requiredPermission }) => [requiredPermission]);
    const adapter = createProductionOpenPlatformAuthorizationAdapter({
      resolver,
      rolePermissions,
    });
    const expectations = [
      { action: "create", permission: "open:webhook:write", resourceId: undefined },
      { action: "read", permission: "open:webhook:read", resourceId: "whk_12345678-1234-4123-8123-123456789abc" },
      { action: "update", permission: "open:webhook:write", resourceId: "whk_12345678-1234-4123-8123-123456789abc" },
      { action: "rotate", permission: "open:webhook:rotate", resourceId: "whk_12345678-1234-4123-8123-123456789abc" },
      { action: "record", permission: "open:webhook:write", resourceId: "whk_12345678-1234-4123-8123-123456789abc" },
    ] as const;

    for (const expectation of expectations) {
      const webhookRequest = request({
        action: expectation.action,
        resource: "webhook",
        ...(expectation.resourceId === undefined ? {} : { resourceId: expectation.resourceId }),
      });
      expect(toOpenPlatformRbacPermission(webhookRequest)).toBe(expectation.permission);
      await expect(adapter.authorize(webhookRequest)).resolves.toBe(true);
    }
    expect(rolePermissions).toHaveBeenCalledWith(expect.objectContaining({
      action: "record",
      requiredPermission: "open:webhook:write",
      resource: "webhook",
      scope: { kind: "tenant", tenantId: "tenant-a" },
    }));
  });

  it("maps audit event reads to a stable audit permission", async () => {
    const resolver = trustedResolver({
      actor: {
        user: { id: "actor-a" },
        roles: ["tenant-auditor"],
        permissions: [],
      },
      tenantIds: ["tenant-a"],
      tenantRoles: { "tenant-a": ["tenant-auditor"] },
    });
    const rolePermissions = vi.fn(async ({ requiredPermission }) => [requiredPermission]);
    const adapter = createProductionOpenPlatformAuthorizationAdapter({ resolver, rolePermissions });
    const auditRequest = request({
      action: "read",
      resource: "auditEvent",
      resourceId: "aud_12345678-1234-4123-8123-123456789abc",
    });

    expect(toOpenPlatformRbacPermission(auditRequest)).toBe("open:audit:read");
    await expect(adapter.authorize(auditRequest)).resolves.toBe(true);
    expect(rolePermissions).toHaveBeenCalledWith(expect.objectContaining({
      requiredPermission: "open:audit:read",
      resource: "auditEvent",
    }));
  });

  it("denies without mapping unregistered webhook and audit actions", async () => {
    const resolver = trustedResolver({
      actor: {
        user: { id: "actor-a" },
        roles: ["tenant-webhook-operator"],
        permissions: ["open:webhook:*", "open:audit:*"],
      },
      tenantIds: ["tenant-a"],
      tenantRoles: { "tenant-a": ["tenant-webhook-operator"] },
    });
    const rolePermissions = vi.fn(async () => ["open:webhook:revoke"]);
    const adapter = createProductionOpenPlatformAuthorizationAdapter({
      resolver,
      rolePermissions,
    });
    const unregistered = [
      { action: "revoke", resource: "webhook" },
      { action: "grant", resource: "webhook" },
      { action: "create", resource: "auditEvent" },
      { action: "record", resource: "auditEvent" },
      { action: "update", resource: "auditEvent" },
    ] as const;

    for (const operation of unregistered) {
      const unregisteredRequest = request({ ...operation, resourceId: undefined });
      expect(toOpenPlatformRbacPermission(unregisteredRequest)).toBeUndefined();
      await expect(adapter.authorizeWithReason(unregisteredRequest)).resolves.toEqual({
        allowed: false,
        reason: "unknown-permission",
      });
    }
    expect(rolePermissions).not.toHaveBeenCalled();
  });

  it("accepts webhook and audit permissions in the platform boundary", () => {
    const resolver = trustedResolver({
      actor: {
        user: { id: "platform-actor" },
        roles: ["platform-operator"],
        permissions: ["open:*:*"],
      },
      tenantIds: [],
      platformRoles: ["platform-operator"],
    });
    const rolePermissions = vi.fn(async () => ["open:webhook:rotate", "open:audit:read"]);
    const adapter = createProductionOpenPlatformAuthorizationAdapter({
      resolver,
      rolePermissions,
      platformPermissions: [
        "open:webhook:read",
        "open:webhook:write",
        "open:webhook:rotate",
        "open:audit:read",
      ],
    });

    expect(() => createProductionOpenPlatformAuthorizationAdapter({
      resolver,
      platformPermissions: ["open:webhook:revoke"],
    })).toThrow(TypeError);
    return expect(adapter.authorize(request({
      context: authenticatedContext("tenant-a", "platform-actor"),
      action: "rotate",
      resource: "webhook",
      resourceId: "whk_12345678-1234-4123-8123-123456789abc",
    }))).resolves.toBe(true);
  });
});

const lifecyclePermissions = [
  "open:tenant:publish",
  "open:tenant:disable",
  "open:tenant:archive",
  "open:tenant:submit-review",
  "open:developer:publish",
  "open:developer:disable",
  "open:developer:archive",
  "open:developer:submit-review",
  "open:application:publish",
  "open:application:disable",
  "open:application:archive",
  "open:application:submit-review",
  "open:api-product:publish",
  "open:api-product:disable",
  "open:api-product:archive",
  "open:api-product:submit-review",
  "open:authorization:publish",
  "open:authorization:disable",
  "open:authorization:archive",
  "open:authorization:submit-review",
] as const;

const lifecycleMatrix = [
  { resource: "tenant", permission: "open:tenant" },
  { resource: "developerOrganization", permission: "open:developer" },
  { resource: "application", permission: "open:application" },
  { resource: "applicationEnvironment", permission: "open:application" },
  { resource: "apiProduct", permission: "open:api-product" },
  { resource: "apiVersion", permission: "open:api-product" },
  { resource: "subscription", permission: "open:authorization" },
] as const;

function lifecycleAdapter(
  permissions: readonly string[],
): ReturnType<typeof createProductionOpenPlatformAuthorizationAdapter> {
  const resolver = trustedResolver({
    actor: { user: { id: "actor-a" }, permissions: [...permissions] },
    tenantIds: ["tenant-a"],
  });
  return createProductionOpenPlatformAuthorizationAdapter({ resolver });
}

describe("open platform lifecycle RBAC permissions", () => {
  it("exposes one stable independent permission per lifecycle resource and action", () => {
    expect(OPEN_PLATFORM_LIFECYCLE_RBAC_ACTIONS).toEqual([
      "publish",
      "disable",
      "archive",
      "submit-review",
    ]);
    expect([...OPEN_PLATFORM_LIFECYCLE_RBAC_PERMISSIONS]).toEqual([...lifecyclePermissions]);
    expect(new Set(OPEN_PLATFORM_LIFECYCLE_RBAC_PERMISSIONS).size).toBe(20);
    for (const { resource, permission } of lifecycleMatrix) {
      expect(toOpenPlatformRbacPermission({ resource, action: "publish" }))
        .toBe(`${permission}:publish`);
      expect(toOpenPlatformRbacPermission({ resource, action: "disable" }))
        .toBe(`${permission}:disable`);
      expect(toOpenPlatformRbacPermission({ resource, action: "archive" }))
        .toBe(`${permission}:archive`);
      expect(toOpenPlatformRbacPermission({ resource, action: "submitReview" }))
        .toBe(`${permission}:submit-review`);
      expect(openPlatformLifecycleRbacPermission(resource, "published"))
        .toBe(`${permission}:publish`);
      expect(openPlatformLifecycleRbacPermission(resource, "disabled"))
        .toBe(`${permission}:disable`);
      expect(openPlatformLifecycleRbacPermission(resource, "archived"))
        .toBe(`${permission}:archive`);
      expect(openPlatformLifecycleRbacPermission(resource, "draft")).toBeUndefined();
    }
  });

  it("resolves lifecycle action aliases onto the same permission", () => {
    expect(toOpenPlatformRbacPermission({ resource: "application", action: "republish" }))
      .toBe("open:application:publish");
    expect(toOpenPlatformRbacPermission({ resource: "application", action: "submit-review" }))
      .toBe("open:application:submit-review");
    expect(toOpenPlatformRbacPermission({ resource: "credential", action: "publish" }))
      .toBeUndefined();
    expect(toOpenPlatformRbacPermission({ resource: "usage", action: "archive" }))
      .toBeUndefined();
  });

  it("does not let publish authority disable or archive a resource", async () => {
    const adapter = lifecycleAdapter(["open:application:publish"]);
    const publishRequest = request({ action: "publish", resource: "application" });
    const disableRequest = request({ action: "disable", resource: "application" });
    const archiveRequest = request({ action: "archive", resource: "application" });
    const submitReviewRequest = request({ action: "submitReview", resource: "application" });

    expect(toOpenPlatformRbacPermission(disableRequest)).toBe("open:application:disable");
    expect(toOpenPlatformRbacPermission(archiveRequest)).toBe("open:application:archive");
    await expect(adapter.authorize(publishRequest)).resolves.toBe(true);
    await expect(adapter.authorizeWithReason(disableRequest)).resolves.toEqual({
      allowed: false,
      reason: "permission-denied",
    });
    await expect(adapter.authorizeWithReason(archiveRequest)).resolves.toEqual({
      allowed: false,
      reason: "permission-denied",
    });
    await expect(adapter.authorizeWithReason(submitReviewRequest)).resolves.toEqual({
      allowed: false,
      reason: "permission-denied",
    });
  });

  it("does not let disable authority archive or publish a resource", async () => {
    const adapter = lifecycleAdapter(["open:application:disable"]);

    await expect(adapter.authorize(request({
      action: "disable",
      resource: "application",
    }))).resolves.toBe(true);
    await expect(adapter.authorize(request({
      action: "archive",
      resource: "application",
    }))).resolves.toBe(false);
    await expect(adapter.authorize(request({
      action: "publish",
      resource: "application",
    }))).resolves.toBe(false);
  });

  it("keeps legacy write authority and scoped wildcards separate from fine-grained actions", async () => {
    const legacy = lifecycleAdapter(["open:application:write"]);
    const legacyWriteRequest = request({ resource: "application", action: "update" });

    expect(toOpenPlatformRbacPermission({ resource: "application", action: "update" }))
      .toBe("open:application:write");
    await expect(legacy.authorize(legacyWriteRequest)).resolves.toBe(true);
    for (const action of ["publish", "disable", "archive", "submitReview"] as const) {
      await expect(legacy.authorizeWithReason(request({
        resource: "application",
        action,
      }))).resolves.toEqual({
        allowed: false,
        reason: "permission-denied",
      });
    }

    const wildcard = lifecycleAdapter(["open:application:*"]);
    for (const action of ["publish", "disable", "archive", "submitReview"] as const) {
      await expect(wildcard.authorize(request({ resource: "application", action })))
        .resolves.toBe(true);
    }
    await expect(wildcard.authorize(request({ resource: "apiProduct", action: "publish" })))
      .resolves.toBe(false);
  });

  it("fails closed for unknown lifecycle actions", async () => {
    const adapter = lifecycleAdapter(["open:application:write", "open:application:*"]);
    const unknown = ["delete", "destroy", "Publish", "publish "] as const;

    for (const action of unknown) {
      const unknownRequest = request({
        action: action as OpenPlatformAuthorizationRequest["action"],
        resource: "application",
      });
      expect(toOpenPlatformRbacPermission(unknownRequest)).toBeUndefined();
      await expect(adapter.authorizeWithReason(unknownRequest)).resolves.toEqual({
        allowed: false,
        reason: "unknown-permission",
      });
    }
  });

  it("accepts every fine-grained lifecycle permission in the platform boundary", async () => {
    const resolver = trustedResolver({
      actor: {
        user: { id: "platform-actor" },
        roles: ["platform-operator"],
        permissions: ["open:*:*"],
      },
      tenantIds: [],
      platformRoles: ["platform-operator"],
    });
    const rolePermissions = vi.fn(async ({ requiredPermission }) => [requiredPermission]);
    const adapter = createProductionOpenPlatformAuthorizationAdapter({
      resolver,
      rolePermissions,
      platformPermissions: [...OPEN_PLATFORM_LIFECYCLE_RBAC_PERMISSIONS],
    });

    expect(() => createProductionOpenPlatformAuthorizationAdapter({
      resolver,
      platformPermissions: ["open:application:unpublish"],
    })).toThrow(TypeError);
    for (const { resource, permission } of lifecycleMatrix) {
      for (const action of ["publish", "disable", "archive", "submitReview"] as const) {
        const platformRequest = request({
          context: authenticatedContext("tenant-a", "platform-actor"),
          resource,
          action,
        });
        void expect(toOpenPlatformRbacPermission(platformRequest))
          .toBe(`${permission}:${action === "submitReview" ? "submit-review" : action}`);
        await expect(adapter.authorize(platformRequest)).resolves.toBe(true);
      }
    }
  });

  it("caches and invalidates each fine-grained lifecycle action independently", async () => {
    const values = new Map<string, readonly string[]>();
    const permissionCache: OpenPlatformPermissionCache = {
      get: async (key) => values.get(key),
      set: async (key, permissions) => {
        values.set(key, permissions);
      },
      delete: async (key) => {
        values.delete(key);
      },
      invalidate: async () => {},
    };
    const resolver = trustedResolver({
      actor: {
        user: { id: "actor-a" },
        roles: ["tenant-publisher"],
        permissions: [],
      },
      tenantIds: ["tenant-a"],
      tenantRoles: { "tenant-a": ["tenant-publisher"] },
    });
    const granted = new Set(["open:application:publish"]);
    const rolePermissions = vi.fn(async ({ requiredPermission }: { requiredPermission: string }) =>
      granted.has(requiredPermission) ? [requiredPermission] : []
    );
    const adapter = createProductionOpenPlatformAuthorizationAdapter({
      resolver,
      rolePermissions,
      permissionCache,
    });
    const publishRequest = request({ resource: "application", action: "publish" });
    const disableRequest = request({ resource: "application", action: "disable" });

    await expect(adapter.authorize(publishRequest)).resolves.toBe(true);
    await expect(adapter.authorize(publishRequest)).resolves.toBe(true);
    await expect(adapter.authorize(disableRequest)).resolves.toBe(false);
    await expect(adapter.authorize(disableRequest)).resolves.toBe(false);
    expect(rolePermissions).toHaveBeenCalledTimes(2);
    expect(values.size).toBe(2);

    granted.add("open:application:disable");
    await expect(adapter.authorize(disableRequest)).resolves.toBe(false);
    await expect(adapter.invalidate({
      actorId: "actor-a",
      tenantId: "tenant-a",
      resourceKind: "application",
      permission: "open:application:disable",
    })).resolves.toBe(true);
    await expect(adapter.authorize(disableRequest)).resolves.toBe(true);
    await expect(adapter.authorize(publishRequest)).resolves.toBe(true);
    expect(rolePermissions).toHaveBeenCalledTimes(3);
  });
});
