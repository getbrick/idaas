import { describe, expect, it } from "vitest";
import {
  createDevelopmentOpenPlatformAuthorization,
  createOpenPlatformRequestContextIssuer,
  openPlatformLifecycleAuthorizationActionForStatus,
  permissionFor,
  type OpenPlatformAuthorizationPort,
  type OpenPlatformPermission,
  type OpenPlatformRequestContext,
} from "../src/open-platform/authorization.js";
import { InMemoryOpenPlatformAuditEventStore } from "../src/open-platform/audit.js";
import { OPEN_PLATFORM_ERROR_CODES } from "../src/open-platform/errors.js";
import { InMemoryOpenPlatformRepositories } from "../src/open-platform/repositories.js";
import {
  createOpenPlatformService,
  type OpenPlatformService,
} from "../src/open-platform/service.js";
import type {
  OpenPlatformServiceOptions,
  Tenant,
} from "../src/open-platform/types.js";

const fixedNow = new Date("2030-03-01T00:00:00.000Z");
const defaultTenantId = "tenant-lifecycle";

interface Harness {
  service: OpenPlatformService;
  audit: InMemoryOpenPlatformAuditEventStore;
  repositories: InMemoryOpenPlatformRepositories;
  context(): OpenPlatformRequestContext;
  createTenant(key: string): Promise<Tenant>;
}

function createHarness(
  permissions: readonly OpenPlatformPermission[] | "all",
  options: {
    tenantId?: string;
    repositories?: InMemoryOpenPlatformRepositories;
    audit?: InMemoryOpenPlatformAuditEventStore;
  } = {},
): Harness {
  const repositories = options.repositories ??
    new InMemoryOpenPlatformRepositories({ clock: () => fixedNow });
  const audit = options.audit ??
    new InMemoryOpenPlatformAuditEventStore({ clock: () => fixedNow });
  const tenantId = options.tenantId ?? defaultTenantId;
  const service = createOpenPlatformService({
    mode: "test",
    authorization: createDevelopmentOpenPlatformAuthorization(permissions),
    repositories,
    audit,
    clock: () => fixedNow,
  });
  const issuer = createOpenPlatformRequestContextIssuer({
    issuerId: "lifecycle-authorization-tests",
    attestation: Object.freeze({ test: true }),
    clock: () => fixedNow,
  });
  let sequence = 0;
  const context = (): OpenPlatformRequestContext =>
    issuer.issueDevelopment({
      tenantId,
      actorId: "actor-lifecycle",
      requestId: `lifecycle-request-${++sequence}`,
    });
  return {
    service,
    audit,
    repositories,
    context,
    async createTenant(key: string) {
      return service.createTenant(context(), {
        tenantId,
        name: `${key} tenant`,
        idempotencyKey: `${key}-create`,
      });
    },
  };
}

function lifecycleCommand(
  resourceId: string,
  key: string,
  tenantId = defaultTenantId,
): { resource: "tenant"; tenantId: string; id: string; idempotencyKey: string } {
  return {
    resource: "tenant",
    tenantId,
    id: resourceId,
    idempotencyKey: key,
  };
}

function authorizationSpy(): {
  port: OpenPlatformAuthorizationPort;
  actions: string[];
} {
  const actions: string[] = [];
  return {
    actions,
    port: {
      productionReady: false,
      authorize(request) {
        actions.push(`${request.resource}.${request.action}:${request.resourceId ?? "none"}`);
        return true;
      },
    },
  };
}

describe("open platform lifecycle authorization actions", () => {
  it("publishes, disables, and archives through independent fine-grained actions", async () => {
    const harness = createHarness([
      "tenant.create",
      "tenant.publish",
      "tenant.disable",
      "tenant.archive",
    ]);
    const tenant = await harness.createTenant("full");

    const published = await harness.service.publish(
      harness.context(),
      lifecycleCommand(tenant.id, "full-publish"),
    );
    expect(published.status).toBe("published");
    const disabled = await harness.service.deactivate(
      harness.context(),
      lifecycleCommand(tenant.id, "full-disable"),
    );
    expect(disabled.status).toBe("disabled");
    const republished = await harness.service.publish(
      harness.context(),
      lifecycleCommand(tenant.id, "full-republish"),
    );
    expect(republished.status).toBe("published");
    const archived = await harness.service.archive(
      harness.context(),
      lifecycleCommand(tenant.id, "full-archive"),
    );
    expect(archived.status).toBe("archived");
    expect(archived.archivedAt).toBe(fixedNow.toISOString());
  });

  it("keeps publish authority from disabling or archiving a resource", async () => {
    const harness = createHarness(["tenant.create", "tenant.publish"]);
    const tenant = await harness.createTenant("publish-only");

    await expect(harness.service.publish(
      harness.context(),
      lifecycleCommand(tenant.id, "publish-only-publish"),
    )).resolves.toMatchObject({ status: "published" });
    await expect(harness.service.deactivate(
      harness.context(),
      lifecycleCommand(tenant.id, "publish-only-disable"),
    )).rejects.toMatchObject({ code: OPEN_PLATFORM_ERROR_CODES.FORBIDDEN });
    await expect(harness.service.archive(
      harness.context(),
      lifecycleCommand(tenant.id, "publish-only-archive"),
    )).rejects.toMatchObject({ code: OPEN_PLATFORM_ERROR_CODES.FORBIDDEN });
    await expect(harness.service.submitReview(
      harness.context(),
      lifecycleCommand(tenant.id, "publish-only-review"),
    )).rejects.toMatchObject({ code: OPEN_PLATFORM_ERROR_CODES.FORBIDDEN });
    await expect(harness.service.transitionLifecycle(harness.context(), {
      ...lifecycleCommand(tenant.id, "publish-only-transition"),
      targetStatus: "disabled",
    })).rejects.toMatchObject({ code: OPEN_PLATFORM_ERROR_CODES.FORBIDDEN });
    await expect(harness.service.getTenant(harness.context(), { tenantId: defaultTenantId }))
      .rejects.toMatchObject({ code: OPEN_PLATFORM_ERROR_CODES.FORBIDDEN });
    const events = harness.audit.snapshot(defaultTenantId);
    expect(events.filter((event) => event.outcome === "denied").map((event) => event.action))
      .toEqual([
        "tenant.disable",
        "tenant.archive",
        "tenant.submitReview",
        "tenant.disable",
      ]);
  });

  it("keeps disable authority from archiving or publishing a resource", async () => {
    const bootstrap = createHarness("all", { tenantId: "tenant-disable-only" });
    const tenant = await bootstrap.createTenant("disable-only");
    await bootstrap.service.publish(
      bootstrap.context(),
      lifecycleCommand(tenant.id, "disable-only-bootstrap", "tenant-disable-only"),
    );
    const harness = createHarness(
      ["tenant.disable"],
      {
        tenantId: "tenant-disable-only",
        repositories: bootstrap.repositories,
        audit: bootstrap.audit,
      },
    );

    await expect(harness.service.publish(
      harness.context(),
      lifecycleCommand(tenant.id, "disable-only-publish", "tenant-disable-only"),
    )).rejects.toMatchObject({ code: OPEN_PLATFORM_ERROR_CODES.FORBIDDEN });
    await expect(harness.service.archive(
      harness.context(),
      lifecycleCommand(tenant.id, "disable-only-archive", "tenant-disable-only"),
    )).rejects.toMatchObject({ code: OPEN_PLATFORM_ERROR_CODES.FORBIDDEN });
    await expect(harness.service.deactivate(
      harness.context(),
      lifecycleCommand(tenant.id, "disable-only-disable", "tenant-disable-only"),
    )).resolves.toMatchObject({ status: "disabled" });
    await expect(harness.service.submitReview(
      harness.context(),
      lifecycleCommand(tenant.id, "disable-only-review", "tenant-disable-only"),
    )).rejects.toMatchObject({ code: OPEN_PLATFORM_ERROR_CODES.FORBIDDEN });
  });

  it("keeps archive authority from publishing or disabling a resource", async () => {
    const bootstrap = createHarness("all", { tenantId: "tenant-archive-only" });
    const tenant = await bootstrap.createTenant("archive-only");
    await bootstrap.service.publish(
      bootstrap.context(),
      lifecycleCommand(tenant.id, "archive-only-bootstrap", "tenant-archive-only"),
    );
    const harness = createHarness(
      ["tenant.archive"],
      {
        tenantId: "tenant-archive-only",
        repositories: bootstrap.repositories,
        audit: bootstrap.audit,
      },
    );

    await expect(harness.service.publish(
      harness.context(),
      lifecycleCommand(tenant.id, "archive-only-publish", "tenant-archive-only"),
    )).rejects.toMatchObject({ code: OPEN_PLATFORM_ERROR_CODES.FORBIDDEN });
    await expect(harness.service.deactivate(
      harness.context(),
      lifecycleCommand(tenant.id, "archive-only-disable", "tenant-archive-only"),
    )).rejects.toMatchObject({ code: OPEN_PLATFORM_ERROR_CODES.FORBIDDEN });
    await expect(harness.service.submitReview(
      harness.context(),
      lifecycleCommand(tenant.id, "archive-only-review", "tenant-archive-only"),
    )).rejects.toMatchObject({ code: OPEN_PLATFORM_ERROR_CODES.FORBIDDEN });
    await expect(harness.service.archive(
      harness.context(),
      lifecycleCommand(tenant.id, "archive-only-archive", "tenant-archive-only"),
    )).resolves.toMatchObject({ status: "archived" });
  });

  it("keeps submit-review authority independent from publish authority", async () => {
    const harness = createHarness(["tenant.create", "tenant.submitReview"]);
    const tenant = await harness.createTenant("review-only");

    await expect(harness.service.submitReview(
      harness.context(),
      lifecycleCommand(tenant.id, "review-only-submit"),
    )).resolves.toMatchObject({ status: "published" });
    await expect(harness.service.publish(
      harness.context(),
      lifecycleCommand(tenant.id, "review-only-publish"),
    )).rejects.toMatchObject({ code: OPEN_PLATFORM_ERROR_CODES.FORBIDDEN });
    await expect(harness.service.deactivate(
      harness.context(),
      lifecycleCommand(tenant.id, "review-only-disable"),
    )).rejects.toMatchObject({ code: OPEN_PLATFORM_ERROR_CODES.FORBIDDEN });
    await expect(harness.service.archive(
      harness.context(),
      lifecycleCommand(tenant.id, "review-only-archive"),
    )).rejects.toMatchObject({ code: OPEN_PLATFORM_ERROR_CODES.FORBIDDEN });
  });

  it("accepts republish and submit-review development permission aliases", async () => {
    const alias = createHarness(
      ["tenant.create", "tenant.republish"],
      { tenantId: "tenant-alias-publish" },
    );
    const aliasTenant = await alias.createTenant("alias-publish");

    await expect(alias.service.publish(
      alias.context(),
      lifecycleCommand(aliasTenant.id, "alias-publish", "tenant-alias-publish"),
    )).resolves.toMatchObject({ status: "published" });
    await expect(alias.service.archive(
      alias.context(),
      lifecycleCommand(aliasTenant.id, "alias-archive", "tenant-alias-publish"),
    )).rejects.toMatchObject({ code: OPEN_PLATFORM_ERROR_CODES.FORBIDDEN });
    await expect(alias.service.deactivate(
      alias.context(),
      lifecycleCommand(aliasTenant.id, "alias-disable", "tenant-alias-publish"),
    )).rejects.toMatchObject({ code: OPEN_PLATFORM_ERROR_CODES.FORBIDDEN });

    const review = createHarness(
      ["tenant.create", "tenant.submit-review"],
      { tenantId: "tenant-alias-review" },
    );
    const reviewTenant = await review.createTenant("alias-review");

    await expect(review.service.submitReview(
      review.context(),
      lifecycleCommand(reviewTenant.id, "alias-submit", "tenant-alias-review"),
    )).resolves.toMatchObject({ status: "published" });
    await expect(review.service.publish(
      review.context(),
      lifecycleCommand(reviewTenant.id, "alias-review-publish", "tenant-alias-review"),
    )).rejects.toMatchObject({ code: OPEN_PLATFORM_ERROR_CODES.FORBIDDEN });
    await expect(review.service.archive(
      review.context(),
      lifecycleCommand(reviewTenant.id, "alias-review-archive", "tenant-alias-review"),
    )).rejects.toMatchObject({ code: OPEN_PLATFORM_ERROR_CODES.FORBIDDEN });
  });

  it("never authorizes a fine-grained lifecycle command through the legacy update action", async () => {
    const legacy = createHarness(["tenant.create", "tenant.update"]);
    const tenant = await legacy.createTenant("legacy");

    await expect(legacy.service.publish(
      legacy.context(),
      lifecycleCommand(tenant.id, "legacy-publish"),
    )).rejects.toMatchObject({ code: OPEN_PLATFORM_ERROR_CODES.FORBIDDEN });
    await expect(legacy.service.deactivate(
      legacy.context(),
      lifecycleCommand(tenant.id, "legacy-disable"),
    )).rejects.toMatchObject({ code: OPEN_PLATFORM_ERROR_CODES.FORBIDDEN });
    await expect(legacy.service.archive(
      legacy.context(),
      lifecycleCommand(tenant.id, "legacy-archive"),
    )).rejects.toMatchObject({ code: OPEN_PLATFORM_ERROR_CODES.FORBIDDEN });
    await expect(legacy.service.submitReview(
      legacy.context(),
      lifecycleCommand(tenant.id, "legacy-review"),
    )).rejects.toMatchObject({ code: OPEN_PLATFORM_ERROR_CODES.FORBIDDEN });
    for (const targetStatus of ["published", "disabled", "archived"] as const) {
      await expect(legacy.service.transitionLifecycle(legacy.context(), {
        ...lifecycleCommand(tenant.id, `legacy-transition-${targetStatus}`),
        targetStatus,
      })).rejects.toMatchObject({ code: OPEN_PLATFORM_ERROR_CODES.FORBIDDEN });
    }
    expect(legacy.audit.snapshot(defaultTenantId).map((event) => event.action))
      .not.toContain("tenant.update");
  });

  it("maps every supported target status to its own action and rejects draft targets", async () => {
    expect(openPlatformLifecycleAuthorizationActionForStatus("published")).toBe("publish");
    expect(openPlatformLifecycleAuthorizationActionForStatus("disabled")).toBe("disable");
    expect(openPlatformLifecycleAuthorizationActionForStatus("archived")).toBe("archive");
    expect(openPlatformLifecycleAuthorizationActionForStatus("draft")).toBeUndefined();
    expect(openPlatformLifecycleAuthorizationActionForStatus("constructor")).toBeUndefined();
    expect(openPlatformLifecycleAuthorizationActionForStatus(undefined)).toBeUndefined();

    const spy = authorizationSpy();
    const issuer = createOpenPlatformRequestContextIssuer({
      issuerId: "lifecycle-authorization-tests",
      attestation: Object.freeze({ test: true }),
      clock: () => fixedNow,
    });
    const repositories = new InMemoryOpenPlatformRepositories({ clock: () => fixedNow });
    const service = createOpenPlatformService({
      mode: "test",
      authorization: spy.port,
      repositories,
      clock: () => fixedNow,
    } satisfies OpenPlatformServiceOptions);
    const scopedService = (scopedTenantId: string) => {
      const context = () => issuer.issueDevelopment({
        tenantId: scopedTenantId,
        actorId: "actor-lifecycle",
        requestId: `lifecycle-spy-${scopedTenantId}`,
      });
      return {
        service,
        context,
        createTenant(name: string) {
          return service.createTenant(context(), {
            tenantId: scopedTenantId,
            name,
            idempotencyKey: `${scopedTenantId}-create`,
          });
        },
      };
    };
    const commands = scopedService(defaultTenantId);
    const transitions = scopedService("tenant-lifecycle-spy");

    const tenant = await commands.createTenant("spy tenant");
    await commands.service.submitReview(
      commands.context(),
      lifecycleCommand(tenant.id, "spy-submit"),
    );
    await commands.service.deactivate(
      commands.context(),
      lifecycleCommand(tenant.id, "spy-disable"),
    );
    await commands.service.publish(
      commands.context(),
      lifecycleCommand(tenant.id, "spy-publish"),
    );
    await commands.service.archive(
      commands.context(),
      lifecycleCommand(tenant.id, "spy-archive"),
    );

    const transitioned = await transitions.createTenant("spy transition tenant");
    for (const targetStatus of ["published", "disabled", "archived"] as const) {
      await transitions.service.transitionLifecycle(transitions.context(), {
        ...lifecycleCommand(
          transitioned.id,
          `spy-transition-${targetStatus}`,
          "tenant-lifecycle-spy",
        ),
        targetStatus,
      });
    }
    await expect(transitions.service.transitionLifecycle(transitions.context(), {
      ...lifecycleCommand(
        transitioned.id,
        "spy-transition-draft",
        "tenant-lifecycle-spy",
      ),
      targetStatus: "draft",
    })).rejects.toMatchObject({ code: OPEN_PLATFORM_ERROR_CODES.VALIDATION_ERROR });

    expect(spy.actions).toEqual([
      "tenant.create:none",
      `tenant.submitReview:${tenant.id}`,
      `tenant.disable:${tenant.id}`,
      `tenant.publish:${tenant.id}`,
      `tenant.archive:${tenant.id}`,
      "tenant.create:none",
      `tenant.publish:${transitioned.id}`,
      `tenant.disable:${transitioned.id}`,
      `tenant.archive:${transitioned.id}`,
    ]);
  });

  it("resolves development permissions through canonical lifecycle actions", () => {
    const port = createDevelopmentOpenPlatformAuthorization([
      "tenant.republish",
      "tenant.submit-review",
    ]);
    const context = createOpenPlatformRequestContextIssuer({
      issuerId: "lifecycle-authorization-tests",
      attestation: Object.freeze({ test: true }),
      clock: () => fixedNow,
    }).issueDevelopment({
      tenantId: defaultTenantId,
      actorId: "actor-lifecycle",
      requestId: "permission-fixture",
    });
    const authorized = (action: "publish" | "republish" | "submitReview" | "submit-review" | "disable" | "archive") =>
      port.authorize({ context, tenantId: defaultTenantId, resource: "tenant", action });

    expect(permissionFor({
      context,
      tenantId: defaultTenantId,
      resource: "tenant",
      action: "republish",
    })).toBe("tenant.publish");
    expect(authorized("publish")).toBe(true);
    expect(authorized("republish")).toBe(true);
    expect(authorized("submitReview")).toBe(true);
    expect(authorized("submit-review")).toBe(true);
    expect(authorized("disable")).toBe(false);
    expect(authorized("archive")).toBe(false);
    expect(() => createDevelopmentOpenPlatformAuthorization([
      "tenant.publish-extra-",
    ] as unknown as OpenPlatformPermission[])).toThrow();
  });

  it("keeps denied and successful lifecycle audit writes tenant and resource scoped", async () => {
    const harness = createHarness(["tenant.create", "tenant.publish"]);
    const tenant = await harness.createTenant("audit");

    await harness.service.publish(
      harness.context(),
      lifecycleCommand(tenant.id, "audit-publish"),
    );
    await expect(harness.service.archive(
      harness.context(),
      lifecycleCommand(tenant.id, "audit-archive"),
    )).rejects.toMatchObject({ code: OPEN_PLATFORM_ERROR_CODES.FORBIDDEN });

    const events = harness.audit.snapshot(defaultTenantId);
    expect(events.every((event) => event.tenantId === defaultTenantId)).toBe(true);
    expect(events.map((event) => ({
      action: event.action,
      outcome: event.outcome,
      type: event.target.type,
      id: event.target.id,
    }))).toEqual([
      {
        action: "tenant.create",
        outcome: "success",
        type: "tenant",
        id: tenant.id,
      },
      {
        action: "lifecycle.transition",
        outcome: "success",
        type: "tenant",
        id: tenant.id,
      },
      {
        action: "tenant.archive",
        outcome: "denied",
        type: "tenant",
        id: tenant.id,
      },
    ]);
    expect(await harness.audit.verifyChain(defaultTenantId)).toBe(true);
  });
});
