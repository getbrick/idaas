import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  OPEN_PLATFORM_CLIENT_KINDS,
  OPEN_PLATFORM_CREDENTIAL_STATUSES,
  OPEN_PLATFORM_DEFAULT_PAGE_SIZE,
  OPEN_PLATFORM_DOMAIN_EVENT_ACTIONS,
  OPEN_PLATFORM_DOMAIN_EVENT_CATALOG,
  OPEN_PLATFORM_DOMAIN_EVENT_RESOURCES,
  OPEN_PLATFORM_DOMAIN_EVENT_SCHEMA_VERSION,
  OPEN_PLATFORM_ERROR_CODES,
  OPEN_PLATFORM_LIFECYCLE_AUTHORIZATION_ACTIONS,
  OPEN_PLATFORM_LIFECYCLE_EVENTS,
  OPEN_PLATFORM_LIFECYCLE_PERMISSION_ACTIONS,
  OPEN_PLATFORM_LIFECYCLE_PERMISSION_RESOURCES,
  OPEN_PLATFORM_LIFECYCLE_PERMISSIONS,
  OPEN_PLATFORM_LIFECYCLE_STATUSES,
  OPEN_PLATFORM_MAX_PAGE_SIZE,
  OPEN_PLATFORM_SUBSCRIPTION_BILLING_STATUSES,
  OPEN_PLATFORM_WEBHOOK_EVENTS,
  OPEN_PLATFORM_WEBHOOK_EVENT_SCHEMA_VERSION,
  OPEN_PLATFORM_WEBHOOK_SECRET_VERSION_HEADER,
  OPEN_PLATFORM_WEBHOOK_SIGNATURE_HEADER,
  OPEN_PLATFORM_WEBHOOK_SIGNATURE_VERSION,
  OpenPlatformContractError,
  canTransitionOpenPlatformApplication,
  canTransitionOpenPlatformCredential,
  canonicalOpenPlatformLifecycleAuthorizationAction,
  createOpenPlatformError,
  formatOpenPlatformScopes,
  getOpenPlatformLifecycleTransition,
  isOpenPlatformDomainEventName,
  isValidOpenPlatformRedirectUri,
  isValidOpenPlatformSlug,
  mapControlPlaneApiVersionStatus,
  mapControlPlaneApplicationStatus,
  mapControlPlaneCredentialStatus,
  mapControlPlaneLifecycleStatus,
  mapControlPlaneSubscriptionStatus,
  mapOpenPlatformLifecycleToSubscriptionBillingStatus,
  normalizeOpenPlatformPageRequest,
  normalizeOpenPlatformScopes,
  openPlatformDomainEventNameParts,
  openPlatformLifecyclePermission,
  openPlatformLifecyclePermissionForEvent,
  openPlatformLifecyclePermissionForStatus,
  parseOpenPlatformScopes,
  resolveOpenPlatformCredentialStatus,
  toOpenPlatformCredentialDto,
  transitionOpenPlatformApplication,
  transitionOpenPlatformCredential,
  transitionOpenPlatformSubscription,
  validateOpenPlatformRedirectUris,
  validateOpenPlatformRedirectUri,
  validateOpenPlatformSlug,
} from "../src/open-platform.js";
import type {
  OpenPlatformApiProductDto,
  OpenPlatformApiResourceRecord,
  OpenPlatformApiVersionRecord,
  OpenPlatformApplicationRecord,
  OpenPlatformAuditEventRecord,
  OpenPlatformClientDto,
  OpenPlatformClientRecord,
  OpenPlatformControlPlaneCredentialSource,
  OpenPlatformCredentialDto,
  OpenPlatformCredentialIssueResultDto,
  OpenPlatformCredentialRecord,
  OpenPlatformCredentialRotationResultDto,
  OpenPlatformDeveloperOrganizationRecord,
  OpenPlatformDomainEvent,
  OpenPlatformEnvironmentRecord,
  OpenPlatformErrorContext,
  OpenPlatformLifecyclePermissionAction,
  OpenPlatformLifecycleStatus,
  OpenPlatformNativeClientRecord,
  OpenPlatformPage,
  OpenPlatformServiceClientDto,
  OpenPlatformSubscriptionBillingStatus,
  OpenPlatformSubscriptionRecord,
  OpenPlatformTenantRecord,
  OpenPlatformUsageRecord,
  OpenPlatformWebhookDeliveryRecord,
  OpenPlatformWebhookRecord,
  OpenPlatformWebClientDto,
} from "../src/open-platform.js";

type Assert<T extends true> = T;

type _ServiceClientRedirectUrisAreNever = Assert<
  Exclude<OpenPlatformServiceClientDto["redirectUris"], undefined> extends never ? true : false
>;
type _ServiceClientPostLogoutRedirectUrisAreNever = Assert<
  Exclude<OpenPlatformServiceClientDto["postLogoutRedirectUris"], undefined> extends never ? true : false
>;
type _PublicCredentialHasNoSecretFields = Assert<
  "secret" extends keyof OpenPlatformCredentialDto
    ? false
    : "digest" extends keyof OpenPlatformCredentialDto
      ? false
      : "reference" extends keyof OpenPlatformCredentialDto
        ? false
        : true
>;
type _InternalCredentialHasSecretFields = Assert<
  "secret" extends keyof OpenPlatformCredentialRecord ? true : false
>;

const createdAt = "2026-01-01T00:00:00.000Z";
const periodStart = "2026-01-01T00:00:00.000Z";
const periodEnd = "2026-02-01T00:00:00.000Z";

function assertContractError(
  operation: () => unknown,
  code: (typeof OPEN_PLATFORM_ERROR_CODES)[keyof typeof OPEN_PLATFORM_ERROR_CODES],
): void {
  assert.throws(operation, (error: unknown) => {
    assert.ok(error instanceof OpenPlatformContractError);
    assert.equal(error.code, code);
    return true;
  });
}

describe("open platform contract", () => {
  it("keeps canonical lifecycle and credential vocabularies stable", () => {
    assert.deepEqual(OPEN_PLATFORM_CLIENT_KINDS, ["web", "native", "service"]);
    assert.deepEqual(OPEN_PLATFORM_LIFECYCLE_STATUSES, [
      "draft",
      "published",
      "disabled",
      "archived",
    ]);
    assert.deepEqual(OPEN_PLATFORM_CREDENTIAL_STATUSES, [
      "pending",
      "active",
      "rotating",
      "rotated",
      "expired",
      "revoked",
    ]);
    assert.deepEqual(OPEN_PLATFORM_SUBSCRIPTION_BILLING_STATUSES, [
      "trialing",
      "active",
      "past_due",
      "suspended",
      "canceled",
      "expired",
    ]);
  });

  it("keeps webhook signature and audit contract fields stable", () => {
    assert.equal(OPEN_PLATFORM_WEBHOOK_SIGNATURE_HEADER, "X-Webhook-Signature");
    assert.equal(OPEN_PLATFORM_WEBHOOK_SECRET_VERSION_HEADER, "X-Webhook-Secret-Version");
    assert.equal(OPEN_PLATFORM_WEBHOOK_SIGNATURE_VERSION, "v1");
    assert.equal(OPEN_PLATFORM_WEBHOOK_EVENT_SCHEMA_VERSION, "open-platform.webhook-event.v1");
    assert.equal(OPEN_PLATFORM_DOMAIN_EVENT_SCHEMA_VERSION, "open-platform.domain-event.v1");
  });

  it("publishes one stable domain event catalog for every open platform resource", () => {
    assert.deepEqual(OPEN_PLATFORM_DOMAIN_EVENT_RESOURCES, [
      "tenant",
      "developer_organization",
      "application",
      "client",
      "credential",
      "api_product",
      "api_version",
      "subscription",
      "scope_grant",
      "usage",
      "commerce_listing",
      "commerce_partner",
      "commerce_commission",
      "commerce_account",
      "commerce_invoice",
      "commerce_dispute",
      "compliance_data_asset",
      "compliance_consent_record",
      "compliance_privacy_request",
      "compliance_retention_policy",
      "compliance_cross_border_assessment",
      "compliance_vendor",
    ]);
    assert.deepEqual(OPEN_PLATFORM_DOMAIN_EVENT_ACTIONS, [
      "created",
      "updated",
      "status_changed",
      "published",
      "deprecated",
      "threshold_reached",
      "granted",
      "withdrawn",
      "decided",
      "executed",
      "verified",
    ]);
    const stableName = /^[a-z][a-z0-9]*(?:_[a-z0-9]+)*\.[a-z][a-z0-9]*(?:_[a-z0-9]+)*$/u;
    const flattened = OPEN_PLATFORM_DOMAIN_EVENT_RESOURCES.flatMap((resource) =>
      OPEN_PLATFORM_DOMAIN_EVENT_CATALOG[resource].map((action) => `${resource}.${action}`),
    );
    assert.deepEqual([...OPEN_PLATFORM_WEBHOOK_EVENTS], flattened);
    assert.equal(new Set(OPEN_PLATFORM_WEBHOOK_EVENTS).size, OPEN_PLATFORM_WEBHOOK_EVENTS.length);
    for (const event of OPEN_PLATFORM_WEBHOOK_EVENTS) {
      assert.match(event, stableName);
      const parts = openPlatformDomainEventNameParts(event);
      assert.equal(parts.resource, event.slice(0, event.indexOf(".")));
      assert.equal(parts.action, event.slice(event.indexOf(".") + 1));
      assert.ok(
        (OPEN_PLATFORM_DOMAIN_EVENT_CATALOG[parts.resource] as readonly string[]).includes(
          parts.action,
        ),
      );
    }
  });

  it("keeps every previously published domain event name in the catalog", () => {
    const legacy: readonly OpenPlatformDomainEvent[] = [
      "application.created",
      "application.updated",
      "application.status_changed",
      "client.created",
      "client.updated",
      "client.status_changed",
      "credential.status_changed",
      "api_product.published",
      "api_version.published",
      "api_version.deprecated",
      "subscription.status_changed",
      "usage.threshold_reached",
    ];
    for (const event of legacy) {
      assert.ok(isOpenPlatformDomainEventName(event), event);
      assert.ok((OPEN_PLATFORM_WEBHOOK_EVENTS as readonly string[]).includes(event), event);
    }
    const coverage: Record<string, readonly string[]> = {
      tenant: ["created", "updated", "status_changed"],
      developer_organization: ["created", "updated", "status_changed"],
      application: ["created", "updated", "status_changed"],
      client: ["created", "updated", "status_changed"],
      credential: ["created", "updated", "status_changed"],
      api_product: ["created", "updated", "published", "deprecated", "status_changed"],
      api_version: ["created", "updated", "published", "deprecated", "status_changed"],
      subscription: ["created", "updated", "status_changed"],
      scope_grant: ["created", "updated", "status_changed"],
      usage: ["threshold_reached"],
      commerce_listing: ["created", "updated", "status_changed", "deprecated"],
      commerce_partner: ["created", "updated", "status_changed"],
      commerce_commission: ["created", "updated", "status_changed"],
      commerce_account: ["created", "updated", "status_changed"],
      commerce_invoice: ["created", "updated", "status_changed"],
      commerce_dispute: ["created", "updated", "status_changed", "decided"],
      compliance_data_asset: ["created", "updated", "status_changed"],
      compliance_consent_record: ["created", "status_changed", "granted", "withdrawn"],
      compliance_privacy_request: ["created", "status_changed", "verified", "decided"],
      compliance_retention_policy: ["created", "status_changed", "executed"],
      compliance_cross_border_assessment: ["created", "status_changed", "decided"],
      compliance_vendor: ["created", "updated", "status_changed"],
    };
    assert.deepEqual({ ...OPEN_PLATFORM_DOMAIN_EVENT_CATALOG }, coverage);
  });

  it("rejects unknown, partial, and non domain event names", () => {
    for (const rejected of [
      "application.deleted",
      "application.created ",
      "application",
      "",
      "APPLICATION.CREATED",
      "usage.recorded",
      "webhook.delivered",
      42,
      null,
      undefined,
    ]) {
      assert.equal(isOpenPlatformDomainEventName(rejected), false, String(rejected));
    }
    assert.equal(isOpenPlatformDomainEventName("usage.threshold_reached"), true);
    assert.equal(isOpenPlatformDomainEventName("scope_grant.status_changed"), true);
  });

  it("parses, normalizes, and formats canonical OAuth scopes", () => {
    assert.deepEqual(parseOpenPlatformScopes(" orders.read openid  orders.read "), [
      "openid",
      "orders.read",
    ]);
    assert.deepEqual(normalizeOpenPlatformScopes(["profile", "openid", "profile"]), [
      "openid",
      "profile",
    ]);
    assert.equal(formatOpenPlatformScopes(["profile", "openid"]), "openid profile");

    const invalidValues: readonly (string | readonly string[])[] = [
      "openid\tprofile",
      'openid"profile',
      "openid\\profile",
      "openidé",
      "a".repeat(129),
      Array.from({ length: 101 }, (_, index) => `scope-${index}`),
      Array.from({ length: 101 }, () => "duplicate").join(" "),
      ["openid profile"],
      [" openid"],
      ["openid "],
      ["openid\tprofile"],
      [42 as never],
      [],
    ];
    for (const value of invalidValues) {
      assertContractError(
        () => normalizeOpenPlatformScopes(value as string | readonly string[]),
        OPEN_PLATFORM_ERROR_CODES.INVALID_SCOPE,
      );
    }
  });

  it("validates stable lowercase slugs", () => {
    assert.equal(isValidOpenPlatformSlug("partner-api"), true);
    assert.equal(validateOpenPlatformSlug("api2"), "api2");
    for (const value of ["Partner", "partner_api", "-partner", "partner-", "a".repeat(64)]) {
      assert.equal(isValidOpenPlatformSlug(value), false);
      assertContractError(
        () => validateOpenPlatformSlug(value),
        OPEN_PLATFORM_ERROR_CODES.INVALID_SLUG,
      );
    }
  });

  it("accepts only secure Web and Native redirect URIs", () => {
    assert.equal(
      validateOpenPlatformRedirectUri("https://client.example.test/oauth/callback", {
        allowedHosts: ["CLIENT.EXAMPLE.TEST"],
      }),
      "https://client.example.test/oauth/callback",
    );
    assert.equal(
      validateOpenPlatformRedirectUri("http://127.0.0.1:3000/oauth/callback", {
        clientKind: "native",
        allowLoopbackHttp: true,
      }),
      "http://127.0.0.1:3000/oauth/callback",
    );
    assert.equal(
      validateOpenPlatformRedirectUri("com.example.app:/oauth/callback", {
        clientKind: "native",
        allowedCustomSchemes: ["com.example.app"],
      }),
      "com.example.app:/oauth/callback",
    );
    assert.deepEqual(
      validateOpenPlatformRedirectUris([
        "https://client.example.test/callback",
        "https://client.example.test/oidc/callback",
      ]),
      ["https://client.example.test/callback", "https://client.example.test/oidc/callback"],
    );

    const rejected = [
      "http://client.example.test/callback",
      "http://127.0.0.1:3000/callback",
      "com.example.app:/callback",
      "javascript:alert(1)",
      "https://user:password@client.example.test/callback",
      "https://client.example.test/callback#fragment",
      "https://client.example.test/callback%0dheader",
    ];
    for (const value of rejected) {
      assert.equal(isValidOpenPlatformRedirectUri(value), false);
      assertContractError(
        () => validateOpenPlatformRedirectUri(value),
        OPEN_PLATFORM_ERROR_CODES.INVALID_REDIRECT_URI,
      );
    }
    assertContractError(
      () => validateOpenPlatformRedirectUri("https://attacker.example.test/callback", {
        allowedHosts: ["client.example.test"],
      }),
      OPEN_PLATFORM_ERROR_CODES.INVALID_REDIRECT_URI,
    );
    assertContractError(
      () => validateOpenPlatformRedirectUris([
        "https://client.example.test/callback",
        "https://client.example.test/callback",
      ]),
      OPEN_PLATFORM_ERROR_CODES.INVALID_REDIRECT_URI,
    );
  });

  it("exposes stable, independent fine-grained lifecycle permissions", () => {
    assert.deepEqual(OPEN_PLATFORM_LIFECYCLE_PERMISSIONS, [
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
    ]);
    assert.equal(new Set(OPEN_PLATFORM_LIFECYCLE_PERMISSIONS).size, 20);
    for (const permission of OPEN_PLATFORM_LIFECYCLE_PERMISSIONS) {
      assert.match(permission, /^open:[a-z][a-z-]*:[a-z][a-z-]*$/u);
      const [, , action] = permission.split(":");
      assert.equal(
        (OPEN_PLATFORM_LIFECYCLE_PERMISSION_ACTIONS as readonly string[]).includes(action ?? ""),
        true,
      );
      assert.equal(
        (OPEN_PLATFORM_LIFECYCLE_PERMISSION_RESOURCES as readonly string[]).includes(
          permission.split(":")[1] ?? "",
        ),
        true,
      );
    }
    assert.equal(
      openPlatformLifecyclePermission("application", "submit-review"),
      "open:application:submit-review",
    );
    assert.equal(
      OPEN_PLATFORM_LIFECYCLE_PERMISSIONS.includes("open:application:write"),
      false,
    );
  });

  it("keeps lifecycle events, statuses, and authorization actions aligned", () => {
    assert.deepEqual(OPEN_PLATFORM_LIFECYCLE_STATUSES, [
      "draft",
      "published",
      "disabled",
      "archived",
    ]);
    for (const status of OPEN_PLATFORM_LIFECYCLE_STATUSES) {
      const action = openPlatformLifecyclePermissionForStatus(status);
      if (status === "draft") {
        assert.equal(action, undefined);
      } else {
        assert.equal(
          OPEN_PLATFORM_LIFECYCLE_PERMISSION_ACTIONS.includes(
            action as OpenPlatformLifecyclePermissionAction,
          ),
          true,
        );
      }
      for (const event of OPEN_PLATFORM_LIFECYCLE_EVENTS) {
        const transition = getOpenPlatformLifecycleTransition(status, event);
        if (transition === undefined) continue;
        assert.equal(
          openPlatformLifecyclePermissionForStatus(transition.to),
          openPlatformLifecyclePermissionForEvent(event),
        );
      }
    }
    assert.equal(openPlatformLifecyclePermissionForEvent("publish"), "publish");
    assert.equal(openPlatformLifecyclePermissionForEvent("disable"), "disable");
    assert.equal(openPlatformLifecyclePermissionForEvent("archive"), "archive");
    assert.equal(openPlatformLifecyclePermissionForEvent("republish"), "publish");
    assert.deepEqual(OPEN_PLATFORM_LIFECYCLE_AUTHORIZATION_ACTIONS, [
      "publish",
      "disable",
      "archive",
      "submitReview",
    ]);
    assert.equal(
      canonicalOpenPlatformLifecycleAuthorizationAction("republish"),
      "publish",
    );
    assert.equal(
      canonicalOpenPlatformLifecycleAuthorizationAction("submit-review"),
      "submitReview",
    );
    assert.equal(canonicalOpenPlatformLifecycleAuthorizationAction("submitReview"), "submitReview");
    assert.equal(canonicalOpenPlatformLifecycleAuthorizationAction("update"), undefined);
    assert.equal(canonicalOpenPlatformLifecycleAuthorizationAction("delete"), undefined);
  });

  it("maps control-plane lifecycle, application, API, subscription, and credential states", () => {
    const lifecycle: readonly OpenPlatformLifecycleStatus[] = [
      "draft",
      "published",
      "disabled",
      "archived",
    ];
    for (const status of lifecycle) {
      assert.equal(mapControlPlaneLifecycleStatus(status), status);
      assert.equal(mapControlPlaneApplicationStatus(status), status);
      assert.equal(mapControlPlaneSubscriptionStatus(status), status);
    }
    assert.equal(transitionOpenPlatformApplication("draft", "publish"), "published");
    assert.equal(transitionOpenPlatformApplication("published", "disable"), "disabled");
    assert.equal(transitionOpenPlatformApplication("disabled", "republish"), "published");
    assert.equal(canTransitionOpenPlatformApplication("archived", "republish"), false);
    assertContractError(
      () => transitionOpenPlatformApplication("archived", "republish"),
      OPEN_PLATFORM_ERROR_CODES.INVALID_STATE_TRANSITION,
    );

    assert.equal(mapControlPlaneApiVersionStatus("draft"), "draft");
    assert.equal(mapControlPlaneApiVersionStatus("published"), "active");
    assert.equal(mapControlPlaneApiVersionStatus("disabled"), "deprecated");
    assert.equal(mapControlPlaneApiVersionStatus("archived"), "retired");
    assert.equal(mapOpenPlatformLifecycleToSubscriptionBillingStatus("draft"), "trialing");
    assert.equal(mapOpenPlatformLifecycleToSubscriptionBillingStatus("published"), "active");
    assert.equal(mapOpenPlatformLifecycleToSubscriptionBillingStatus("disabled"), "suspended");
    assert.equal(mapOpenPlatformLifecycleToSubscriptionBillingStatus("archived"), "canceled");

    for (const status of ["active", "rotating", "rotated", "expired", "revoked"] as const) {
      assert.equal(mapControlPlaneCredentialStatus(status), status);
    }
    assert.equal(transitionOpenPlatformCredential("active", "rotate"), "rotating");
    assert.equal(transitionOpenPlatformCredential("rotating", "complete"), "active");
    assert.equal(transitionOpenPlatformCredential("active", "mark_rotated"), "rotated");
    assert.equal(
      resolveOpenPlatformCredentialStatus(
        "active",
        "2025-12-31T23:59:59.000Z",
        "2026-01-01T00:00:00.000Z",
      ),
      "expired",
    );
    assert.equal(
      resolveOpenPlatformCredentialStatus(
        "rotated",
        "2025-12-31T23:59:59.000Z",
        "2026-01-01T00:00:00.000Z",
      ),
      "rotated",
    );
    assert.equal(canTransitionOpenPlatformCredential("rotated", "rotate"), false);
    assertContractError(
      () => mapControlPlaneCredentialStatus("unknown"),
      OPEN_PLATFORM_ERROR_CODES.INVALID_STATUS,
    );

    assert.equal(transitionOpenPlatformSubscription("active", "mark_past_due"), "past_due");
    assert.equal(transitionOpenPlatformSubscription("past_due", "resume"), "active");
    assert.equal(transitionOpenPlatformSubscription("active", "cancel"), "canceled");
  });

  it("normalizes safe cursor pagination bounds", () => {
    assert.deepEqual(normalizeOpenPlatformPageRequest(), { limit: OPEN_PLATFORM_DEFAULT_PAGE_SIZE });
    assert.deepEqual(normalizeOpenPlatformPageRequest({ cursor: "cursor_01", limit: "50" }), {
      cursor: "cursor_01",
      limit: 50,
    });
    for (const value of [
      { limit: 0 },
      { limit: OPEN_PLATFORM_MAX_PAGE_SIZE + 1 },
      { limit: 1.5 },
      { limit: "01" },
      { cursor: "bad\ncursor" },
      [],
    ]) {
      assertContractError(
        () => normalizeOpenPlatformPageRequest(value),
        OPEN_PLATFORM_ERROR_CODES.INVALID_ARGUMENT,
      );
    }
  });

  it("creates fixed, non-echoing safe errors", () => {
    const response = createOpenPlatformError(OPEN_PLATFORM_ERROR_CODES.INVALID_ARGUMENT, {
      field: "client.redirectUris[0]",
      requestId: "req_01",
      issues: [{ code: OPEN_PLATFORM_ERROR_CODES.INVALID_REDIRECT_URI, field: "redirectUri" }],
    });
    assert.deepEqual(response, {
      error: {
        code: "INVALID_ARGUMENT",
        status: 400,
        retryable: false,
        message: "The open platform request is invalid.",
        field: "client.redirectUris[0]",
        issues: [{ code: "INVALID_REDIRECT_URI", field: "redirectUri" }],
      },
      requestId: "req_01",
    });

    const unsafeContext = {
      field: "raw secret value",
      requestId: "raw secret value",
    } as unknown as OpenPlatformErrorContext;
    const safeResponse = createOpenPlatformError(
      OPEN_PLATFORM_ERROR_CODES.CREDENTIAL_EXPOSED,
      unsafeContext,
    );
    assert.deepEqual(safeResponse, {
      error: {
        code: "CREDENTIAL_EXPOSED",
        status: 400,
        retryable: false,
        message: "Credential material must not be supplied to this contract.",
      },
    });
    assert.equal(JSON.stringify(safeResponse).includes("raw secret value"), false);
    assert.equal("details" in safeResponse.error, false);
  });

  it("models tenant, organization, application, environment, and all client kinds", () => {
    const tenant: OpenPlatformTenantRecord = {
      contractVersion: 1,
      id: "tenant-01",
      name: "Tenant",
      slug: "tenant",
      status: "published",
      createdAt,
      region: "cn-1",
      settings: { dataResidency: "required" },
    };
    const organization: OpenPlatformDeveloperOrganizationRecord = {
      contractVersion: 1,
      id: "organization-01",
      tenantId: tenant.id,
      name: "Developer",
      slug: "developer",
      status: "published",
      verificationStatus: "verified",
      createdAt,
      metadata: {},
    };
    const application: OpenPlatformApplicationRecord = {
      contractVersion: 1,
      id: "application-01",
      tenantId: tenant.id,
      developerOrganizationId: organization.id,
      name: "Orders",
      slug: "orders",
      status: "published",
      environmentIds: ["environment-01"],
      apiProductIds: ["product-01"],
      createdAt,
      settings: {},
      metadata: { tier: "standard" },
    };
    const environment: OpenPlatformEnvironmentRecord = {
      contractVersion: 1,
      id: "environment-01",
      applicationId: application.id,
      name: "Production",
      slug: "production",
      status: "published",
      region: "cn-1",
      baseUrl: "https://api.example.test",
      createdAt,
      isolationLevel: "shared",
      configuration: {},
    };
    const identity = {
      id: "client-record-01",
      tenantId: tenant.id,
      developerOrganizationId: organization.id,
      applicationId: application.id,
      environmentId: environment.id,
      clientId: "orders-service",
      name: "Orders service",
      status: "active" as const,
      allowedScopes: ["orders.read", "orders.write"],
      createdAt,
    };
    const webClient: OpenPlatformWebClientDto = {
      ...identity,
      kind: "web",
      redirectUris: ["https://client.example.test/callback"],
      postLogoutRedirectUris: [],
      tokenEndpointAuthMethod: "private_key_jwt",
      requirePkce: true,
    };
    const nativeClient: OpenPlatformNativeClientRecord = {
      ...identity,
      id: "client-record-02",
      clientId: "orders-native",
      kind: "native",
      redirectUris: ["com.example.orders:/oauth/callback"],
      postLogoutRedirectUris: [],
      tokenEndpointAuthMethod: "none",
      requirePkce: true,
    };
    const serviceClient: OpenPlatformServiceClientDto = {
      ...identity,
      id: "client-record-03",
      clientId: "orders-worker",
      kind: "service",
      serviceAccountId: "service-orders",
      tokenEndpointAuthMethod: "client_secret_basic",
    };
    const client: OpenPlatformClientRecord = {
      ...identity,
      kind: "service",
      serviceAccountId: "service-orders",
      tokenEndpointAuthMethod: "private_key_jwt",
      credentialId: "credential-01",
    };
    const discriminatedClient: OpenPlatformClientDto = serviceClient;

    assert.equal(tenant.slug, "tenant");
    assert.equal(organization.tenantId, tenant.id);
    assert.equal(application.environmentIds[0], environment.id);
    assert.equal(webClient.requirePkce, true);
    assert.equal(nativeClient.redirectUris[0], "com.example.orders:/oauth/callback");
    assert.equal(discriminatedClient.kind, "service");
    assert.equal(client.kind, "service");
  });

  it("models APIs, credentials, subscriptions, usage, webhooks, audit, and pages", () => {
    const resource: OpenPlatformApiResourceRecord = {
      contractVersion: 1,
      id: "resource-01",
      apiVersionId: "version-01",
      name: "List orders",
      method: "GET",
      pathTemplate: "/v1/orders",
      scopes: ["orders.read"],
      idempotent: true,
      createdAt,
      tenantId: "tenant-01",
      developerOrganizationId: "organization-01",
      applicationId: "application-01",
      apiProductId: "product-01",
      createdByUserId: "user-01",
    };
    const version: OpenPlatformApiVersionRecord = {
      contractVersion: 1,
      id: "version-01",
      apiProductId: "product-01",
      version: "2026-01-01",
      status: "published",
      releaseStatus: "active",
      basePath: "/v1",
      resourceIds: [resource.id],
      scopes: ["orders.read"],
      releasedAt: createdAt,
      createdAt,
      tenantId: "tenant-01",
      developerOrganizationId: "organization-01",
      applicationId: "application-01",
    };
    const product: OpenPlatformApiProductDto = {
      contractVersion: 1,
      id: "product-01",
      applicationId: "application-01",
      name: "Orders API",
      slug: "orders-api",
      status: "published",
      versions: [version],
      scopes: ["orders.read"],
      createdAt,
    };
    const credential: OpenPlatformCredentialRecord = {
      contractVersion: 1,
      id: "credential-01",
      tenantId: "tenant-01",
      developerOrganizationId: "organization-01",
      applicationId: "application-01",
      environmentId: "environment-01",
      clientId: "orders-service",
      name: "Orders service credential",
      kind: "client_secret",
      status: "active",
      scopes: ["orders.read"],
      keyPrefix: "secret_live_",
      lastFour: "1234",
      version: 2,
      createdAt,
      secret: {
        digest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        reference: "vault://credential-01",
      },
      createdByUserId: "user-01",
    };
    const credentialProjection: OpenPlatformControlPlaneCredentialSource = {
      id: credential.id,
      tenantId: credential.tenantId,
      applicationId: credential.applicationId,
      environmentId: credential.environmentId,
      name: credential.name,
      status: credential.status,
      scopes: credential.scopes,
      secret: credential.secret,
      fingerprint: "sha256:abcdef123456",
      version: credential.version,
      createdAt: credential.createdAt,
    };
    const credentialDto: OpenPlatformCredentialDto = toOpenPlatformCredentialDto(
      credentialProjection,
      { developerOrganizationId: "organization-01", now: createdAt },
    );
    const credentialIssue: OpenPlatformCredentialIssueResultDto = {
      credential: credentialDto,
      secret: { credentialId: credential.id, value: "one-time-credential-value" },
    };
    const credentialRotation: OpenPlatformCredentialRotationResultDto = {
      credential: credentialDto,
      previousCredential: { ...credentialDto, status: "rotated" },
      secret: { credentialId: credential.id, value: "one-time-rotation-value" },
    };
    const subscriptionBillingStatus: OpenPlatformSubscriptionBillingStatus = "active";
    const subscription: OpenPlatformSubscriptionRecord = {
      contractVersion: 1,
      id: "subscription-01",
      tenantId: "tenant-01",
      developerOrganizationId: "organization-01",
      applicationId: "application-01",
      apiProductId: product.id,
      apiVersionId: version.id,
      name: "Orders production",
      scopes: ["orders.read"],
      planId: "plan-standard",
      status: "published",
      billingStatus: subscriptionBillingStatus,
      quantity: 1,
      currentPeriodStart: periodStart,
      currentPeriodEnd: periodEnd,
      cancelAtPeriodEnd: false,
      createdAt,
      billingAccountReference: "billing-account-01",
      externalSubscriptionId: "external-subscription-01",
      metadata: {},
    };
    const usage: OpenPlatformUsageRecord = {
      contractVersion: 1,
      tenantId: "tenant-01",
      developerOrganizationId: "organization-01",
      subscriptionId: subscription.id,
      metric: "requests",
      aggregation: "sum",
      quantity: 1200,
      unit: "request",
      periodStart,
      periodEnd,
      recordedAt: periodEnd,
      dimensions: { environmentId: "environment-01" },
      sourceEventId: "usage-event-01",
    };
    const webhook: OpenPlatformWebhookRecord = {
      contractVersion: 1,
      id: "webhook-01",
      tenantId: "tenant-01",
      developerOrganizationId: "organization-01",
      applicationId: "application-01",
      environmentId: "environment-01",
      name: "Order events",
      endpointUrl: "https://client.example.test/webhooks/orders",
      status: "active",
      events: ["application.status_changed"],
      signingAlgorithm: "hmac-sha256",
      createdAt,
      signingSecretReference: "vault://webhook-01",
      failureCount: 0,
    };
    const delivery: OpenPlatformWebhookDeliveryRecord = {
      id: "delivery-01",
      webhookId: webhook.id,
      event: "application.status_changed",
      status: "succeeded",
      attempt: 1,
      idempotencyKey: "delivery-key-01",
      createdAt,
      deliveredAt: createdAt,
      responseStatusCode: 204,
    };
    const audit: OpenPlatformAuditEventRecord = {
      contractVersion: 1,
      id: "audit-01",
      tenantId: "tenant-01",
      developerOrganizationId: "organization-01",
      action: "credential.rotate",
      outcome: "success",
      actor: { type: "user", id: "user-01" },
      target: { type: "credential", id: credential.id },
      requestId: "req-01",
      metadata: { version: credential.version },
      occurredAt: createdAt,
      sequence: 1,
      source: "control-plane",
      eventHash: "hash",
    };
    const page: OpenPlatformPage<OpenPlatformApiResourceRecord> = {
      items: [resource],
      nextCursor: "cursor-02",
      hasMore: true,
      total: 2,
    };

    assert.equal(product.versions[0].resourceIds[0], resource.id);
    assert.equal("secret" in credential, true);
    assert.equal("secret" in credentialDto, false);
    assert.equal("digest" in credentialDto, false);
    assert.equal("reference" in credentialDto, false);
    assert.equal(JSON.stringify(credentialDto).includes("vault://"), false);
    assert.equal(credentialIssue.secret.value, "one-time-credential-value");
    assert.equal(credentialRotation.secret.value, "one-time-rotation-value");
    assert.equal(subscription.status, "published");
    assert.equal(subscription.billingStatus, "active");
    assert.equal(usage.quantity, 1200);
    assert.equal(webhook.events[0], delivery.event);
    assert.equal(audit.target.id, credential.id);
    assert.equal(page.items[0].method, "GET");
  });
});
