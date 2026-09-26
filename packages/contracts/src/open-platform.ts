export const OPEN_PLATFORM_CONTRACT_VERSION = 1 as const;

export const OPEN_PLATFORM_RESOURCE_TYPES = [
  "tenant",
  "developer_organization",
  "application",
  "application_environment",
  "environment",
  "client",
  "api_product",
  "api_version",
  "api_resource",
  "credential",
  "subscription",
  "webhook",
  "audit_event",
] as const;
export type OpenPlatformResourceType = (typeof OPEN_PLATFORM_RESOURCE_TYPES)[number];

export const OPEN_PLATFORM_LIFECYCLE_STATUSES = [
  "draft",
  "published",
  "disabled",
  "archived",
] as const;
export type OpenPlatformLifecycleStatus = (typeof OPEN_PLATFORM_LIFECYCLE_STATUSES)[number];

export const OPEN_PLATFORM_LIFECYCLE_EVENTS = ["publish", "disable", "republish", "archive"] as const;
export type OpenPlatformLifecycleEvent = (typeof OPEN_PLATFORM_LIFECYCLE_EVENTS)[number];

export const OPEN_PLATFORM_LIFECYCLE_AUTHORIZATION_ACTIONS = [
  "publish",
  "disable",
  "archive",
  "submitReview",
] as const;
export type OpenPlatformLifecycleAuthorizationAction =
  (typeof OPEN_PLATFORM_LIFECYCLE_AUTHORIZATION_ACTIONS)[number];

export const OPEN_PLATFORM_LIFECYCLE_AUTHORIZATION_ACTION_ALIASES = {
  republish: "publish",
  "submit-review": "submitReview",
} as const satisfies Readonly<Record<string, OpenPlatformLifecycleAuthorizationAction>>;
export type OpenPlatformLifecycleAuthorizationActionAlias =
  keyof typeof OPEN_PLATFORM_LIFECYCLE_AUTHORIZATION_ACTION_ALIASES;

export const OPEN_PLATFORM_LIFECYCLE_PERMISSION_RESOURCES = [
  "tenant",
  "developer",
  "application",
  "api-product",
  "authorization",
] as const;
export type OpenPlatformLifecyclePermissionResource =
  (typeof OPEN_PLATFORM_LIFECYCLE_PERMISSION_RESOURCES)[number];

export const OPEN_PLATFORM_LIFECYCLE_PERMISSION_ACTIONS = [
  "publish",
  "disable",
  "archive",
  "submit-review",
] as const;
export type OpenPlatformLifecyclePermissionAction =
  (typeof OPEN_PLATFORM_LIFECYCLE_PERMISSION_ACTIONS)[number];

export type OpenPlatformLifecyclePermission =
  `open:${OpenPlatformLifecyclePermissionResource}:${OpenPlatformLifecyclePermissionAction}`;

export const OPEN_PLATFORM_LIFECYCLE_PERMISSIONS: readonly OpenPlatformLifecyclePermission[] =
  Object.freeze(
    OPEN_PLATFORM_LIFECYCLE_PERMISSION_RESOURCES.flatMap((resource) =>
      OPEN_PLATFORM_LIFECYCLE_PERMISSION_ACTIONS.map(
        (action) => `open:${resource}:${action}` as OpenPlatformLifecyclePermission,
      ),
    ),
  );

export const OPEN_PLATFORM_LIFECYCLE_PERMISSION_ACTIONS_BY_EVENT = {
  publish: "publish",
  disable: "disable",
  republish: "publish",
  archive: "archive",
} as const satisfies Record<OpenPlatformLifecycleEvent, OpenPlatformLifecyclePermissionAction>;

export const OPEN_PLATFORM_LIFECYCLE_PERMISSION_ACTIONS_BY_STATUS = {
  draft: undefined,
  published: "publish",
  disabled: "disable",
  archived: "archive",
} as const satisfies Readonly<
  Record<OpenPlatformLifecycleStatus, OpenPlatformLifecyclePermissionAction | undefined>
>;

export function canonicalOpenPlatformLifecycleAuthorizationAction(
  action: string,
): OpenPlatformLifecycleAuthorizationAction | undefined {
  if (
    !(OPEN_PLATFORM_LIFECYCLE_AUTHORIZATION_ACTIONS as readonly string[]).includes(action)
  ) {
    return Object.hasOwn(OPEN_PLATFORM_LIFECYCLE_AUTHORIZATION_ACTION_ALIASES, action)
      ? OPEN_PLATFORM_LIFECYCLE_AUTHORIZATION_ACTION_ALIASES[
        action as OpenPlatformLifecycleAuthorizationActionAlias
      ]
      : undefined;
  }
  return action as OpenPlatformLifecycleAuthorizationAction;
}

export function openPlatformLifecyclePermissionForStatus(
  status: OpenPlatformLifecycleStatus,
): OpenPlatformLifecyclePermissionAction | undefined {
  return Object.hasOwn(OPEN_PLATFORM_LIFECYCLE_PERMISSION_ACTIONS_BY_STATUS, status)
    ? OPEN_PLATFORM_LIFECYCLE_PERMISSION_ACTIONS_BY_STATUS[status]
    : undefined;
}

export function openPlatformLifecyclePermissionForEvent(
  event: OpenPlatformLifecycleEvent,
): OpenPlatformLifecyclePermissionAction {
  return OPEN_PLATFORM_LIFECYCLE_PERMISSION_ACTIONS_BY_EVENT[event];
}

export function openPlatformLifecyclePermission(
  resource: OpenPlatformLifecyclePermissionResource,
  action: OpenPlatformLifecyclePermissionAction,
): OpenPlatformLifecyclePermission {
  return `open:${resource}:${action}`;
}

export const OPEN_PLATFORM_CONTROL_PLANE_LIFECYCLE_STATUS_MAP = {
  draft: "draft",
  published: "published",
  disabled: "disabled",
  archived: "archived",
} as const satisfies Record<OpenPlatformLifecycleStatus, OpenPlatformLifecycleStatus>;

export type OpenPlatformLifecycleTransition =
  | { readonly from: "draft"; readonly event: "publish"; readonly to: "published" }
  | { readonly from: "draft"; readonly event: "archive"; readonly to: "archived" }
  | { readonly from: "published"; readonly event: "disable"; readonly to: "disabled" }
  | { readonly from: "published"; readonly event: "archive"; readonly to: "archived" }
  | { readonly from: "disabled"; readonly event: "republish"; readonly to: "published" }
  | { readonly from: "disabled"; readonly event: "archive"; readonly to: "archived" };

export const OPEN_PLATFORM_TENANT_STATUSES = OPEN_PLATFORM_LIFECYCLE_STATUSES;
export type OpenPlatformTenantStatus = OpenPlatformLifecycleStatus;

export const OPEN_PLATFORM_DEVELOPER_ORGANIZATION_STATUSES = OPEN_PLATFORM_LIFECYCLE_STATUSES;
export type OpenPlatformDeveloperOrganizationStatus = OpenPlatformLifecycleStatus;

export const OPEN_PLATFORM_DEVELOPER_ORGANIZATION_ROLES = [
  "owner",
  "administrator",
  "developer",
  "auditor",
] as const;
export type OpenPlatformDeveloperOrganizationRole =
  (typeof OPEN_PLATFORM_DEVELOPER_ORGANIZATION_ROLES)[number];

export const OPEN_PLATFORM_ORGANIZATION_MEMBERSHIP_STATUSES = ["invited", "active", "removed"] as const;
export type OpenPlatformOrganizationMembershipStatus =
  (typeof OPEN_PLATFORM_ORGANIZATION_MEMBERSHIP_STATUSES)[number];

export const OPEN_PLATFORM_VERIFICATION_STATUSES = ["not_required", "pending", "verified", "rejected"] as const;
export type OpenPlatformVerificationStatus = (typeof OPEN_PLATFORM_VERIFICATION_STATUSES)[number];

export const OPEN_PLATFORM_APPLICATION_STATUSES = OPEN_PLATFORM_LIFECYCLE_STATUSES;
export type OpenPlatformApplicationStatus = OpenPlatformLifecycleStatus;

export const OPEN_PLATFORM_APPLICATION_EVENTS = OPEN_PLATFORM_LIFECYCLE_EVENTS;
export type OpenPlatformApplicationEvent = OpenPlatformLifecycleEvent;

export type OpenPlatformApplicationTransition = OpenPlatformLifecycleTransition;

export const OPEN_PLATFORM_ENVIRONMENT_STATUSES = OPEN_PLATFORM_LIFECYCLE_STATUSES;
export type OpenPlatformEnvironmentStatus = OpenPlatformLifecycleStatus;

export const OPEN_PLATFORM_ENVIRONMENT_ISOLATION_LEVELS = ["shared", "dedicated"] as const;
export type OpenPlatformEnvironmentIsolationLevel =
  (typeof OPEN_PLATFORM_ENVIRONMENT_ISOLATION_LEVELS)[number];

export const OPEN_PLATFORM_CLIENT_KINDS = ["web", "native", "service"] as const;
export type OpenPlatformClientKind = (typeof OPEN_PLATFORM_CLIENT_KINDS)[number];

export const OPEN_PLATFORM_CLIENT_STATUSES = ["active", "suspended", "revoked"] as const;
export type OpenPlatformClientStatus = (typeof OPEN_PLATFORM_CLIENT_STATUSES)[number];

export const OPEN_PLATFORM_CLIENT_AUTH_METHODS = [
  "none",
  "client_secret_basic",
  "client_secret_post",
  "private_key_jwt",
] as const;
export type OpenPlatformClientAuthMethod = (typeof OPEN_PLATFORM_CLIENT_AUTH_METHODS)[number];

export const OPEN_PLATFORM_SERVICE_CLIENT_AUTH_METHODS = [
  "client_secret_basic",
  "client_secret_post",
  "private_key_jwt",
] as const;
export type OpenPlatformServiceClientAuthMethod =
  (typeof OPEN_PLATFORM_SERVICE_CLIENT_AUTH_METHODS)[number];

export const OPEN_PLATFORM_API_PRODUCT_STATUSES = OPEN_PLATFORM_LIFECYCLE_STATUSES;
export type OpenPlatformApiProductStatus = OpenPlatformLifecycleStatus;

export const OPEN_PLATFORM_API_VERSION_RELEASE_STATUSES = [
  "draft",
  "preview",
  "active",
  "deprecated",
  "retired",
] as const;
export type OpenPlatformApiVersionReleaseStatus =
  (typeof OPEN_PLATFORM_API_VERSION_RELEASE_STATUSES)[number];

export const OPEN_PLATFORM_API_VERSION_STATUSES = OPEN_PLATFORM_API_VERSION_RELEASE_STATUSES;
export type OpenPlatformApiVersionStatus = OpenPlatformApiVersionReleaseStatus;

export const OPEN_PLATFORM_API_VERSION_LIFECYCLE_STATUSES = OPEN_PLATFORM_LIFECYCLE_STATUSES;
export type OpenPlatformApiVersionLifecycleStatus = OpenPlatformLifecycleStatus;

export const OPEN_PLATFORM_HTTP_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE"] as const;
export type OpenPlatformHttpMethod = (typeof OPEN_PLATFORM_HTTP_METHODS)[number];

export type OpenPlatformScope = string;

export interface OpenPlatformEntityReferenceDto {
  readonly id: string;
  readonly type: OpenPlatformResourceType;
  readonly slug?: string;
}

export interface OpenPlatformTenantDto {
  readonly contractVersion: typeof OPEN_PLATFORM_CONTRACT_VERSION;
  readonly id: string;
  readonly name: string;
  readonly slug: string;
  readonly status: OpenPlatformTenantStatus;
  readonly defaultEnvironmentId?: string;
  readonly createdAt: string;
  readonly updatedAt?: string;
}

export interface OpenPlatformTenantRecord extends OpenPlatformTenantDto {
  readonly region: string;
  readonly settings: Readonly<Record<string, string | number | boolean | null>>;
}

export interface OpenPlatformDeveloperOrganizationDto {
  readonly contractVersion: typeof OPEN_PLATFORM_CONTRACT_VERSION;
  readonly id: string;
  readonly tenantId: string;
  readonly name: string;
  readonly slug: string;
  readonly status: OpenPlatformDeveloperOrganizationStatus;
  readonly verificationStatus: OpenPlatformVerificationStatus;
  readonly websiteUrl?: string;
  readonly supportEmail?: string;
  readonly createdAt: string;
  readonly updatedAt?: string;
}

export interface OpenPlatformDeveloperOrganizationRecord extends OpenPlatformDeveloperOrganizationDto {
  readonly legalName?: string;
  readonly metadata: Readonly<Record<string, string | number | boolean | null>>;
}

export interface OpenPlatformDeveloperOrganizationMemberDto {
  readonly organizationId: string;
  readonly userId: string;
  readonly role: OpenPlatformDeveloperOrganizationRole;
  readonly status: OpenPlatformOrganizationMembershipStatus;
  readonly invitedAt?: string;
  readonly joinedAt?: string;
}

export interface OpenPlatformDeveloperOrganizationMembershipRecord
  extends OpenPlatformDeveloperOrganizationMemberDto {
  readonly tenantId: string;
  readonly invitedByUserId?: string;
  readonly removedAt?: string;
}

export interface OpenPlatformApplicationDto {
  readonly contractVersion: typeof OPEN_PLATFORM_CONTRACT_VERSION;
  readonly id: string;
  readonly tenantId: string;
  readonly developerOrganizationId: string;
  readonly name: string;
  readonly slug: string;
  readonly status: OpenPlatformApplicationStatus;
  readonly description?: string;
  readonly environmentIds: readonly string[];
  readonly apiProductIds: readonly string[];
  readonly supportEmail?: string;
  readonly createdAt: string;
  readonly updatedAt?: string;
}

export interface OpenPlatformApplicationRecord extends OpenPlatformApplicationDto {
  readonly settings: Readonly<Record<string, string | number | boolean | null>>;
  readonly metadata: Readonly<Record<string, string | number | boolean | null>>;
}

export interface OpenPlatformEnvironmentDto {
  readonly contractVersion: typeof OPEN_PLATFORM_CONTRACT_VERSION;
  readonly id: string;
  readonly applicationId: string;
  readonly name: string;
  readonly slug: string;
  readonly status: OpenPlatformEnvironmentStatus;
  readonly region: string;
  readonly baseUrl?: string;
  readonly createdAt: string;
  readonly updatedAt?: string;
}

export interface OpenPlatformEnvironmentRecord extends OpenPlatformEnvironmentDto {
  readonly isolationLevel: OpenPlatformEnvironmentIsolationLevel;
  readonly configuration: Readonly<Record<string, string | number | boolean | null>>;
}

export interface OpenPlatformClientIdentityDto {
  readonly id: string;
  readonly tenantId: string;
  readonly developerOrganizationId: string;
  readonly applicationId: string;
  readonly environmentId: string;
  readonly clientId: string;
  readonly name: string;
  readonly status: OpenPlatformClientStatus;
  readonly allowedScopes: readonly OpenPlatformScope[];
  readonly createdAt: string;
  readonly updatedAt?: string;
}

export interface OpenPlatformWebClientDto extends OpenPlatformClientIdentityDto {
  readonly kind: "web";
  readonly redirectUris: readonly string[];
  readonly postLogoutRedirectUris: readonly string[];
  readonly tokenEndpointAuthMethod: OpenPlatformClientAuthMethod;
  readonly requirePkce: true;
}

export interface OpenPlatformNativeClientDto extends OpenPlatformClientIdentityDto {
  readonly kind: "native";
  readonly redirectUris: readonly string[];
  readonly postLogoutRedirectUris: readonly string[];
  readonly tokenEndpointAuthMethod: OpenPlatformClientAuthMethod;
  readonly requirePkce: true;
}

export interface OpenPlatformServiceClientDto extends OpenPlatformClientIdentityDto {
  readonly kind: "service";
  readonly serviceAccountId: string;
  readonly tokenEndpointAuthMethod: OpenPlatformServiceClientAuthMethod;
  readonly redirectUris?: never;
  readonly postLogoutRedirectUris?: never;
  readonly requirePkce?: false;
}

export type OpenPlatformClientDto =
  | OpenPlatformWebClientDto
  | OpenPlatformNativeClientDto
  | OpenPlatformServiceClientDto;

export interface OpenPlatformClientRecordBase extends OpenPlatformClientIdentityDto {
  readonly lastUsedAt?: string;
  readonly createdByUserId?: string;
}

export interface OpenPlatformWebClientRecord extends OpenPlatformClientRecordBase, OpenPlatformWebClientDto {}
export interface OpenPlatformNativeClientRecord extends OpenPlatformClientRecordBase, OpenPlatformNativeClientDto {}

export interface OpenPlatformServiceClientRecord extends OpenPlatformClientRecordBase, OpenPlatformServiceClientDto {
  readonly credentialId: string;
}

export type OpenPlatformClientRecord =
  | OpenPlatformWebClientRecord
  | OpenPlatformNativeClientRecord
  | OpenPlatformServiceClientRecord;

export interface OpenPlatformApiScopeDto {
  readonly name: OpenPlatformScope;
  readonly displayName: string;
  readonly description?: string;
  readonly sensitive: boolean;
  readonly requiresApproval: boolean;
}

export interface OpenPlatformRateLimitDto {
  readonly requests: number;
  readonly intervalSeconds: number;
  readonly burst?: number;
}

export interface OpenPlatformApiResourceDto {
  readonly contractVersion: typeof OPEN_PLATFORM_CONTRACT_VERSION;
  readonly id: string;
  readonly apiVersionId: string;
  readonly name: string;
  readonly method: OpenPlatformHttpMethod;
  readonly pathTemplate: string;
  readonly scopes: readonly OpenPlatformScope[];
  readonly idempotent: boolean;
  readonly rateLimit?: OpenPlatformRateLimitDto;
  readonly createdAt: string;
  readonly updatedAt?: string;
}

export interface OpenPlatformApiResourceRecord extends OpenPlatformApiResourceDto {
  readonly tenantId: string;
  readonly developerOrganizationId: string;
  readonly applicationId: string;
  readonly apiProductId: string;
  readonly createdByUserId: string;
}

export interface OpenPlatformApiVersionDto {
  readonly contractVersion: typeof OPEN_PLATFORM_CONTRACT_VERSION;
  readonly id: string;
  readonly apiProductId: string;
  readonly version: string;
  readonly status: OpenPlatformApiVersionLifecycleStatus;
  readonly releaseStatus: OpenPlatformApiVersionReleaseStatus;
  readonly basePath: string;
  readonly resourceIds: readonly string[];
  readonly scopes: readonly OpenPlatformScope[];
  readonly releasedAt?: string;
  readonly deprecatedAt?: string;
  readonly retiredAt?: string;
  readonly createdAt: string;
  readonly updatedAt?: string;
}

export interface OpenPlatformApiVersionRecord extends OpenPlatformApiVersionDto {
  readonly tenantId: string;
  readonly developerOrganizationId: string;
  readonly applicationId: string;
  readonly deprecationNotice?: string;
}

export interface OpenPlatformApiProductDto {
  readonly contractVersion: typeof OPEN_PLATFORM_CONTRACT_VERSION;
  readonly id: string;
  readonly applicationId: string;
  readonly name: string;
  readonly slug: string;
  readonly status: OpenPlatformApiProductStatus;
  readonly description?: string;
  readonly versions: readonly OpenPlatformApiVersionDto[];
  readonly scopes: readonly OpenPlatformScope[];
  readonly createdAt: string;
  readonly updatedAt?: string;
}

export interface OpenPlatformApiProductRecord extends OpenPlatformApiProductDto {
  readonly tenantId: string;
  readonly developerOrganizationId: string;
  readonly ownerUserId: string;
  readonly metadata: Readonly<Record<string, string | number | boolean | null>>;
}

export const OPEN_PLATFORM_CREDENTIAL_KINDS = ["api_key", "client_secret", "signing_key"] as const;
export type OpenPlatformCredentialKind = (typeof OPEN_PLATFORM_CREDENTIAL_KINDS)[number];

export const OPEN_PLATFORM_CREDENTIAL_STATUSES = [
  "pending",
  "active",
  "rotating",
  "rotated",
  "expired",
  "revoked",
] as const;
export type OpenPlatformCredentialStatus = (typeof OPEN_PLATFORM_CREDENTIAL_STATUSES)[number];

export const OPEN_PLATFORM_CONTROL_PLANE_CREDENTIAL_STATUS_MAP = {
  pending: "pending",
  active: "active",
  rotating: "rotating",
  rotated: "rotated",
  expired: "expired",
  revoked: "revoked",
} as const satisfies Record<OpenPlatformCredentialStatus, OpenPlatformCredentialStatus>;
export type OpenPlatformControlPlaneCredentialStatus =
  keyof typeof OPEN_PLATFORM_CONTROL_PLANE_CREDENTIAL_STATUS_MAP;

export const OPEN_PLATFORM_CREDENTIAL_EVENTS = [
  "activate",
  "rotate",
  "complete",
  "mark_rotated",
  "expire",
  "revoke",
] as const;
export type OpenPlatformCredentialEvent = (typeof OPEN_PLATFORM_CREDENTIAL_EVENTS)[number];

export type OpenPlatformCredentialTransition =
  | { readonly from: "pending"; readonly event: "activate"; readonly to: "active" }
  | { readonly from: "pending"; readonly event: "expire"; readonly to: "expired" }
  | { readonly from: "pending"; readonly event: "revoke"; readonly to: "revoked" }
  | { readonly from: "active"; readonly event: "rotate"; readonly to: "rotating" }
  | { readonly from: "active"; readonly event: "mark_rotated"; readonly to: "rotated" }
  | { readonly from: "active"; readonly event: "expire"; readonly to: "expired" }
  | { readonly from: "active"; readonly event: "revoke"; readonly to: "revoked" }
  | { readonly from: "rotating"; readonly event: "complete"; readonly to: "active" }
  | { readonly from: "rotating"; readonly event: "mark_rotated"; readonly to: "rotated" }
  | { readonly from: "rotating"; readonly event: "expire"; readonly to: "expired" }
  | { readonly from: "rotating"; readonly event: "revoke"; readonly to: "revoked" }
  | { readonly from: "expired"; readonly event: "rotate"; readonly to: "rotating" }
  | { readonly from: "expired"; readonly event: "revoke"; readonly to: "revoked" };

export interface OpenPlatformCredentialDto {
  readonly contractVersion: typeof OPEN_PLATFORM_CONTRACT_VERSION;
  readonly id: string;
  readonly tenantId: string;
  readonly developerOrganizationId?: string;
  readonly applicationId: string;
  readonly environmentId?: string;
  readonly clientId?: string;
  readonly name: string;
  readonly kind: OpenPlatformCredentialKind;
  readonly status: OpenPlatformCredentialStatus;
  readonly scopes: readonly OpenPlatformScope[];
  readonly keyPrefix?: string;
  readonly lastFour?: string;
  readonly version: number;
  readonly createdAt: string;
  readonly updatedAt?: string;
  readonly activatedAt?: string;
  readonly expiresAt?: string;
  readonly rotatedAt?: string;
  readonly revokedAt?: string;
  readonly previousCredentialId?: string;
  readonly replacedByCredentialId?: string;
}

export interface OpenPlatformCredentialSecretRecord {
  readonly digest: string;
  readonly reference?: string;
}

export interface OpenPlatformCredentialRecord extends OpenPlatformCredentialDto {
  readonly secret: OpenPlatformCredentialSecretRecord;
  readonly previousSecretDigest?: string;
  readonly rotationRequestedAt?: string;
  readonly createdByUserId: string;
}

export interface OpenPlatformControlPlaneCredentialSource {
  readonly id: string;
  readonly tenantId: string;
  readonly applicationId: string;
  readonly environmentId?: string;
  readonly name: string;
  readonly status: OpenPlatformControlPlaneCredentialStatus;
  readonly scopes: readonly OpenPlatformScope[];
  readonly secret: OpenPlatformCredentialSecretRecord;
  readonly fingerprint: string;
  readonly version: number;
  readonly createdAt: string;
  readonly updatedAt?: string;
  readonly expiresAt?: string;
  readonly rotatedAt?: string;
  readonly revokedAt?: string;
  readonly previousCredentialId?: string;
  readonly replacedByCredentialId?: string;
}

export interface OpenPlatformCredentialProjectionOptions {
  readonly developerOrganizationId?: string;
  readonly kind?: OpenPlatformCredentialKind;
  readonly now?: string;
}

export interface OpenPlatformCredentialSecretDto {
  readonly credentialId: string;
  readonly value: string;
  readonly expiresAt?: string;
}

export interface OpenPlatformCredentialIssueResultDto {
  readonly credential: OpenPlatformCredentialDto;
  readonly secret: OpenPlatformCredentialSecretDto;
}

export interface OpenPlatformCredentialRotationResultDto {
  readonly credential: OpenPlatformCredentialDto;
  readonly previousCredential: OpenPlatformCredentialDto;
  readonly secret: OpenPlatformCredentialSecretDto;
}

export const OPEN_PLATFORM_SUBSCRIPTION_STATUSES = OPEN_PLATFORM_LIFECYCLE_STATUSES;
export type OpenPlatformSubscriptionStatus = OpenPlatformLifecycleStatus;

export const OPEN_PLATFORM_SUBSCRIPTION_BILLING_STATUSES = [
  "trialing",
  "active",
  "past_due",
  "suspended",
  "canceled",
  "expired",
] as const;
export type OpenPlatformSubscriptionBillingStatus =
  (typeof OPEN_PLATFORM_SUBSCRIPTION_BILLING_STATUSES)[number];

export const OPEN_PLATFORM_SUBSCRIPTION_EVENTS = [
  "activate",
  "mark_past_due",
  "suspend",
  "resume",
  "cancel",
  "expire",
] as const;
export type OpenPlatformSubscriptionEvent = (typeof OPEN_PLATFORM_SUBSCRIPTION_EVENTS)[number];

export type OpenPlatformSubscriptionTransition =
  | { readonly from: "trialing"; readonly event: "activate"; readonly to: "active" }
  | { readonly from: "trialing"; readonly event: "cancel"; readonly to: "canceled" }
  | { readonly from: "trialing"; readonly event: "expire"; readonly to: "expired" }
  | { readonly from: "active"; readonly event: "mark_past_due"; readonly to: "past_due" }
  | { readonly from: "active"; readonly event: "suspend"; readonly to: "suspended" }
  | { readonly from: "active"; readonly event: "cancel"; readonly to: "canceled" }
  | { readonly from: "active"; readonly event: "expire"; readonly to: "expired" }
  | { readonly from: "past_due"; readonly event: "resume"; readonly to: "active" }
  | { readonly from: "past_due"; readonly event: "suspend"; readonly to: "suspended" }
  | { readonly from: "past_due"; readonly event: "cancel"; readonly to: "canceled" }
  | { readonly from: "past_due"; readonly event: "expire"; readonly to: "expired" }
  | { readonly from: "suspended"; readonly event: "resume"; readonly to: "active" }
  | { readonly from: "suspended"; readonly event: "cancel"; readonly to: "canceled" }
  | { readonly from: "suspended"; readonly event: "expire"; readonly to: "expired" };

export const OPEN_PLATFORM_BILLING_INTERVALS = ["month", "year"] as const;
export type OpenPlatformBillingInterval = (typeof OPEN_PLATFORM_BILLING_INTERVALS)[number];

export interface OpenPlatformSubscriptionPlanDto {
  readonly id: string;
  readonly apiProductId: string;
  readonly code: string;
  readonly name: string;
  readonly billingInterval: OpenPlatformBillingInterval;
  readonly amountMinor: number;
  readonly currency: string;
  readonly includedUnits: Readonly<Record<string, number>>;
  readonly active: boolean;
}

export interface OpenPlatformSubscriptionDto {
  readonly contractVersion: typeof OPEN_PLATFORM_CONTRACT_VERSION;
  readonly id: string;
  readonly tenantId: string;
  readonly developerOrganizationId?: string;
  readonly applicationId: string;
  readonly apiProductId: string;
  readonly apiVersionId?: string;
  readonly name: string;
  readonly scopes: readonly OpenPlatformScope[];
  readonly planId?: string;
  readonly status: OpenPlatformSubscriptionStatus;
  readonly billingStatus?: OpenPlatformSubscriptionBillingStatus;
  readonly quantity?: number;
  readonly currentPeriodStart?: string;
  readonly currentPeriodEnd?: string;
  readonly cancelAtPeriodEnd?: boolean;
  readonly createdAt: string;
  readonly updatedAt?: string;
  readonly canceledAt?: string;
}

export interface OpenPlatformSubscriptionRecord extends OpenPlatformSubscriptionDto {
  readonly billingAccountReference: string;
  readonly externalSubscriptionId: string;
  readonly metadata: Readonly<Record<string, string | number | boolean | null>>;
}

export const OPEN_PLATFORM_USAGE_METRICS = [
  "requests",
  "tokens",
  "storage_bytes",
  "bandwidth_bytes",
  "active_users",
  "webhook_deliveries",
] as const;
export type OpenPlatformUsageMetric = (typeof OPEN_PLATFORM_USAGE_METRICS)[number];

export const OPEN_PLATFORM_USAGE_AGGREGATIONS = ["sum", "max", "last"] as const;
export type OpenPlatformUsageAggregation = (typeof OPEN_PLATFORM_USAGE_AGGREGATIONS)[number];

export interface OpenPlatformUsageRecord {
  readonly contractVersion: typeof OPEN_PLATFORM_CONTRACT_VERSION;
  readonly tenantId: string;
  readonly developerOrganizationId: string;
  readonly subscriptionId: string;
  readonly metric: OpenPlatformUsageMetric;
  readonly aggregation: OpenPlatformUsageAggregation;
  readonly quantity: number;
  readonly unit: string;
  readonly periodStart: string;
  readonly periodEnd: string;
  readonly recordedAt: string;
  readonly dimensions: Readonly<Record<string, string>>;
  readonly sourceEventId?: string;
}

export interface OpenPlatformUsageSummaryDto {
  readonly metric: OpenPlatformUsageMetric;
  readonly quantity: number;
  readonly unit: string;
  readonly periodStart: string;
  readonly periodEnd: string;
  readonly dimensions: Readonly<Record<string, string>>;
}

export const OPEN_PLATFORM_WEBHOOK_STATUSES = ["active", "paused", "failing", "disabled"] as const;
export type OpenPlatformWebhookStatus = (typeof OPEN_PLATFORM_WEBHOOK_STATUSES)[number];
export const OPEN_PLATFORM_WEBHOOK_TRANSITIONS = Object.freeze({
  active: Object.freeze(["paused", "failing", "disabled"]),
  paused: Object.freeze(["active", "failing", "disabled"]),
  failing: Object.freeze(["active", "paused", "disabled"]),
  disabled: Object.freeze(["active"]),
} satisfies Readonly<Record<OpenPlatformWebhookStatus, readonly OpenPlatformWebhookStatus[]>>);
export function canTransitionOpenPlatformWebhook(from: OpenPlatformWebhookStatus, to: OpenPlatformWebhookStatus): boolean {
  return (OPEN_PLATFORM_WEBHOOK_TRANSITIONS[from] as readonly OpenPlatformWebhookStatus[]).includes(to);
}
export function transitionOpenPlatformWebhook(from: OpenPlatformWebhookStatus, to: OpenPlatformWebhookStatus): OpenPlatformWebhookStatus {
  if (!canTransitionOpenPlatformWebhook(from, to)) {
    throw new OpenPlatformContractError(OPEN_PLATFORM_ERROR_CODES.INVALID_STATE_TRANSITION, "webhook.status");
  }
  return to;
}

export const OPEN_PLATFORM_DOMAIN_EVENT_ACTIONS = [
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
] as const;
export type OpenPlatformDomainEventAction = (typeof OPEN_PLATFORM_DOMAIN_EVENT_ACTIONS)[number];

export const OPEN_PLATFORM_DOMAIN_EVENT_CATALOG = {
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
} as const satisfies Readonly<
  Record<string, readonly OpenPlatformDomainEventAction[]>
>;

export type OpenPlatformDomainEventResource = keyof typeof OPEN_PLATFORM_DOMAIN_EVENT_CATALOG;

export const OPEN_PLATFORM_DOMAIN_EVENT_RESOURCES: readonly OpenPlatformDomainEventResource[] =
  Object.freeze(
    Object.keys(OPEN_PLATFORM_DOMAIN_EVENT_CATALOG) as readonly OpenPlatformDomainEventResource[],
  );

export type OpenPlatformWebhookEvent = {
  readonly [Resource in OpenPlatformDomainEventResource]: `${Resource}.${(typeof OPEN_PLATFORM_DOMAIN_EVENT_CATALOG)[Resource][number]}`;
}[OpenPlatformDomainEventResource];

export const OPEN_PLATFORM_WEBHOOK_EVENTS: readonly OpenPlatformWebhookEvent[] =
  Object.freeze(openPlatformDomainEventNames());

export const OPEN_PLATFORM_DOMAIN_EVENTS = OPEN_PLATFORM_WEBHOOK_EVENTS;

export type OpenPlatformDomainEvent = OpenPlatformWebhookEvent;

export const OPEN_PLATFORM_DOMAIN_EVENT_SCHEMA_VERSION = "open-platform.domain-event.v1" as const;

export interface OpenPlatformDomainEventNameParts {
  readonly resource: OpenPlatformDomainEventResource;
  readonly action: OpenPlatformDomainEventAction;
}

export function isOpenPlatformDomainEventName(
  value: unknown,
): value is OpenPlatformDomainEvent {
  return (
    typeof value === "string" &&
    (OPEN_PLATFORM_WEBHOOK_EVENTS as readonly string[]).includes(value)
  );
}

export function openPlatformDomainEventNameParts(
  value: OpenPlatformWebhookEvent,
): OpenPlatformDomainEventNameParts {
  const separator = value.indexOf(".");
  if (separator < 1) {
    throw new OpenPlatformContractError(OPEN_PLATFORM_ERROR_CODES.INVALID_ARGUMENT, "event");
  }
  return {
    resource: value.slice(0, separator) as OpenPlatformDomainEventResource,
    action: value.slice(separator + 1) as OpenPlatformDomainEventAction,
  };
}

function openPlatformDomainEventNames(): OpenPlatformWebhookEvent[] {
  const names: OpenPlatformWebhookEvent[] = [];
  for (const resource of OPEN_PLATFORM_DOMAIN_EVENT_RESOURCES) {
    for (const action of OPEN_PLATFORM_DOMAIN_EVENT_CATALOG[resource]) {
      names.push(`${resource}.${action}` as OpenPlatformWebhookEvent);
    }
  }
  return names;
}

export const OPEN_PLATFORM_WEBHOOK_SIGNATURE_ALGORITHM = "hmac-sha256" as const;
export const OPEN_PLATFORM_WEBHOOK_SIGNATURE_VERSION = "v1" as const;
export const OPEN_PLATFORM_WEBHOOK_EVENT_SCHEMA_VERSION = "open-platform.webhook-event.v1" as const;
export const OPEN_PLATFORM_WEBHOOK_SIGNATURE_HEADER = "X-Webhook-Signature" as const;
export const OPEN_PLATFORM_WEBHOOK_TIMESTAMP_HEADER = "X-Webhook-Timestamp" as const;
export const OPEN_PLATFORM_WEBHOOK_SECRET_VERSION_HEADER = "X-Webhook-Secret-Version" as const;
export const OPEN_PLATFORM_WEBHOOK_EVENT_ID_HEADER = "X-Webhook-Event-Id" as const;
export const OPEN_PLATFORM_WEBHOOK_EVENT_TYPE_HEADER = "X-Webhook-Event-Type" as const;
export const OPEN_PLATFORM_WEBHOOK_IDEMPOTENCY_HEADER = "Idempotency-Key" as const;
export const OPEN_PLATFORM_WEBHOOK_SIGNATURE_HEADER_NAME = OPEN_PLATFORM_WEBHOOK_SIGNATURE_HEADER;
export const OPEN_PLATFORM_WEBHOOK_TIMESTAMP_HEADER_NAME = OPEN_PLATFORM_WEBHOOK_TIMESTAMP_HEADER;
export const OPEN_PLATFORM_WEBHOOK_SECRET_VERSION_HEADER_NAME = OPEN_PLATFORM_WEBHOOK_SECRET_VERSION_HEADER;

export const OPEN_PLATFORM_WEBHOOK_DELIVERY_STATUSES = [
  "pending",
  "delivering",
  "succeeded",
  "failed",
  "dead_lettered",
] as const;
export type OpenPlatformWebhookDeliveryStatus =
  (typeof OPEN_PLATFORM_WEBHOOK_DELIVERY_STATUSES)[number];

export interface OpenPlatformWebhookDto {
  readonly contractVersion: typeof OPEN_PLATFORM_CONTRACT_VERSION;
  readonly id: string;
  readonly tenantId: string;
  readonly developerOrganizationId: string;
  readonly applicationId: string;
  readonly environmentId: string;
  readonly name: string;
  readonly endpointUrl: string;
  readonly status: OpenPlatformWebhookStatus;
  readonly events: readonly OpenPlatformWebhookEvent[];
  readonly signingAlgorithm: typeof OPEN_PLATFORM_WEBHOOK_SIGNATURE_ALGORITHM;
  readonly secretVersion?: number;
  readonly createdAt: string;
  readonly updatedAt?: string;
  readonly lastDeliveryAt?: string;
  readonly failureCount?: number;
  readonly nextDeliveryAt?: string;
}

export interface OpenPlatformWebhookRecord extends OpenPlatformWebhookDto {
  readonly signingSecretReference: string;
  readonly secretVersion?: number;
  readonly failureCount: number;
  readonly nextDeliveryAt?: string;
}

export interface OpenPlatformWebhookDeliveryRecord {
  readonly id: string;
  readonly tenantId?: string;
  readonly webhookId: string;
  readonly eventId?: string;
  readonly event: OpenPlatformWebhookEvent;
  readonly eventType?: OpenPlatformWebhookEvent;
  readonly status: OpenPlatformWebhookDeliveryStatus;
  readonly attempt: number;
  readonly maxAttempts?: number;
  readonly idempotencyKey: string;
  readonly payload?: string;
  readonly body?: string;
  readonly secretVersion?: number;
  readonly createdAt: string;
  readonly updatedAt?: string;
  readonly nextAttemptAt?: string;
  readonly deliveredAt?: string;
  readonly responseStatusCode?: number;
  readonly responseBodyExcerpt?: string;
  readonly errorCode?: string;
}

export const OPEN_PLATFORM_AUDIT_OUTCOMES = ["success", "failure", "denied"] as const;
export type OpenPlatformAuditOutcome = (typeof OPEN_PLATFORM_AUDIT_OUTCOMES)[number];

export const OPEN_PLATFORM_AUDIT_ACTOR_TYPES = ["user", "service", "system"] as const;
export type OpenPlatformAuditActorType = (typeof OPEN_PLATFORM_AUDIT_ACTOR_TYPES)[number];

export interface OpenPlatformAuditActor {
  readonly type: OpenPlatformAuditActorType;
  readonly id: string;
  readonly displayName?: string;
  readonly ipAddress?: string;
  readonly userAgent?: string;
}

export interface OpenPlatformAuditTarget {
  readonly type: OpenPlatformResourceType;
  readonly id: string;
  readonly displayName?: string;
}

export interface OpenPlatformAuditEventDto {
  readonly contractVersion: typeof OPEN_PLATFORM_CONTRACT_VERSION;
  readonly id: string;
  readonly tenantId: string;
  readonly developerOrganizationId?: string;
  readonly action: string;
  readonly outcome: OpenPlatformAuditOutcome;
  readonly actor: OpenPlatformAuditActor;
  readonly target: OpenPlatformAuditTarget;
  readonly requestId?: string;
  readonly metadata: Readonly<Record<string, string | number | boolean | null>>;
  readonly occurredAt: string;
  readonly source?: string;
}

export interface OpenPlatformAuditEventRecord extends OpenPlatformAuditEventDto {
  readonly sequence: number;
  readonly source: string;
  readonly previousHash?: string;
  readonly eventHash: string;
}

export interface OpenPlatformAuditQuery extends OpenPlatformPageRequest {
  readonly tenantId: string;
  readonly action?: string;
  readonly outcome?: OpenPlatformAuditOutcome;
  readonly targetId?: string;
}

export interface OpenPlatformAuditAppendInput {
  readonly tenantId: string;
  readonly action: string;
  readonly outcome: OpenPlatformAuditOutcome;
  readonly actor: OpenPlatformAuditActor;
  readonly target: OpenPlatformAuditTarget;
  readonly requestId?: string;
  readonly metadata?: Readonly<Record<string, string | number | boolean | null>>;
  readonly occurredAt?: string;
  readonly source?: string;
  readonly id?: string;
}

export interface OpenPlatformWebhookEventEnvelope {
  readonly eventId: string;
  readonly eventType: OpenPlatformWebhookEvent;
  readonly occurredAt: string;
  readonly tenantId: string;
  readonly actor?: {
    readonly type: "user" | "service" | "system";
    readonly id: string;
  };
  readonly resource?: {
    readonly type: string;
    readonly id: string;
    readonly version?: number;
    readonly status?: string;
  };
  readonly data?: Readonly<Record<string, unknown>>;
  readonly schemaVersion: string;
  readonly requestId?: string;
  readonly traceId?: string;
}

export interface OpenPlatformWebhookCreateInput {
  readonly applicationId: string;
  readonly environmentId: string;
  readonly developerOrganizationId?: string;
  readonly name: string;
  readonly endpointUrl: string;
  readonly events: readonly OpenPlatformWebhookEvent[];
  readonly tenantId?: string;
  readonly idempotencyKey?: string;
}

export interface OpenPlatformWebhookSecretIssueResult {
  readonly webhook: OpenPlatformWebhookDto;
  readonly secret: string;
  readonly secretVersion: number;
  readonly replayed?: boolean;
}

export interface OpenPlatformWebhookDeliveryQuery extends OpenPlatformPageRequest {
  readonly tenantId: string;
  readonly webhookId?: string;
  readonly eventId?: string;
  readonly status?: OpenPlatformWebhookDeliveryStatus;
}

export interface OpenPlatformWebhookReplayInput {
  readonly tenantId: string;
  readonly webhookId: string;
  readonly deliveryId: string;
  readonly idempotencyKey?: string;
}

export interface OpenPlatformWebhookDispatchResult {
  readonly delivery: OpenPlatformWebhookDeliveryRecord;
  readonly deliveries: readonly OpenPlatformWebhookDeliveryRecord[];
  readonly attempts: number;
  readonly duplicate: boolean;
  readonly deadLettered: boolean;
}

export interface OpenPlatformWebhookSignatureHeaders {
  readonly signature: string;
  readonly timestamp: string;
  readonly secretVersion: string;
}

export interface OpenPlatformWebhookSignatureInput {
  readonly timestamp: string | number;
  readonly body: string | Uint8Array;
  readonly secret: string;
  readonly secretVersion: string | number;
}

export type OpenPlatformWebhookSubscriptionDto = OpenPlatformWebhookDto;
export type OpenPlatformWebhookSubscriptionRecord = OpenPlatformWebhookRecord;
export type OpenPlatformWebhookSecretVersion = number;
export type OpenPlatformWebhookSignature = string;
export type OpenPlatformAuditEventPage = OpenPlatformPage<OpenPlatformAuditEventRecord>;
export type OpenPlatformWebhookDeliveryPage = OpenPlatformPage<OpenPlatformWebhookDeliveryRecord>;

export const OPEN_PLATFORM_DEFAULT_PAGE_SIZE = 20 as const;
export const OPEN_PLATFORM_MAX_PAGE_SIZE = 100 as const;

export interface OpenPlatformPageRequest {
  readonly cursor?: string;
  readonly limit?: number | string;
}

export interface OpenPlatformNormalizedPageRequest {
  readonly cursor?: string;
  readonly limit: number;
}

export interface OpenPlatformPage<T> {
  readonly items: readonly T[];
  readonly nextCursor?: string;
  readonly previousCursor?: string;
  readonly hasMore: boolean;
  readonly total?: number;
}

export interface OpenPlatformListQuery extends OpenPlatformPageRequest {
  readonly search?: string;
  readonly status?: string;
  readonly sort?: string;
}

export const OPEN_PLATFORM_ERROR_CODES = {
  INVALID_ARGUMENT: "INVALID_ARGUMENT",
  INVALID_STATUS: "INVALID_STATUS",
  INVALID_SLUG: "INVALID_SLUG",
  INVALID_SCOPE: "INVALID_SCOPE",
  INVALID_REDIRECT_URI: "INVALID_REDIRECT_URI",
  INVALID_CLIENT_CONFIGURATION: "INVALID_CLIENT_CONFIGURATION",
  INVALID_STATE_TRANSITION: "INVALID_STATE_TRANSITION",
  TENANT_MISMATCH: "TENANT_MISMATCH",
  CREDENTIAL_EXPOSED: "CREDENTIAL_EXPOSED",
  NOT_FOUND: "NOT_FOUND",
  CONFLICT: "CONFLICT",
  RATE_LIMITED: "RATE_LIMITED",
  TEMPORARILY_UNAVAILABLE: "TEMPORARILY_UNAVAILABLE",
  INTERNAL_ERROR: "INTERNAL_ERROR",
} as const;
export type OpenPlatformErrorCode = (typeof OPEN_PLATFORM_ERROR_CODES)[keyof typeof OPEN_PLATFORM_ERROR_CODES];

export interface OpenPlatformErrorDefinition {
  readonly status: number;
  readonly retryable: boolean;
  readonly message: string;
}

export const OPEN_PLATFORM_ERROR_DEFINITIONS = {
  INVALID_ARGUMENT: { status: 400, retryable: false, message: "The open platform request is invalid." },
  INVALID_STATUS: { status: 400, retryable: false, message: "The resource status is invalid." },
  INVALID_SLUG: { status: 400, retryable: false, message: "The slug is invalid." },
  INVALID_SCOPE: { status: 400, retryable: false, message: "The scope value is invalid." },
  INVALID_REDIRECT_URI: {
    status: 400,
    retryable: false,
    message: "The redirect URI is not allowed.",
  },
  INVALID_CLIENT_CONFIGURATION: {
    status: 400,
    retryable: false,
    message: "The client configuration is invalid.",
  },
  INVALID_STATE_TRANSITION: {
    status: 409,
    retryable: false,
    message: "The resource state transition is not allowed.",
  },
  TENANT_MISMATCH: {
    status: 403,
    retryable: false,
    message: "The resource is outside the active tenant boundary.",
  },
  CREDENTIAL_EXPOSED: {
    status: 400,
    retryable: false,
    message: "Credential material must not be supplied to this contract.",
  },
  NOT_FOUND: { status: 404, retryable: false, message: "The requested resource was not found." },
  CONFLICT: { status: 409, retryable: false, message: "The resource state conflicts with the request." },
  RATE_LIMITED: { status: 429, retryable: true, message: "The request rate limit was exceeded." },
  TEMPORARILY_UNAVAILABLE: {
    status: 503,
    retryable: true,
    message: "The service is temporarily unavailable.",
  },
  INTERNAL_ERROR: { status: 500, retryable: true, message: "The service could not complete the request." },
} as const satisfies Record<OpenPlatformErrorCode, OpenPlatformErrorDefinition>;

export interface OpenPlatformErrorIssue {
  readonly code: OpenPlatformErrorCode;
  readonly field?: string;
}

export interface OpenPlatformErrorContext {
  readonly field?: string;
  readonly requestId?: string;
  readonly issues?: readonly OpenPlatformErrorIssue[];
}

export interface OpenPlatformSafeError extends OpenPlatformErrorDefinition {
  readonly code: OpenPlatformErrorCode;
  readonly field?: string;
  readonly issues?: readonly OpenPlatformErrorIssue[];
}

export interface OpenPlatformErrorResponse {
  readonly error: OpenPlatformSafeError;
  readonly requestId?: string;
}

export class OpenPlatformContractError extends Error {
  readonly code: OpenPlatformErrorCode;
  readonly status: number;
  readonly retryable: boolean;
  readonly field: string | undefined;

  constructor(code: OpenPlatformErrorCode, field?: string) {
    const definition = OPEN_PLATFORM_ERROR_DEFINITIONS[code];
    super(definition.message);
    this.name = "OpenPlatformContractError";
    this.code = code;
    this.status = definition.status;
    this.retryable = definition.retryable;
    this.field = sanitizeOpenPlatformErrorField(field);
  }

  toResponse(requestId?: string): OpenPlatformErrorResponse {
    const safeRequestId = sanitizeOpenPlatformRequestId(requestId);
    return createOpenPlatformError(this.code, {
      ...(this.field === undefined ? {} : { field: this.field }),
      ...(safeRequestId === undefined ? {} : { requestId: safeRequestId }),
    });
  }
}

export function createOpenPlatformError(
  code: OpenPlatformErrorCode,
  context: OpenPlatformErrorContext = {},
): OpenPlatformErrorResponse {
  const definition = OPEN_PLATFORM_ERROR_DEFINITIONS[code];
  const field = sanitizeOpenPlatformErrorField(context.field);
  const requestId = sanitizeOpenPlatformRequestId(context.requestId);
  const issues = sanitizeOpenPlatformErrorIssues(context.issues);
  const error: OpenPlatformSafeError = {
    code,
    ...definition,
    ...(field === undefined ? {} : { field }),
    ...(issues === undefined ? {} : { issues }),
  };
  return {
    error,
    ...(requestId === undefined ? {} : { requestId }),
  };
}

export function mapControlPlaneLifecycleStatus(value: unknown): OpenPlatformLifecycleStatus {
  if (
    typeof value !== "string" ||
    !(OPEN_PLATFORM_LIFECYCLE_STATUSES as readonly string[]).includes(value)
  ) {
    throw new OpenPlatformContractError(OPEN_PLATFORM_ERROR_CODES.INVALID_STATUS, "status");
  }
  return OPEN_PLATFORM_CONTROL_PLANE_LIFECYCLE_STATUS_MAP[
    value as keyof typeof OPEN_PLATFORM_CONTROL_PLANE_LIFECYCLE_STATUS_MAP
  ];
}

export const mapControlPlaneApplicationStatus = mapControlPlaneLifecycleStatus;
export const mapControlPlaneApplicationPublicationStatus = mapControlPlaneLifecycleStatus;
export const mapControlPlaneSubscriptionStatus = mapControlPlaneLifecycleStatus;

export function mapControlPlaneApiVersionStatus(value: unknown): OpenPlatformApiVersionStatus {
  const status = mapControlPlaneLifecycleStatus(value);
  switch (status) {
    case "draft":
      return "draft";
    case "published":
      return "active";
    case "disabled":
      return "deprecated";
    case "archived":
      return "retired";
  }
}

export function mapOpenPlatformLifecycleToSubscriptionBillingStatus(
  value: OpenPlatformLifecycleStatus,
): OpenPlatformSubscriptionBillingStatus {
  switch (value) {
    case "draft":
      return "trialing";
    case "published":
      return "active";
    case "disabled":
      return "suspended";
    case "archived":
      return "canceled";
  }
}

export function mapControlPlaneCredentialStatus(value: unknown): OpenPlatformCredentialStatus {
  if (
    typeof value !== "string" ||
    !(OPEN_PLATFORM_CREDENTIAL_STATUSES as readonly string[]).includes(value)
  ) {
    throw new OpenPlatformContractError(OPEN_PLATFORM_ERROR_CODES.INVALID_STATUS, "status");
  }
  return OPEN_PLATFORM_CONTROL_PLANE_CREDENTIAL_STATUS_MAP[
    value as keyof typeof OPEN_PLATFORM_CONTROL_PLANE_CREDENTIAL_STATUS_MAP
  ];
}

export function resolveOpenPlatformCredentialStatus(
  value: unknown,
  expiresAt?: string,
  now: string = new Date().toISOString(),
): OpenPlatformCredentialStatus {
  const status = mapControlPlaneCredentialStatus(value);
  const nowTime = Date.parse(now);
  if (!Number.isFinite(nowTime)) {
    throw new OpenPlatformContractError(OPEN_PLATFORM_ERROR_CODES.INVALID_ARGUMENT, "now");
  }
  if (expiresAt === undefined) return status;
  const expiresTime = Date.parse(expiresAt);
  if (!Number.isFinite(expiresTime)) {
    throw new OpenPlatformContractError(OPEN_PLATFORM_ERROR_CODES.INVALID_ARGUMENT, "expiresAt");
  }
  if (
    expiresTime <= nowTime &&
    (status === "pending" || status === "active" || status === "rotating")
  ) {
    return "expired";
  }
  return status;
}

export function toOpenPlatformCredentialDto(
  record: OpenPlatformControlPlaneCredentialSource,
  options: OpenPlatformCredentialProjectionOptions = {},
): OpenPlatformCredentialDto {
  const kind = options.kind ?? "api_key";
  if (!isOpenPlatformCredentialKind(kind)) {
    throw new OpenPlatformContractError(
      OPEN_PLATFORM_ERROR_CODES.INVALID_ARGUMENT,
      "kind",
    );
  }
  const fingerprint = typeof record.fingerprint === "string" ? record.fingerprint : "";
  return {
    contractVersion: OPEN_PLATFORM_CONTRACT_VERSION,
    id: record.id,
    tenantId: record.tenantId,
    ...(options.developerOrganizationId === undefined
      ? {}
      : { developerOrganizationId: options.developerOrganizationId }),
    applicationId: record.applicationId,
    ...(record.environmentId === undefined ? {} : { environmentId: record.environmentId }),
    name: record.name,
    kind,
    status: resolveOpenPlatformCredentialStatus(
      record.status,
      record.expiresAt,
      options.now,
    ),
    scopes: normalizeOpenPlatformScopes(record.scopes),
    ...(fingerprint.length < 4 ? {} : { lastFour: fingerprint.slice(-4) }),
    version: record.version,
    createdAt: record.createdAt,
    ...(record.updatedAt === undefined ? {} : { updatedAt: record.updatedAt }),
    ...(record.expiresAt === undefined ? {} : { expiresAt: record.expiresAt }),
    ...(record.rotatedAt === undefined ? {} : { rotatedAt: record.rotatedAt }),
    ...(record.revokedAt === undefined ? {} : { revokedAt: record.revokedAt }),
    ...(record.previousCredentialId === undefined
      ? {}
      : { previousCredentialId: record.previousCredentialId }),
    ...(record.replacedByCredentialId === undefined
      ? {}
      : { replacedByCredentialId: record.replacedByCredentialId }),
  };
}

export function parseOpenPlatformScopes(value: unknown): OpenPlatformScope[] {
  if (typeof value !== "string" || value.length > 8192 || /[\u0000-\u001f\u007f]/u.test(value)) {
    throw new OpenPlatformContractError(OPEN_PLATFORM_ERROR_CODES.INVALID_SCOPE, "scope");
  }
  const normalized = value.trim();
  if (normalized.length === 0) {
    throw new OpenPlatformContractError(OPEN_PLATFORM_ERROR_CODES.INVALID_SCOPE, "scope");
  }
  const tokens = normalized.split(" ").filter((token) => token.length > 0);
  if (tokens.length > 100) {
    throw new OpenPlatformContractError(OPEN_PLATFORM_ERROR_CODES.INVALID_SCOPE, "scope");
  }
  const scopes: OpenPlatformScope[] = [];
  for (const token of tokens) {
    assertOpenPlatformScopeToken(token, "scope");
    scopes.push(token);
  }
  return sortOpenPlatformScopes(scopes);
}

export function normalizeOpenPlatformScopes(value: string | readonly string[]): OpenPlatformScope[] {
  if (typeof value === "string") return parseOpenPlatformScopes(value);
  if (!Array.isArray(value) || value.length === 0 || value.length > 100) {
    throw new OpenPlatformContractError(OPEN_PLATFORM_ERROR_CODES.INVALID_SCOPE, "scopes");
  }
  const scopes: OpenPlatformScope[] = [];
  for (const item of value) {
    if (typeof item !== "string") {
      throw new OpenPlatformContractError(OPEN_PLATFORM_ERROR_CODES.INVALID_SCOPE, "scopes");
    }
    assertOpenPlatformScopeToken(item, "scopes");
    scopes.push(item);
  }
  return sortOpenPlatformScopes(scopes);
}

export function formatOpenPlatformScopes(scopes: readonly OpenPlatformScope[]): string {
  return normalizeOpenPlatformScopes(scopes).join(" ");
}

export function isValidOpenPlatformSlug(value: unknown): value is string {
  return typeof value === "string" && /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u.test(value);
}

export function validateOpenPlatformSlug(value: unknown): string {
  if (!isValidOpenPlatformSlug(value)) {
    throw new OpenPlatformContractError(OPEN_PLATFORM_ERROR_CODES.INVALID_SLUG, "slug");
  }
  return value;
}

export type OpenPlatformRedirectUriClientKind = Extract<OpenPlatformClientKind, "web" | "native">;

export interface OpenPlatformRedirectUriOptions {
  readonly clientKind?: OpenPlatformRedirectUriClientKind;
  readonly allowLoopbackHttp?: boolean;
  readonly allowedHosts?: readonly string[];
  readonly allowedCustomSchemes?: readonly string[];
}

export function isValidOpenPlatformRedirectUri(
  value: unknown,
  options: OpenPlatformRedirectUriOptions = {},
): value is string {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > 2048 ||
    value !== value.trim() ||
    /[\u0000-\u0020\u007f\\]/u.test(value) ||
    /%(?:0a|0d)/iu.test(value)
  ) {
    return false;
  }
  if (!isOpenPlatformRecord(options)) return false;
  if (options.allowedHosts !== undefined && !Array.isArray(options.allowedHosts)) return false;
  if (options.allowedCustomSchemes !== undefined && !Array.isArray(options.allowedCustomSchemes)) return false;
  const clientKind = options.clientKind ?? "web";
  if (clientKind !== "web" && clientKind !== "native") return false;
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    return false;
  }
  if (parsed.username !== "" || parsed.password !== "" || parsed.hash !== "") return false;
  if (options.allowedHosts !== undefined && !hostMatchesAllowList(parsed.hostname, options.allowedHosts)) {
    return false;
  }
  if (parsed.protocol === "https:") return parsed.hostname.length > 0;
  if (parsed.protocol === "http:") {
    return (
      options.allowLoopbackHttp === true &&
      parsed.hostname.length > 0 &&
      isLoopbackHostname(parsed.hostname)
    );
  }
  if (clientKind !== "native" || options.allowedCustomSchemes === undefined) return false;
  const scheme = parsed.protocol.slice(0, -1).toLowerCase();
  if (
    scheme.length === 0 ||
    scheme === "http" ||
    scheme === "https" ||
    !options.allowedCustomSchemes.some(
      (allowed) => typeof allowed === "string" && allowed.toLowerCase() === scheme,
    )
  ) {
    return false;
  }
  return parsed.hostname.length > 0 || parsed.pathname.length > 0;
}

export function validateOpenPlatformRedirectUri(
  value: unknown,
  options: OpenPlatformRedirectUriOptions = {},
): string {
  if (!isValidOpenPlatformRedirectUri(value, options)) {
    throw new OpenPlatformContractError(
      OPEN_PLATFORM_ERROR_CODES.INVALID_REDIRECT_URI,
      "redirectUri",
    );
  }
  return value;
}

export function validateOpenPlatformRedirectUris(
  value: unknown,
  options: OpenPlatformRedirectUriOptions = {},
): string[] {
  if (!Array.isArray(value) || value.length === 0 || value.length > 100) {
    throw new OpenPlatformContractError(
      OPEN_PLATFORM_ERROR_CODES.INVALID_REDIRECT_URI,
      "redirectUris",
    );
  }
  const output: string[] = [];
  for (const item of value) {
    const redirectUri = validateOpenPlatformRedirectUri(item, options);
    if (output.includes(redirectUri)) {
      throw new OpenPlatformContractError(
        OPEN_PLATFORM_ERROR_CODES.INVALID_REDIRECT_URI,
        "redirectUris",
      );
    }
    output.push(redirectUri);
  }
  return output;
}

export function normalizeOpenPlatformPageRequest(value: unknown = {}): OpenPlatformNormalizedPageRequest {
  if (!isOpenPlatformRecord(value)) {
    throw new OpenPlatformContractError(OPEN_PLATFORM_ERROR_CODES.INVALID_ARGUMENT, "page");
  }
  const cursor = value.cursor;
  if (
    cursor !== undefined &&
    (typeof cursor !== "string" || cursor.length === 0 || cursor.length > 2048 || /[\u0000-\u001f\u007f]/u.test(cursor))
  ) {
    throw new OpenPlatformContractError(OPEN_PLATFORM_ERROR_CODES.INVALID_ARGUMENT, "cursor");
  }
  const rawLimit = value.limit;
  const limit = rawLimit === undefined
    ? OPEN_PLATFORM_DEFAULT_PAGE_SIZE
    : typeof rawLimit === "number"
      ? rawLimit
      : typeof rawLimit === "string" && /^[1-9][0-9]{0,2}$/u.test(rawLimit)
        ? Number(rawLimit)
        : Number.NaN;
  if (!Number.isInteger(limit) || limit < 1 || limit > OPEN_PLATFORM_MAX_PAGE_SIZE) {
    throw new OpenPlatformContractError(OPEN_PLATFORM_ERROR_CODES.INVALID_ARGUMENT, "limit");
  }
  return {
    ...(cursor === undefined ? {} : { cursor: cursor as string }),
    limit,
  };
}

export function getOpenPlatformLifecycleTransition(
  from: OpenPlatformLifecycleStatus,
  event: OpenPlatformLifecycleEvent,
): OpenPlatformLifecycleTransition | undefined {
  switch (from) {
    case "draft":
      if (event === "publish") return { from, event, to: "published" };
      if (event === "archive") return { from, event, to: "archived" };
      return undefined;
    case "published":
      if (event === "disable") return { from, event, to: "disabled" };
      if (event === "archive") return { from, event, to: "archived" };
      return undefined;
    case "disabled":
      if (event === "republish") return { from, event, to: "published" };
      if (event === "archive") return { from, event, to: "archived" };
      return undefined;
    case "archived":
      return undefined;
  }
}

export function canTransitionOpenPlatformLifecycle(
  from: OpenPlatformLifecycleStatus,
  event: OpenPlatformLifecycleEvent,
): boolean {
  return getOpenPlatformLifecycleTransition(from, event) !== undefined;
}

export function transitionOpenPlatformLifecycle(
  from: OpenPlatformLifecycleStatus,
  event: OpenPlatformLifecycleEvent,
): OpenPlatformLifecycleStatus {
  const transition = getOpenPlatformLifecycleTransition(from, event);
  if (transition === undefined) {
    throw new OpenPlatformContractError(
      OPEN_PLATFORM_ERROR_CODES.INVALID_STATE_TRANSITION,
      "lifecycle.status",
    );
  }
  return transition.to;
}

export const getOpenPlatformApplicationTransition = getOpenPlatformLifecycleTransition;
export const canTransitionOpenPlatformApplication = canTransitionOpenPlatformLifecycle;
export const transitionOpenPlatformApplication = transitionOpenPlatformLifecycle;

export function getOpenPlatformCredentialTransition(
  from: OpenPlatformCredentialStatus,
  event: OpenPlatformCredentialEvent,
): OpenPlatformCredentialTransition | undefined {
  switch (from) {
    case "pending":
      if (event === "activate") return { from, event, to: "active" };
      if (event === "expire") return { from, event, to: "expired" };
      if (event === "revoke") return { from, event, to: "revoked" };
      return undefined;
    case "active":
      if (event === "rotate") return { from, event, to: "rotating" };
      if (event === "mark_rotated") return { from, event, to: "rotated" };
      if (event === "expire") return { from, event, to: "expired" };
      if (event === "revoke") return { from, event, to: "revoked" };
      return undefined;
    case "rotating":
      if (event === "complete") return { from, event, to: "active" };
      if (event === "mark_rotated") return { from, event, to: "rotated" };
      if (event === "expire") return { from, event, to: "expired" };
      if (event === "revoke") return { from, event, to: "revoked" };
      return undefined;
    case "rotated":
      return undefined;
    case "expired":
      if (event === "rotate") return { from, event, to: "rotating" };
      if (event === "revoke") return { from, event, to: "revoked" };
      return undefined;
    case "revoked":
      return undefined;
  }
}

export function canTransitionOpenPlatformCredential(
  from: OpenPlatformCredentialStatus,
  event: OpenPlatformCredentialEvent,
): boolean {
  return getOpenPlatformCredentialTransition(from, event) !== undefined;
}

export function transitionOpenPlatformCredential(
  from: OpenPlatformCredentialStatus,
  event: OpenPlatformCredentialEvent,
): OpenPlatformCredentialStatus {
  const transition = getOpenPlatformCredentialTransition(from, event);
  if (transition === undefined) {
    throw new OpenPlatformContractError(
      OPEN_PLATFORM_ERROR_CODES.INVALID_STATE_TRANSITION,
      "credential.status",
    );
  }
  return transition.to;
}

export function getOpenPlatformSubscriptionTransition(
  from: OpenPlatformSubscriptionBillingStatus,
  event: OpenPlatformSubscriptionEvent,
): OpenPlatformSubscriptionTransition | undefined {
  switch (from) {
    case "trialing":
      if (event === "activate") return { from, event, to: "active" };
      if (event === "cancel") return { from, event, to: "canceled" };
      if (event === "expire") return { from, event, to: "expired" };
      return undefined;
    case "active":
      if (event === "mark_past_due") return { from, event, to: "past_due" };
      if (event === "suspend") return { from, event, to: "suspended" };
      if (event === "cancel") return { from, event, to: "canceled" };
      if (event === "expire") return { from, event, to: "expired" };
      return undefined;
    case "past_due":
      if (event === "resume") return { from, event, to: "active" };
      if (event === "suspend") return { from, event, to: "suspended" };
      if (event === "cancel") return { from, event, to: "canceled" };
      if (event === "expire") return { from, event, to: "expired" };
      return undefined;
    case "suspended":
      if (event === "resume") return { from, event, to: "active" };
      if (event === "cancel") return { from, event, to: "canceled" };
      if (event === "expire") return { from, event, to: "expired" };
      return undefined;
    case "canceled":
    case "expired":
      return undefined;
  }
}

export function canTransitionOpenPlatformSubscription(
  from: OpenPlatformSubscriptionBillingStatus,
  event: OpenPlatformSubscriptionEvent,
): boolean {
  return getOpenPlatformSubscriptionTransition(from, event) !== undefined;
}

export function transitionOpenPlatformSubscription(
  from: OpenPlatformSubscriptionBillingStatus,
  event: OpenPlatformSubscriptionEvent,
): OpenPlatformSubscriptionBillingStatus {
  const transition = getOpenPlatformSubscriptionTransition(from, event);
  if (transition === undefined) {
    throw new OpenPlatformContractError(
      OPEN_PLATFORM_ERROR_CODES.INVALID_STATE_TRANSITION,
      "subscription.status",
    );
  }
  return transition.to;
}

function sortOpenPlatformScopes(scopes: readonly OpenPlatformScope[]): OpenPlatformScope[] {
  return [...new Set(scopes)].sort((left, right) => left < right ? -1 : left > right ? 1 : 0);
}

function assertOpenPlatformScopeToken(value: string, field: string): void {
  if (
    value.length === 0 ||
    value.length > 128 ||
    !/^[\u0021\u0023-\u005b\u005d-\u007e]+$/u.test(value)
  ) {
    throw new OpenPlatformContractError(OPEN_PLATFORM_ERROR_CODES.INVALID_SCOPE, field);
  }
}

function isLoopbackHostname(hostname: string): boolean {
  const normalized = hostname.toLowerCase();
  if (normalized === "localhost" || normalized === "[::1]") return true;
  const octets = normalized.split(".");
  return (
    octets.length === 4 &&
    octets.every((octet) => /^[0-9]{1,3}$/u.test(octet) && Number(octet) <= 255) &&
    octets[0] === "127"
  );
}

function hostMatchesAllowList(hostname: string, allowedHosts: readonly string[]): boolean {
  const normalizedHostname = hostname.toLowerCase();
  return allowedHosts.some((host) => typeof host === "string" && host.toLowerCase() === normalizedHostname);
}

function isOpenPlatformRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function sanitizeOpenPlatformErrorField(value: unknown): string | undefined {
  if (typeof value !== "string" || value.length === 0 || value.length > 256) return undefined;
  return /^[A-Za-z0-9_.[\]-]+$/u.test(value) ? value : undefined;
}

function sanitizeOpenPlatformRequestId(value: unknown): string | undefined {
  if (typeof value !== "string" || value.length === 0 || value.length > 128) return undefined;
  return /^[A-Za-z0-9_-]+$/u.test(value) ? value : undefined;
}

function sanitizeOpenPlatformErrorIssues(value: unknown): readonly OpenPlatformErrorIssue[] | undefined {
  if (!Array.isArray(value) || value.length === 0 || value.length > 20) return undefined;
  const issues: OpenPlatformErrorIssue[] = [];
  for (const item of value) {
    if (!isOpenPlatformRecord(item) || !isOpenPlatformErrorCode(item.code)) continue;
    const field = sanitizeOpenPlatformErrorField(item.field);
    issues.push({
      code: item.code,
      ...(field === undefined ? {} : { field }),
    });
  }
  return issues.length === 0 ? undefined : issues;
}

function isOpenPlatformCredentialKind(value: unknown): value is OpenPlatformCredentialKind {
  return (
    typeof value === "string" &&
    (OPEN_PLATFORM_CREDENTIAL_KINDS as readonly string[]).includes(value)
  );
}

function isOpenPlatformErrorCode(value: unknown): value is OpenPlatformErrorCode {
  return (
    typeof value === "string" &&
    (Object.values(OPEN_PLATFORM_ERROR_CODES) as readonly string[]).includes(value)
  );
}
