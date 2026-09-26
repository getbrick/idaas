import {
  invalidIdempotencyKey,
  validationError,
} from "./errors.js";
import {
  isOpenPlatformLifecycleStatus,
} from "./state-machine.js";
import {
  OPEN_PLATFORM_LIFECYCLE_RESOURCE_KINDS,
  type ApiProductQuery,
  type ApiVersionQuery,
  type ApplicationEnvironmentQuery,
  type ApplicationQuery,
  type AuthorizeScopesCommand,
  type CreateApiProductCommand,
  type CreateApiVersionCommand,
  type CreateApplicationCommand,
  type CreateApplicationEnvironmentCommand,
  type CreateDeveloperOrganizationCommand,
  type CreateSubscriptionCommand,
  type CreateTenantCommand,
  type CredentialQuery,
  type DeveloperOrganizationQuery,
  type GrantScopesCommand,
  type IssueCredentialCommand,
  type LifecycleCommand,
  type LifecycleTransitionCommand,
  type OpenPlatformEntityKind,
  type OpenPlatformLifecycleResourceKind,
  type RecordUsageCommand,
  type RevokeCredentialCommand,
  type RevokeScopeGrantCommand,
  type RotateCredentialCommand,
  type ScopeGrantQuery,
  type SubscriptionQuery,
  type TenantQuery,
  type UsageQuery,
} from "./types.js";

export const OPEN_PLATFORM_RESOURCE_ID_PREFIXES = Object.freeze({
  tenant: "tenant",
  developerOrganization: "org",
  application: "app",
  applicationEnvironment: "env",
  apiProduct: "product",
  apiVersion: "apiver",
  subscription: "subscription",
  credential: "credential",
  scopeGrant: "grant",
  usage: "usage",
  webhook: "webhook",
  auditEvent: "audit",
} satisfies Readonly<Record<OpenPlatformEntityKind, string>>);

export interface NormalizedCreateTenantCommand {
  tenantId: string;
  name: string;
  idempotencyKey: string;
}

export interface NormalizedTenantQuery {
  tenantId: string;
}

export interface NormalizedCreateDeveloperOrganizationCommand {
  tenantId: string;
  name: string;
  description?: string;
  idempotencyKey: string;
}

export interface NormalizedDeveloperOrganizationQuery {
  tenantId: string;
  id?: string;
}

export interface NormalizedCreateApplicationCommand {
  tenantId: string;
  organizationId: string;
  name: string;
  description?: string;
  idempotencyKey: string;
}

export interface NormalizedApplicationQuery {
  tenantId: string;
  id?: string;
}

export interface NormalizedCreateApplicationEnvironmentCommand {
  tenantId: string;
  applicationId: string;
  name: string;
  idempotencyKey: string;
}

export interface NormalizedApplicationEnvironmentQuery {
  tenantId: string;
  applicationId?: string;
  id?: string;
}

export interface NormalizedCreateApiProductCommand {
  tenantId: string;
  name: string;
  description?: string;
  scopes: string[];
  idempotencyKey: string;
}

export interface NormalizedApiProductQuery {
  tenantId: string;
  id?: string;
}

export interface NormalizedCreateApiVersionCommand {
  tenantId: string;
  productId: string;
  apiVersion: string;
  description?: string;
  scopes: string[];
  idempotencyKey: string;
}

export interface NormalizedApiVersionQuery {
  tenantId: string;
  productId?: string;
  id?: string;
}

export interface NormalizedIssueCredentialCommand {
  tenantId: string;
  applicationId: string;
  environmentId?: string;
  name: string;
  scopes: string[];
  expiresAt?: string;
  idempotencyKey: string;
}

export interface NormalizedRotateCredentialCommand {
  tenantId: string;
  credentialId: string;
  idempotencyKey: string;
}

export interface NormalizedRevokeCredentialCommand {
  tenantId: string;
  credentialId: string;
  idempotencyKey: string;
}

export interface NormalizedCredentialQuery {
  tenantId: string;
  applicationId?: string;
  environmentId?: string;
  id?: string;
}

export interface NormalizedCreateSubscriptionCommand {
  tenantId: string;
  applicationId: string;
  productId: string;
  apiVersionId?: string;
  name: string;
  scopes: string[];
  idempotencyKey: string;
}

export interface NormalizedSubscriptionQuery {
  tenantId: string;
  applicationId?: string;
  productId?: string;
  id?: string;
}

export interface NormalizedLifecycleCommand {
  resource: OpenPlatformLifecycleResourceKind;
  tenantId: string;
  id: string;
  idempotencyKey: string;
}

export interface NormalizedLifecycleTransitionCommand
  extends NormalizedLifecycleCommand {
  targetStatus: "draft" | "published" | "disabled" | "archived";
}

export interface NormalizedGrantScopesCommand {
  tenantId: string;
  credentialId: string;
  productId: string;
  apiVersionId?: string;
  scopes: string[];
  idempotencyKey: string;
}

export interface NormalizedRevokeScopeGrantCommand {
  tenantId: string;
  scopeGrantId: string;
  idempotencyKey: string;
}

export interface NormalizedAuthorizeScopesCommand {
  tenantId: string;
  credentialId: string;
  productId: string;
  apiVersionId?: string;
  scopes: string[];
}

export interface NormalizedScopeGrantQuery {
  tenantId: string;
  credentialId?: string;
  productId?: string;
  apiVersionId?: string;
  id?: string;
}

export interface NormalizedRecordUsageCommand {
  tenantId: string;
  subscriptionId: string;
  credentialId?: string;
  metric: string;
  quantity: number;
  occurredAt?: string;
  idempotencyKey: string;
}

export interface NormalizedUsageQuery {
  tenantId: string;
  subscriptionId?: string;
  credentialId?: string;
  from?: string;
  to?: string;
}

export function normalizeCreateTenantCommand(
  command: CreateTenantCommand,
): NormalizedCreateTenantCommand {
  assertCommandObject(command);
  return {
    tenantId: normalizeTenantKey(command.tenantId),
    name: normalizeText(command.name, "name", 200),
    idempotencyKey: normalizeIdempotencyKey(command.idempotencyKey),
  };
}

export function normalizeTenantQuery(query: TenantQuery): NormalizedTenantQuery {
  return { tenantId: normalizeTenantKey(query?.tenantId) };
}

export function normalizeCreateDeveloperOrganizationCommand(
  command: CreateDeveloperOrganizationCommand,
): NormalizedCreateDeveloperOrganizationCommand {
  assertCommandObject(command);
  return {
    tenantId: normalizeTenantKey(command.tenantId),
    name: normalizeText(command.name, "name", 200),
    ...optionalText(command.description, "description", 2000),
    idempotencyKey: normalizeIdempotencyKey(command.idempotencyKey),
  };
}

export function normalizeDeveloperOrganizationQuery(
  query: DeveloperOrganizationQuery,
): NormalizedDeveloperOrganizationQuery {
  return {
    tenantId: normalizeTenantKey(query?.tenantId),
    ...optionalResourceId(query?.id, "developerOrganization", "id"),
  };
}

export function normalizeCreateApplicationCommand(
  command: CreateApplicationCommand,
): NormalizedCreateApplicationCommand {
  assertCommandObject(command);
  return {
    tenantId: normalizeTenantKey(command.tenantId),
    organizationId: normalizeResourceId(
      command.organizationId,
      "developerOrganization",
    ),
    name: normalizeText(command.name, "name", 200),
    ...optionalText(command.description, "description", 2000),
    idempotencyKey: normalizeIdempotencyKey(command.idempotencyKey),
  };
}

export function normalizeApplicationQuery(
  query: ApplicationQuery,
): NormalizedApplicationQuery {
  return {
    tenantId: normalizeTenantKey(query?.tenantId),
    ...optionalResourceId(query?.id, "application", "id"),
  };
}

export function normalizeCreateApplicationEnvironmentCommand(
  command: CreateApplicationEnvironmentCommand,
): NormalizedCreateApplicationEnvironmentCommand {
  assertCommandObject(command);
  return {
    tenantId: normalizeTenantKey(command.tenantId),
    applicationId: normalizeResourceId(command.applicationId, "application"),
    name: normalizeText(command.name, "name", 200),
    idempotencyKey: normalizeIdempotencyKey(command.idempotencyKey),
  };
}

export function normalizeApplicationEnvironmentQuery(
  query: ApplicationEnvironmentQuery,
): NormalizedApplicationEnvironmentQuery {
  return {
    tenantId: normalizeTenantKey(query?.tenantId),
    ...optionalResourceId(query?.applicationId, "application"),
    ...optionalResourceId(query?.id, "applicationEnvironment", "id"),
  };
}

export function normalizeCreateApiProductCommand(
  command: CreateApiProductCommand,
): NormalizedCreateApiProductCommand {
  assertCommandObject(command);
  return {
    tenantId: normalizeTenantKey(command.tenantId),
    name: normalizeText(command.name, "name", 200),
    ...optionalText(command.description, "description", 2000),
    scopes: normalizeScopes(command.scopes, "scopes", true),
    idempotencyKey: normalizeIdempotencyKey(command.idempotencyKey),
  };
}

export function normalizeApiProductQuery(
  query: ApiProductQuery,
): NormalizedApiProductQuery {
  return {
    tenantId: normalizeTenantKey(query?.tenantId),
    ...optionalResourceId(query?.id, "apiProduct", "id"),
  };
}

export function normalizeCreateApiVersionCommand(
  command: CreateApiVersionCommand,
): NormalizedCreateApiVersionCommand {
  assertCommandObject(command);
  return {
    tenantId: normalizeTenantKey(command.tenantId),
    productId: normalizeResourceId(command.productId, "apiProduct"),
    apiVersion: normalizeApiVersion(command.apiVersion),
    ...optionalText(command.description, "description", 2000),
    scopes: normalizeScopes(command.scopes, "scopes", true),
    idempotencyKey: normalizeIdempotencyKey(command.idempotencyKey),
  };
}

export function normalizeApiVersionQuery(
  query: ApiVersionQuery,
): NormalizedApiVersionQuery {
  return {
    tenantId: normalizeTenantKey(query?.tenantId),
    ...optionalResourceId(query?.productId, "apiProduct"),
    ...optionalResourceId(query?.id, "apiVersion", "id"),
  };
}

export function normalizeIssueCredentialCommand(
  command: IssueCredentialCommand,
): NormalizedIssueCredentialCommand {
  assertCommandObject(command);
  const expiresAt = normalizeOptionalDate(command.expiresAt, "expiresAt");
  return {
    tenantId: normalizeTenantKey(command.tenantId),
    applicationId: normalizeResourceId(command.applicationId, "application"),
    ...optionalResourceId(
      command.environmentId,
      "applicationEnvironment",
      "environmentId",
    ),
    name: normalizeText(command.name, "name", 200),
    scopes: normalizeScopes(command.scopes, "scopes", true),
    ...(expiresAt === undefined ? {} : { expiresAt }),
    idempotencyKey: normalizeIdempotencyKey(command.idempotencyKey),
  };
}

export function normalizeRotateCredentialCommand(
  command: RotateCredentialCommand,
): NormalizedRotateCredentialCommand {
  assertCommandObject(command);
  return {
    tenantId: normalizeTenantKey(command.tenantId),
    credentialId: normalizeResourceId(command.credentialId, "credential"),
    idempotencyKey: normalizeIdempotencyKey(command.idempotencyKey),
  };
}

export function normalizeRevokeCredentialCommand(
  command: RevokeCredentialCommand,
): NormalizedRevokeCredentialCommand {
  assertCommandObject(command);
  return {
    tenantId: normalizeTenantKey(command.tenantId),
    credentialId: normalizeResourceId(command.credentialId, "credential"),
    idempotencyKey: normalizeIdempotencyKey(command.idempotencyKey),
  };
}

export function normalizeCredentialQuery(
  query: CredentialQuery,
): NormalizedCredentialQuery {
  return {
    tenantId: normalizeTenantKey(query?.tenantId),
    ...optionalResourceId(query?.applicationId, "application"),
    ...optionalResourceId(
      query?.environmentId,
      "applicationEnvironment",
      "environmentId",
    ),
    ...optionalResourceId(query?.id, "credential", "id"),
  };
}

export function normalizeCreateSubscriptionCommand(
  command: CreateSubscriptionCommand,
): NormalizedCreateSubscriptionCommand {
  assertCommandObject(command);
  return {
    tenantId: normalizeTenantKey(command.tenantId),
    applicationId: normalizeResourceId(command.applicationId, "application"),
    productId: normalizeResourceId(command.productId, "apiProduct"),
    ...optionalResourceId(command.apiVersionId, "apiVersion"),
    name: normalizeText(command.name, "name", 200),
    scopes: normalizeScopes(command.scopes, "scopes", true),
    idempotencyKey: normalizeIdempotencyKey(command.idempotencyKey),
  };
}

export function normalizeSubscriptionQuery(
  query: SubscriptionQuery,
): NormalizedSubscriptionQuery {
  return {
    tenantId: normalizeTenantKey(query?.tenantId),
    ...optionalResourceId(query?.applicationId, "application"),
    ...optionalResourceId(query?.productId, "apiProduct"),
    ...optionalResourceId(query?.id, "subscription", "id"),
  };
}

export function normalizeLifecycleCommand(
  command: LifecycleCommand,
): NormalizedLifecycleCommand {
  assertCommandObject(command);
  const resource = normalizeLifecycleResource(command.resource);
  return {
    resource,
    tenantId: normalizeTenantKey(command.tenantId),
    id: normalizeResourceId(command.id, resource),
    idempotencyKey: normalizeIdempotencyKey(command.idempotencyKey),
  };
}

export function normalizeLifecycleTransitionCommand(
  command: LifecycleTransitionCommand,
): NormalizedLifecycleTransitionCommand {
  const normalized = normalizeLifecycleCommand(command);
  if (!isOpenPlatformLifecycleStatus(command?.targetStatus)) {
    throw validationError("Lifecycle target status is invalid", {
      field: "targetStatus",
    });
  }
  return { ...normalized, targetStatus: command.targetStatus };
}

export function normalizeGrantScopesCommand(
  command: GrantScopesCommand,
): NormalizedGrantScopesCommand {
  assertCommandObject(command);
  return {
    tenantId: normalizeTenantKey(command.tenantId),
    credentialId: normalizeResourceId(command.credentialId, "credential"),
    productId: normalizeResourceId(command.productId, "apiProduct"),
    ...optionalResourceId(command.apiVersionId, "apiVersion"),
    scopes: normalizeScopes(command.scopes, "scopes", true),
    idempotencyKey: normalizeIdempotencyKey(command.idempotencyKey),
  };
}

export function normalizeRevokeScopeGrantCommand(
  command: RevokeScopeGrantCommand,
): NormalizedRevokeScopeGrantCommand {
  assertCommandObject(command);
  return {
    tenantId: normalizeTenantKey(command.tenantId),
    scopeGrantId: normalizeResourceId(command.scopeGrantId, "scopeGrant"),
    idempotencyKey: normalizeIdempotencyKey(command.idempotencyKey),
  };
}

export function normalizeAuthorizeScopesCommand(
  command: AuthorizeScopesCommand,
): NormalizedAuthorizeScopesCommand {
  assertCommandObject(command);
  return {
    tenantId: normalizeTenantKey(command.tenantId),
    credentialId: normalizeResourceId(command.credentialId, "credential"),
    productId: normalizeResourceId(command.productId, "apiProduct"),
    ...optionalResourceId(command.apiVersionId, "apiVersion"),
    scopes: normalizeScopes(command.scopes, "scopes", true),
  };
}

export function normalizeScopeGrantQuery(
  query: ScopeGrantQuery,
): NormalizedScopeGrantQuery {
  return {
    tenantId: normalizeTenantKey(query?.tenantId),
    ...optionalResourceId(query?.credentialId, "credential"),
    ...optionalResourceId(query?.productId, "apiProduct"),
    ...optionalResourceId(query?.apiVersionId, "apiVersion"),
    ...optionalResourceId(query?.id, "scopeGrant", "id"),
  };
}

export function normalizeRecordUsageCommand(
  command: RecordUsageCommand,
): NormalizedRecordUsageCommand {
  assertCommandObject(command);
  return {
    tenantId: normalizeTenantKey(command.tenantId),
    subscriptionId: normalizeResourceId(command.subscriptionId, "subscription"),
    ...optionalResourceId(command.credentialId, "credential"),
    metric: normalizeMetric(command.metric),
    quantity: normalizeQuantity(command.quantity),
    ...optionalDate(command.occurredAt, "occurredAt"),
    idempotencyKey: normalizeIdempotencyKey(command.idempotencyKey),
  };
}

export function normalizeUsageQuery(query: UsageQuery): NormalizedUsageQuery {
  return {
    tenantId: normalizeTenantKey(query?.tenantId),
    ...optionalResourceId(query?.subscriptionId, "subscription"),
    ...optionalResourceId(query?.credentialId, "credential"),
    ...optionalDate(query?.from, "from"),
    ...optionalDate(query?.to, "to"),
  };
}

export function normalizeTenantKey(value: unknown): string {
  if (typeof value !== "string") {
    throw validationError("Open platform tenant identifier is invalid", {
      field: "tenantId",
    });
  }
  const normalized = value.trim();
  if (
    !/^[a-z][a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u.test(normalized) ||
    Object.values(OPEN_PLATFORM_RESOURCE_ID_PREFIXES).some((prefix) =>
      normalized.startsWith(`${prefix}_`)
    )
  ) {
    throw validationError("Open platform tenant identifier is invalid", {
      field: "tenantId",
    });
  }
  return normalized;
}

export function normalizeResourceId(
  value: unknown,
  resource: OpenPlatformEntityKind,
): string {
  if (typeof value !== "string") {
    throw validationError("Open platform resource identifier is invalid", {
      field: `${resource}Id`,
    });
  }
  const normalized = value.trim();
  const prefix = OPEN_PLATFORM_RESOURCE_ID_PREFIXES[resource];
  const pattern = new RegExp(
    `^${prefix}_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`,
    "u",
  );
  if (!pattern.test(normalized)) {
    throw validationError("Open platform resource identifier is invalid", {
      field: `${resource}Id`,
    });
  }
  return normalized;
}

export function normalizeIdentifier(value: unknown, field: string): string {
  if (typeof value !== "string") {
    throw validationError("Open platform identifier is invalid", { field });
  }
  const normalized = value.trim();
  if (
    normalized.length < 1 ||
    normalized.length > 128 ||
    !/^[A-Za-z0-9][A-Za-z0-9._:@-]*$/u.test(normalized)
  ) {
    throw validationError("Open platform identifier is invalid", { field });
  }
  return normalized;
}

export function normalizeText(
  value: unknown,
  field: string,
  maxLength: number,
): string {
  if (typeof value !== "string") {
    throw validationError("Open platform text is invalid", { field });
  }
  const normalized = value.trim();
  if (
    normalized.length < 1 ||
    normalized.length > maxLength ||
    /[\u0000-\u000f\u007f]/u.test(normalized)
  ) {
    throw validationError("Open platform text is invalid", { field });
  }
  return normalized;
}

export function normalizeScopes(
  value: unknown,
  field: string,
  requireAtLeastOne: boolean,
): string[] {
  if (!Array.isArray(value)) {
    throw validationError("Open platform scopes are invalid", { field });
  }
  const scopes = value.map((scope) => {
    if (typeof scope !== "string") {
      throw validationError("Open platform scope is invalid", { field });
    }
    const normalized = scope.trim();
    if (
      normalized.length < 1 ||
      normalized.length > 128 ||
      /[\s\u0000-\u001f\u007f]/u.test(normalized)
    ) {
      throw validationError("Open platform scope is invalid", { field });
    }
    return normalized;
  });
  const unique = [...new Set(scopes)].sort((left, right) =>
    left.localeCompare(right)
  );
  if (requireAtLeastOne && unique.length === 0) {
    throw validationError("At least one open platform scope is required", {
      field,
    });
  }
  return unique;
}

export function normalizeIdempotencyKey(value: unknown): string {
  if (typeof value !== "string") throw invalidIdempotencyKey();
  const normalized = value.trim();
  if (
    normalized.length < 1 ||
    normalized.length > 128 ||
    /[\s\u0000-\u001f\u007f]/u.test(normalized)
  ) {
    throw invalidIdempotencyKey();
  }
  return normalized;
}

export function normalizeTimestamp(value: Date): string {
  if (!(value instanceof Date) || !Number.isFinite(value.getTime())) {
    throw validationError("Open platform clock returned an invalid date");
  }
  return value.toISOString();
}

export function normalizeLifecycleResource(
  value: unknown,
): OpenPlatformLifecycleResourceKind {
  if (
    typeof value !== "string" ||
    !(OPEN_PLATFORM_LIFECYCLE_RESOURCE_KINDS as readonly string[]).includes(value)
  ) {
    throw validationError("Open platform lifecycle resource is invalid", {
      field: "resource",
    });
  }
  return value as OpenPlatformLifecycleResourceKind;
}

function normalizeApiVersion(value: unknown): string {
  if (
    typeof value !== "string" ||
    !/^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$/u.test(value.trim())
  ) {
    throw validationError("API version is invalid", { field: "apiVersion" });
  }
  return value.trim();
}

function normalizeMetric(value: unknown): string {
  if (
    typeof value !== "string" ||
    !/^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/u.test(value.trim())
  ) {
    throw validationError("Usage metric is invalid", { field: "metric" });
  }
  return value.trim();
}

function normalizeQuantity(value: unknown): number {
  if (
    typeof value !== "number" ||
    !Number.isFinite(value) ||
    value <= 0 ||
    value > Number.MAX_SAFE_INTEGER
  ) {
    throw validationError("Usage quantity is invalid", { field: "quantity" });
  }
  return value;
}

function normalizeOptionalDate(
  value: unknown,
  field: string,
): string | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== "string") {
    throw validationError("Open platform date is invalid", { field });
  }
  const timestamp = Date.parse(value);
  if (!Number.isFinite(timestamp)) {
    throw validationError("Open platform date is invalid", { field });
  }
  return new Date(timestamp).toISOString();
}

function optionalResourceId(
  value: unknown,
  resource: OpenPlatformEntityKind,
  field = `${resource}Id`,
): { [key: string]: string } | Record<string, never> {
  return value === undefined
    ? {}
    : { [field]: normalizeResourceId(value, resource) };
}

function optionalText(
  value: unknown,
  field: string,
  maxLength: number,
): { [key: string]: string } | Record<string, never> {
  return value === undefined
    ? {}
    : { [field]: normalizeText(value, field, maxLength) };
}

function optionalDate(
  value: unknown,
  field: string,
): { [key: string]: string } | Record<string, never> {
  const normalized = normalizeOptionalDate(value, field);
  return normalized === undefined ? {} : { [field]: normalized };
}

function assertCommandObject(value: unknown): void {
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value)
  ) {
    throw validationError("Open platform request is invalid");
  }
  assertNoPlaintext(value);
}

function assertNoPlaintext(value: unknown, path = "command", depth = 0): void {
  if (depth > 6 || value === null || typeof value !== "object") return;
  if (Array.isArray(value)) {
    value.forEach((item, index) => {
      assertNoPlaintext(item, `${path}[${index}]`, depth + 1);
    });
    return;
  }
  for (const [key, nested] of Object.entries(value as Record<string, unknown>)) {
    if (isPlaintextKey(key)) {
      throw validationError("Plaintext secret input is not accepted", {
        field: `${path}.${key}`,
      });
    }
    assertNoPlaintext(nested, `${path}.${key}`, depth + 1);
  }
}

function isPlaintextKey(key: string): boolean {
  const normalized = key.replace(/[-_]/gu, "").toLowerCase();
  return normalized === "secret" ||
    normalized === "clientsecret" ||
    normalized === "plaintext" ||
    normalized === "password" ||
    normalized === "token" ||
    normalized === "privatekey" ||
    normalized === "authorization";
}
