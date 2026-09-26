import type {
  ApplicationClientKind,
  ApplicationClientSummary,
  ApplicationEffectiveStatus,
  ApplicationExternalIdentitySummary,
  ApplicationPlatformSummary,
  ApplicationReadiness,
  ApplicationReadinessCheck,
  ApplicationReadinessDetails,
  ApplicationReadinessStatus,
  ApplicationSecretStatus,
  ApplicationStatus,
  ApplicationSummary,
  ApplicationType,
  ApplicationVersion,
  OidcRpClient,
  WechatComponentPlatformBindingSummary,
} from "@getbrick/idaas-contracts";
import { internalError } from "./errors.js";
import { isApplicationPlatformType } from "./application-validation.js";

export function toApplicationSummary(value: unknown): ApplicationSummary {
  const record = recordValue(value);
  const status = statusValue(record.status);
  const lifecycleStatus = lifecycleStatusValue(record.lifecycleStatus, status);
  const readiness = readinessProjection(record.readiness, lifecycleStatus, lifecycleStatus === "active");
  const version = versionValue(record.version) ?? 1;
  const dto: ApplicationSummary = {
    id: requiredId(record.id),
    name: requiredString(record.name, "name"),
    slug: requiredString(record.slug, "slug"),
    applicationType: applicationTypeValue(record.applicationType),
    status,
    lifecycleStatus,
    readiness,
    effectiveStatus: effectiveStatusValue(record.effectiveStatus, lifecycleStatus, readiness),
    version,
    etag: etagValue(record.etag, `application:${requiredId(record.id)}:${version}`),
  };
  assignString(dto, "description", record.description);
  assignDate(dto, "createdAt", record.createdAt);
  assignDate(dto, "updatedAt", record.updatedAt);
  assignDate(dto, "enabledAt", record.enabledAt);
  assignDate(dto, "disabledAt", record.disabledAt);
  assignDate(dto, "archivedAt", record.archivedAt);
  assignDate(dto, "purgedAt", record.purgedAt);
  return dto;
}

export function toApplicationPlatformSummary(value: unknown): ApplicationPlatformSummary {
  const record = recordValue(value);
  const type = requiredString(record.type, "type");
  if (!isApplicationPlatformType(type)) throw internalError();
  const status = statusValue(record.status);
  const lifecycleStatus = lifecycleStatusValue(record.lifecycleStatus, status);
  const configured = credentialConfigured(record);
  const readiness = readinessProjection(
    record.readiness,
    lifecycleStatus,
    lifecycleStatus === "active" && configured,
  );
  const version = versionValue(record.version) ?? 1;
  const dto: ApplicationPlatformSummary & { lifecycleStatus?: ApplicationStatus } = {
    id: requiredId(record.id),
    applicationId: requiredString(record.applicationId, "applicationId"),
    type,
    redirectUris: stringArray(record.redirectUris),
    credentialConfigured: configured,
    secretStatus: secretStatusValue(record.secretStatus, configured),
    secretVersion: secretVersionValue(record.secretVersion, configured),
    readiness,
    effectiveStatus: effectiveStatusValue(record.effectiveStatus, lifecycleStatus, readiness),
    version,
    etag: etagValue(record.etag, `application-platform:${requiredId(record.id)}:${version}`),
    status,
    lifecycleStatus: lifecycleStatusValue(record.lifecycleStatus, status),
  };
  assignString(dto, "externalAppId", record.externalAppId);
  assignString(dto, "displayName", record.displayName);
  assignString(dto, "loginMode", record.loginMode);
  assignString(dto, "scope", record.scope);
  const scopes = stringArray(record.scopes);
  if (scopes.length > 0) dto.scopes = scopes;
   assignSafeEndpoint(dto, record.endpointUrl);
   assignString(dto, "componentAppId", record.componentAppId);
   assignString(dto, "authorizedAppId", record.authorizedAppId);
   assignString(dto, "authorizerAppId", record.authorizerAppId);
   const componentSecretConfigured = [
     "componentAppSecretRef",
     "componentVerifyTicketRef",
     "componentAccessTokenRef",
     "authorizerRefreshTokenRef",
     "authorizerAccessTokenRef",
     "componentTicketRef",
   ].some((field) => safePublicString(record[field], 512) !== undefined);
   if (componentSecretConfigured) dto.componentAppSecretConfigured = true;
   const componentStatus = safeString(record.componentBindingStatus, 64);
   if (componentStatus !== undefined && ["pending", "active", "expired", "revoked", "unbound"].includes(componentStatus)) dto.componentBindingStatus = componentStatus as typeof dto.componentBindingStatus;
   const componentVersion = versionValue(record.componentBindingVersion);
   if (componentVersion !== undefined) dto.componentBindingVersion = componentVersion;
   assignDate(dto, "componentTicketExpiresAt", record.componentTicketExpiresAt);
   const componentBinding = componentBindingSummary(record);
   if (componentBinding !== undefined) dto.componentBinding = componentBinding;
   assignDate(dto, "createdAt", record.createdAt);
  assignDate(dto, "updatedAt", record.updatedAt);
  assignDate(dto, "enabledAt", record.enabledAt);
  assignDate(dto, "disabledAt", record.disabledAt);
  assignDate(dto, "archivedAt", record.archivedAt);
  assignDate(dto, "purgedAt", record.purgedAt);
  return dto;
}

export function toApplicationClientSummary(value: unknown): ApplicationClientSummary {
  const record = recordValue(value);
  const status = clientStatusValue(record.status);
  const lifecycleStatus = lifecycleStatusValue(record.lifecycleStatus, status);
  const authMethod = authMethodValue(record.tokenEndpointAuthMethod, record);
  const configured = credentialConfigured(record);
  const secretConfigured = configured && authMethod !== "none" && authMethod !== "private_key_jwt";
  const readiness = readinessProjection(
    record.readiness,
    lifecycleStatus,
    lifecycleStatus === "active" && (authMethod === "none" || authMethod === "private_key_jwt" || secretConfigured),
  );
  const version = versionValue(record.version) ?? 1;
  const dto: ApplicationClientSummary & { lifecycleStatus?: ApplicationStatus } = {
    id: requiredId(record.id),
    applicationId: requiredString(record.applicationId, "applicationId"),
     clientId: requiredString(record.clientId, "clientId"),
     ...(clientKindValue(record) === undefined ? {} : { clientKind: clientKindValue(record), clientType: clientKindValue(record) }),
     ...(safeString(record.redirectUriPolicy, 64) === "exact" ? { redirectUriPolicy: "exact" as const } : {}),
     ...(safeString(record.pkceMethod, 64) === "S256" ? { pkceMethod: "S256" as const } : {}),
     ...(typeof record.consentRequired === "boolean" ? { consentRequired: record.consentRequired } : {}),
     ...(typeof record.requireExplicitConsent === "boolean" ? { requireExplicitConsent: record.requireExplicitConsent } : {}),
     ...(rpClientSummary(record) === undefined ? {} : { rpClient: rpClientSummary(record) }),
     status,
    lifecycleStatus,
    ...(record.applicationType === undefined ? {} : { applicationType: applicationTypeValue(record.applicationType) }),
    ...(record.clientIdScope === "global" ? { clientIdScope: "global" as const } : {}),
    redirectUris: stringArray(record.redirectUris),
    postLogoutRedirectUris: stringArray(record.postLogoutRedirectUris),
    grantTypes: stringArray(record.grantTypes) as ApplicationClientSummary["grantTypes"],
    responseTypes: stringArray(record.responseTypes) as ApplicationClientSummary["responseTypes"],
    scopes: stringArray(record.scopes),
    tokenEndpointAuthMethod: authMethod,
    ...(authMethod === "private_key_jwt" || record.tokenEndpointAuthSigningAlg !== undefined
      ? { tokenEndpointAuthSigningAlg: signingAlgorithmValue(record.tokenEndpointAuthSigningAlg) }
      : {}),
    requirePkce: record.requirePkce !== false,
    hasSecret: secretConfigured,
    secretStatus: authMethod === "none" || authMethod === "private_key_jwt"
      ? "not_required"
      : secretStatusValue(record.secretStatus, secretConfigured),
    secretVersion: authMethod === "none" || authMethod === "private_key_jwt"
      ? 0
      : secretVersionValue(record.secretVersion, secretConfigured),
    readiness,
    effectiveStatus: effectiveStatusValue(record.effectiveStatus, lifecycleStatus, readiness),
    version,
    etag: etagValue(record.etag, `application-client:${requiredId(record.id)}:${version}`),
  };
  assignSafeEndpointProperty(dto, "jwksUri", record.jwksUri);
  assignString(dto, "keyId", record.keyId);
  assignDate(dto, "createdAt", record.createdAt);
  assignDate(dto, "updatedAt", record.updatedAt);
  assignDate(dto, "enabledAt", record.enabledAt);
  assignDate(dto, "disabledAt", record.disabledAt);
  assignDate(dto, "archivedAt", record.archivedAt);
  assignDate(dto, "purgedAt", record.purgedAt);
  return dto;
}

export function toApplicationExternalIdentitySummary(value: unknown): ApplicationExternalIdentitySummary {
  const record = recordValue(value);
  const dto: ApplicationExternalIdentitySummary = {
    id: requiredId(record.id),
    applicationId: requiredString(record.applicationId, "applicationId"),
    provider: requiredString(record.provider, "provider"),
    subject: requiredString(record.subject, "subject"),
  };
  assignString(dto, "platformId", record.platformId);
  assignString(dto, "platform", record.platform);
  assignString(dto, "appId", record.appId ?? record.externalAppId);
  assignString(dto, "externalAppId", record.externalAppId);
  assignString(dto, "openid", record.openid);
  assignString(dto, "unionid", record.unionid);
  assignString(dto, "nickname", record.nickname);
  assignString(dto, "displayName", record.displayName);
  assignString(dto, "email", record.email);
   assignSafeUrlProperty(dto, "avatarUrl", record.avatarUrl);
   const scopes = stringArray(record.scopes);
   if (scopes.length > 0) dto.scopes = scopes;
   assignString(dto, "canonicalUserId", record.canonicalUserId);
   assignString(dto, "linkStatus", record.linkStatus);
   if (typeof record.emailVerified === "boolean") dto.emailVerified = record.emailVerified;
   const version = versionValue(record.version);
  if (version !== undefined) dto.version = version;
  assignDate(dto, "firstLinkedAt", record.firstLinkedAt);
  assignDate(dto, "linkedAt", record.linkedAt);
  assignDate(dto, "lastAuthenticatedAt", record.lastAuthenticatedAt);
  assignDate(dto, "createdAt", record.createdAt);
  assignDate(dto, "updatedAt", record.updatedAt);
  return dto;
}

export const toApplicationDto = toApplicationSummary;
export const toApplicationPlatformDto = toApplicationPlatformSummary;
export const toApplicationClientDto = toApplicationClientSummary;
export const toExternalIdentityDto = toApplicationExternalIdentitySummary;
export const toApplicationExternalIdentityDto = toApplicationExternalIdentitySummary;

function clientKindValue(record: Record<string, unknown>): ApplicationClientKind | undefined {
  const value = record.clientKind ?? record.clientType;
  if (value === "web" || value === "webview" || value === "mp_weixin" || value === "native") return value;
  return undefined;
}

function rpClientSummary(record: Record<string, unknown>): OidcRpClient | undefined {
  const value = record.rpClient;
  if (!isRecord(value)) return undefined;
  const redirectUris = stringArray(value.redirectUris);
  if (redirectUris.length === 0) return undefined;
  return {
    clientId: safePublicString(value.clientId, 512) ?? requiredString(record.clientId, "clientId"),
    clientType: "web",
    clientKind: "web",
    redirectUris,
    ...(stringArray(value.postLogoutRedirectUris).length > 0 ? { postLogoutRedirectUris: stringArray(value.postLogoutRedirectUris) } : {}),
    redirectUriPolicy: "exact",
    redirectPolicy: { mode: "exact", exact: true },
    requirePkce: true,
    pkceMethod: "S256",
    pkce: { required: true, method: "S256" },
    consent: "explicit",
    grantTypes: ["authorization_code"],
    responseTypes: ["code"],
    scopes: stringArray(value.scopes).length > 0 ? stringArray(value.scopes) : ["openid"],
  };
}

function componentBindingSummary(record: Record<string, unknown>): WechatComponentPlatformBindingSummary | undefined {
  const componentAppId = safePublicString(record.componentAppId, 512);
  const authorizedAppId = safePublicString(record.authorizedAppId, 512) ?? safePublicString(record.authorizerAppId, 512);
  const status = safeString(record.componentBindingStatus, 64);
  if (componentAppId === undefined || (status === undefined || !["pending", "active", "expired", "revoked", "unbound"].includes(status))) return undefined;
  return {
    componentAppId,
    ...(authorizedAppId === undefined ? {} : { authorizedAppId }),
    ...(safeString(record.authorizerAppId, 512) === undefined ? {} : { authorizerAppId: safeString(record.authorizerAppId, 512) }),
    ...(record.componentTicketExpiresAt === undefined ? {} : { componentTicketExpiresAt: dateValue(record.componentTicketExpiresAt) }),
    status: status as WechatComponentPlatformBindingSummary["status"],
    ...(versionValue(record.componentBindingVersion) === undefined ? {} : { version: versionValue(record.componentBindingVersion) }),
  };
}

function dateValue(value: unknown): string | undefined {
  if (!(value instanceof Date) && typeof value !== "string" && typeof value !== "number") return undefined;
  const date = value instanceof Date ? value : new Date(value);
  return Number.isNaN(date.getTime()) ? undefined : date.toISOString();
}

function credentialConfigured(record: Record<string, unknown>): boolean {
  const status = safeString(record.secretStatus, 64);
  if (status !== undefined) return ["configured", "active", "retiring"].includes(status);
  return record.credentialConfigured === true ||
    record.hasCredential === true ||
    record.hasSecret === true ||
    safeString(record.secretRef, 512) !== undefined ||
    safeString(record.componentAppId, 512) !== undefined ||
    safeString(record.componentAccessTokenRef, 512) !== undefined ||
    safeString(record.authorizerRefreshTokenRef, 512) !== undefined;
}

function secretStatusValue(value: unknown, configured: boolean): ApplicationSecretStatus {
  if (typeof value === "string") {
    const normalized = safeString(value, 64);
    if (normalized !== undefined && ["configured", "not_configured", "missing", "rotating", "active", "retiring", "revoked", "not_required", "expired", "unknown"].includes(normalized)) {
      return normalized as ApplicationSecretStatus;
    }
  }
  return configured ? "configured" : "not_configured";
}

function secretVersionValue(value: unknown, configured: boolean): ApplicationVersion {
  const version = versionValue(value);
  if (version !== undefined) return version;
  return configured ? 1 : 0;
}

function applicationTypeValue(value: unknown): ApplicationType {
  if (value === "web" || value === "native") return value;
  if (value === undefined || value === null || value === "") return "web";
  throw internalError();
}

function statusValue(value: unknown): ApplicationStatus {
  if (value === undefined || value === null || value === "") return "active";
  if (value === "active" || value === "disabled" || value === "archived" || value === "purged") return value;
  throw internalError();
}

function clientStatusValue(value: unknown): ApplicationStatus {
  if (value === undefined || value === null || value === "") return "active";
  if (value === "active" || value === "disabled" || value === "archived" || value === "purged") return value;
  throw internalError();
}

function lifecycleStatusValue(value: unknown, fallback: ApplicationStatus): ApplicationStatus {
  if (value === "active" || value === "disabled" || value === "archived" || value === "purged") return value;
  return fallback;
}

function readinessValue(value: unknown, status: ApplicationStatus, fallbackReady = status === "active"): ApplicationReadiness {
  if (typeof value === "string") {
    if (value === "ready" || value === "not_ready" || value === "unknown") return value;
  }
  if (isRecord(value)) {
    const candidate = value.status;
    if (candidate === "ready" || candidate === "not_ready" || candidate === "unknown") {
      const details: ApplicationReadinessDetails = { status: candidate };
      if (typeof value.ready === "boolean") details.ready = value.ready;
      const checks = readinessChecks(value.checks);
      if (checks.length > 0) details.checks = checks;
      const reasons = stringArray(value.reasons);
      if (reasons.length > 0) details.reasons = reasons;
      return details;
    }
    if (typeof value.ready === "boolean") return value.ready ? "ready" : "not_ready";
  }
  return fallbackReady ? "ready" : "not_ready";
}

function readinessProjection(
  value: unknown,
  status: ApplicationStatus,
  fallbackReady: boolean,
): ApplicationReadiness {
  const readiness = readinessValue(value, status, fallbackReady);
  if (fallbackReady) return readiness;
  if (typeof readiness === "string") return "not_ready";
  return {
    ...readiness,
    status: "not_ready",
    ready: false,
  };
}

function effectiveStatusValue(
  value: unknown,
  status: ApplicationStatus,
  readiness: ApplicationReadiness,
): ApplicationEffectiveStatus {
  if (status === "archived" || status === "purged" || status === "disabled") return status;
  if (typeof value === "string" && value.trim() === "invalid") return "invalid";
  const readinessState = readinessStatus(readiness);
  if (readinessState === "unknown") return "unknown";
  if (readinessState !== "ready") return "not_ready";
  return status;
}

function readinessStatus(value: ApplicationReadiness): ApplicationReadinessStatus {
  if (typeof value === "string") return value;
  return value.status;
}

function readinessChecks(value: unknown): ApplicationReadinessCheck[] {
  if (!Array.isArray(value)) return [];
  const output: ApplicationReadinessCheck[] = [];
  for (const item of value.slice(0, 100)) {
    if (!isRecord(item)) continue;
    const check: ApplicationReadinessCheck = {};
    assignString(check, "id", item.id);
    assignString(check, "name", item.name);
    if (typeof item.status === "string") assignString(check, "status", item.status);
    if (typeof item.ready === "boolean") check.ready = item.ready;
    assignString(check, "message", item.message);
    if (Object.keys(check).length > 0) output.push(check);
  }
  return output;
}

function signingAlgorithmValue(value: unknown): string {
  if (value === undefined || value === null || value === "") return "RS256";
  if (typeof value === "string" && ["RS256", "PS256", "ES256", "EdDSA"].includes(value)) return value;
  throw internalError();
}

function authMethodValue(value: unknown, record?: Record<string, unknown>): string {
  if (value === undefined || value === null || value === "") {
    if (record && (record.hasSecret === true || record.credentialConfigured === true || safeString(record.secretRef, 512) !== undefined)) {
      return "client_secret_basic";
    }
    return "private_key_jwt";
  }
  if (typeof value === "string" && ["none", "client_secret_basic", "client_secret_post", "private_key_jwt"].includes(value)) return value;
  throw internalError();
}

function versionValue(value: unknown): ApplicationVersion | undefined {
  if (typeof value === "number" && Number.isSafeInteger(value) && value >= 0) return value;
  if (typeof value === "string") {
    const normalized = safeString(value, 128);
    if (normalized !== undefined && !containsCredentialMaterial(normalized)) return normalized;
  }
  return undefined;
}

function etagValue(value: unknown, fallback: string): string {
  const normalized = safeString(value, 256);
  return normalized !== undefined && !containsCredentialMaterial(normalized) ? normalized : fallback;
}

function containsCredentialMaterial(value: string): boolean {
  return /(?:secret|token|password|private[_-]?key|credential|vault:\/\/)/iu.test(value);
}

function recordValue(value: unknown): Record<string, unknown> {
  if (!isRecord(value)) throw internalError();
  return value;
}

function requiredId(value: unknown): string {
  return requiredString(value, "id");
}

function requiredString(value: unknown, _field: string): string {
  const normalized = safeString(value, 512);
  if (normalized === undefined) throw internalError();
  return normalized;
}

function safeString(value: unknown, maxLength = 2048): string | undefined {
  if (typeof value !== "string") return undefined;
  const normalized = value.trim();
  if (normalized.length === 0 || normalized.length > maxLength || /[\u0000-\u001f\u007f]/u.test(normalized)) {
    return undefined;
  }
  return normalized;
}

function safePublicString(value: unknown, maxLength = 2048): string | undefined {
  const normalized = safeString(value, maxLength);
  return normalized !== undefined && !containsCredentialMaterial(normalized) ? normalized : undefined;
}

function stringArray(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  const output: string[] = [];
  for (const item of value) {
    const normalized = safePublicString(item, 2048);
    if (normalized !== undefined && !output.includes(normalized)) output.push(normalized);
    if (output.length >= 100) break;
  }
  return output;
}

function assignSafeEndpoint<T extends object>(target: T, value: unknown): void {
  const normalized = safeString(value, 2048);
  if (normalized === undefined) return;
  try {
    const parsed = new URL(normalized);
    if (
      (parsed.protocol !== "http:" && parsed.protocol !== "https:") ||
      !parsed.hostname ||
      parsed.username ||
      parsed.password ||
      parsed.search ||
      parsed.hash ||
      /\s/u.test(normalized) ||
      normalized.includes("?") ||
      normalized.includes("#")
    ) return;
    (target as Record<string, unknown>).endpointUrl = parsed.toString();
  } catch {
    return;
  }
}

function assignSafeEndpointProperty<T extends object>(target: T, key: string, value: unknown): void {
  const normalized = safeString(value, 2048);
  if (normalized === undefined) return;
  try {
    const parsed = new URL(normalized);
    if (
      (parsed.protocol !== "http:" && parsed.protocol !== "https:") ||
      !parsed.hostname ||
      parsed.username ||
      parsed.password ||
      parsed.search ||
      parsed.hash
    ) return;
    (target as Record<string, unknown>)[key] = parsed.toString();
  } catch {
    return;
  }
}

function assignSafeUrlProperty<T extends object>(target: T, key: string, value: unknown): void {
  const normalized = safeString(value, 2048);
  if (normalized === undefined) return;
  try {
    const parsed = new URL(normalized);
    if (
      (parsed.protocol !== "http:" && parsed.protocol !== "https:") ||
      !parsed.hostname ||
      parsed.username ||
      parsed.password ||
      parsed.search ||
      parsed.hash ||
      /\s/u.test(normalized)
    ) return;
    (target as Record<string, unknown>)[key] = parsed.toString();
  } catch {
    return;
  }
}

function assignString<T extends object>(target: T, key: keyof T, value: unknown): void {
  const normalized = safePublicString(value);
  if (normalized !== undefined) (target as Record<string, unknown>)[key as string] = normalized;
}

function assignDate<T extends object>(target: T, key: keyof T, value: unknown): void {
  if (value === undefined || value === null) return;
  if (!(value instanceof Date) && typeof value !== "string" && typeof value !== "number") return;
  const date = value instanceof Date ? value : new Date(value);
  if (!Number.isNaN(date.getTime())) (target as Record<string, unknown>)[key as string] = date.toISOString();
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
