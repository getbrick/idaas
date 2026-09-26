import {
  APPLICATION_CLIENT_AUTH_SIGNING_ALGORITHMS,
  APPLICATION_CLIENT_ID_SCOPES,
  APPLICATION_CLIENT_KINDS,
  APPLICATION_PLATFORM_TYPES,
  APPLICATION_TYPES,
  DEFAULT_APPLICATION_CLIENT_AUTH_METHOD,
  DEFAULT_APPLICATION_CLIENT_AUTH_SIGNING_ALGORITHM,
  OIDC_RP_CONSENT_MODES,
  OIDC_RP_PKCE_METHODS,
  OIDC_RP_REDIRECT_URI_POLICIES,
  WECHAT_COMPONENT_BINDING_STATUSES,
  WECHAT_COMPONENT_PLATFORM_TYPES,
  type ApplicationClientAuthSigningAlgorithm,
  type ApplicationClientCreateRequest,
  type ApplicationClientKind,
  type ApplicationClientListQuery,
  type ApplicationClientRotateSecretRequest,
  type ApplicationClientStatus,
  type ApplicationClientUpdateRequest,
  type ApplicationEffectiveStatus,
  type ApplicationExternalIdentityListQuery,
  type ApplicationListQuery,
  type ApplicationPlatformCreateRequest,
  type ApplicationPlatformListQuery,
  type ApplicationPlatformType,
  type ApplicationPlatformUpdateRequest,
  type ApplicationReadinessStatus,
  type ApplicationStatus,
  type ApplicationType,
  type ApplicationCreateRequest,
  type ApplicationUpdateRequest,
  type ApplicationVersion,
  type OidcRpClient,
  type OidcRpConsent,
  type OidcRpPkceMethod,
  type OidcRpRedirectUriPolicy,
  type WechatComponentBindingStatus,
  type WechatComponentPlatformBinding,
  validateOidcRpClient,
} from "@getbrick/idaas-contracts";
import { invalidRequest } from "./errors.js";
import {
  CONTROL_PLANE_DEFAULT_LIMIT,
  CONTROL_PLANE_MAX_LIMIT,
} from "./types.js";

const APPLICATION_FIELDS = new Set(["name", "slug", "description", "applicationType"]);
const APPLICATION_UPDATE_FIELDS = new Set(["name", "slug", "description", "applicationType"]);
const APPLICATION_PLATFORM_FIELDS = new Set([
  "type",
  "externalAppId",
  "componentAppId",
  "authorizedAppId",
  "authorizerAppId",
  "componentBinding",
  "componentAppSecretRef",
  "componentVerifyTicketRef",
  "componentAccessTokenRef",
  "authorizerRefreshTokenRef",
  "authorizerAccessTokenRef",
  "componentTicketRef",
  "componentTicketExpiresAt",
  "componentBindingStatus",
  "componentBindingVersion",
  "componentScope",
  "displayName",
  "loginMode",
  "scope",
  "redirectUris",
  "endpointUrl",
  "secretRef",
]);
const APPLICATION_PLATFORM_UPDATE_FIELDS = new Set([
  "type",
  "externalAppId",
  "componentAppId",
  "authorizedAppId",
  "authorizerAppId",
  "componentBinding",
  "componentAppSecretRef",
  "componentVerifyTicketRef",
  "componentAccessTokenRef",
  "authorizerRefreshTokenRef",
  "authorizerAccessTokenRef",
  "componentTicketRef",
  "componentTicketExpiresAt",
  "componentBindingStatus",
  "componentBindingVersion",
  "componentScope",
  "displayName",
  "loginMode",
  "scope",
  "redirectUris",
  "endpointUrl",
]);
const APPLICATION_CLIENT_FIELDS = new Set([
  "applicationType",
  "clientId",
  "clientIdScope",
  "clientKind",
  "clientType",
  "redirectUris",
  "postLogoutRedirectUris",
  "redirectUriPolicy",
  "redirectPolicy",
  "pkce",
  "pkceMethod",
  "consent",
  "consentRequired",
  "requireExplicitConsent",
  "rpClient",
  "grantTypes",
  "responseTypes",
  "scopes",
  "tokenEndpointAuthMethod",
  "tokenEndpointAuthSigningAlg",
  "jwksUri",
  "privateKeyRef",
  "keyId",
  "requirePkce",
  "secretRef",
]);
const APPLICATION_CLIENT_UPDATE_FIELDS = new Set([
  "applicationType",
  "clientId",
  "clientIdScope",
  "clientKind",
  "clientType",
  "redirectUris",
  "postLogoutRedirectUris",
  "redirectUriPolicy",
  "redirectPolicy",
  "pkce",
  "pkceMethod",
  "consent",
  "consentRequired",
  "requireExplicitConsent",
  "rpClient",
  "grantTypes",
  "responseTypes",
  "scopes",
  "tokenEndpointAuthMethod",
  "tokenEndpointAuthSigningAlg",
  "jwksUri",
  "privateKeyRef",
  "keyId",
  "requirePkce",
]);
const QUERY_FIELDS = new Set([
  "cursor",
  "limit",
  "pageSize",
  "page",
  "offset",
  "search",
  "q",
  "status",
]);
const APPLICATION_QUERY_FIELDS = new Set([
  ...QUERY_FIELDS,
  "applicationType",
  "readiness",
  "effectiveStatus",
]);
const PLATFORM_QUERY_FIELDS = new Set([
  ...QUERY_FIELDS,
  "readiness",
  "effectiveStatus",
]);
const CLIENT_QUERY_FIELDS = new Set([
  ...QUERY_FIELDS,
  "readiness",
  "effectiveStatus",
  "clientKind",
]);
const EXTERNAL_IDENTITY_QUERY_FIELDS = new Set([
  "cursor",
  "limit",
  "pageSize",
  "page",
  "offset",
  "search",
  "q",
  "provider",
  "platformId",
]);
const TOKEN_ENDPOINT_AUTH_METHODS = new Set<string>([
  "none",
  "client_secret_basic",
  "client_secret_post",
  DEFAULT_APPLICATION_CLIENT_AUTH_METHOD,
]);
const TOKEN_ENDPOINT_AUTH_SIGNING_ALGORITHMS = new Set<string>(APPLICATION_CLIENT_AUTH_SIGNING_ALGORITHMS);
const APPLICATION_CLIENT_ID_SCOPE_VALUES = new Set<string>(APPLICATION_CLIENT_ID_SCOPES);
const APPLICATION_CLIENT_KIND_VALUES = new Set<string>(APPLICATION_CLIENT_KINDS);
const RP_REDIRECT_URI_POLICY_VALUES = new Set<string>(OIDC_RP_REDIRECT_URI_POLICIES);
const RP_PKCE_METHOD_VALUES = new Set<string>(OIDC_RP_PKCE_METHODS);
const RP_CONSENT_MODE_VALUES = new Set<string>(OIDC_RP_CONSENT_MODES);
const COMPONENT_PLATFORM_TYPE_VALUES = new Set<string>(WECHAT_COMPONENT_PLATFORM_TYPES);
const COMPONENT_BINDING_STATUS_VALUES = new Set<string>(WECHAT_COMPONENT_BINDING_STATUSES);
const PLATFORM_TYPES = new Set<string>(APPLICATION_PLATFORM_TYPES);
const RP_CLIENT_FIELDS = new Set([
  "clientId",
  "clientType",
  "clientKind",
  "redirectUris",
  "postLogoutRedirectUris",
  "redirectUriPolicy",
  "redirectPolicy",
  "requirePkce",
  "pkceMethod",
  "pkce",
  "consent",
  "consentRequired",
  "requireExplicitConsent",
  "grantTypes",
  "responseTypes",
  "scopes",
]);
const COMPONENT_BINDING_FIELDS = new Set([
  "componentAppId",
  "authorizedAppId",
  "authorizerAppId",
  "componentAppSecretRef",
  "componentVerifyTicketRef",
  "componentAccessTokenRef",
  "authorizerRefreshTokenRef",
  "authorizerAccessTokenRef",
  "componentTicketRef",
  "componentTicketExpiresAt",
  "status",
  "version",
  "scope",
]);
const REFERENCE_FIELD_NAMES = new Set([
  "privateKeyRef",
  "componentAppSecretRef",
  "componentVerifyTicketRef",
  "componentAccessTokenRef",
  "authorizerRefreshTokenRef",
  "authorizerAccessTokenRef",
  "componentTicketRef",
]);
const CONTROL_CHARACTERS = /[\u0000-\u001f\u007f]/u;
const UNSAFE_NAMES = new Set(["__proto__", "prototype", "constructor"]);
const MAX_STRING_LENGTH = 2048;
const MAX_SHORT_STRING_LENGTH = 512;
const MAX_NAME_LENGTH = 256;
const MAX_SLUG_LENGTH = 128;
const MAX_DESCRIPTION_LENGTH = 4096;
const MAX_ARRAY_ITEMS = 100;
const MAX_SCOPE_LENGTH = 4096;

export interface ApplicationValidationOptions {
  defaultLimit?: number;
  maxLimit?: number;
}

export interface ApplicationClientValidationOptions {
  applicationType?: ApplicationType;
}

export interface ApplicationPlatformValidationOptions {
  applicationType?: ApplicationType;
}

export function validateApplicationClientAuthSigningAlgorithm(
  value: unknown,
  field = "tokenEndpointAuthSigningAlg",
): ApplicationClientAuthSigningAlgorithm {
  if (typeof value !== "string" || !TOKEN_ENDPOINT_AUTH_SIGNING_ALGORITHMS.has(value)) {
    throw invalidRequest("Invalid tokenEndpointAuthSigningAlg", { field });
  }
  return value as ApplicationClientAuthSigningAlgorithm;
}

export function validateApplicationClientIdScope(
  value: unknown,
  field = "clientIdScope",
): "global" {
  if (value === undefined) return "global";
  if (typeof value === "string" && APPLICATION_CLIENT_ID_SCOPE_VALUES.has(value)) return "global";
  throw invalidRequest("OIDC clientIdScope must be global", { field });
}

export function validateApplicationClientIdUniqueness(
  clients: readonly { clientId: string }[],
): void {
  const seen = new Set<string>();
  for (const client of clients) {
    if (typeof client?.clientId !== "string") {
      throw invalidRequest("Invalid clientId", { field: "clientId" });
    }
    const normalized = client.clientId.trim().toLowerCase();
    if (normalized.length === 0) {
      throw invalidRequest("Invalid clientId", { field: "clientId" });
    }
    if (seen.has(normalized)) {
      throw invalidRequest("OIDC clientId must be globally unique", { field: "clientId" });
    }
    seen.add(normalized);
  }
}

export function parseApplicationListQuery(
  input: unknown,
  options: ApplicationValidationOptions = {},
): ApplicationListQuery & { limit: number; offset?: number } {
  const record = strictQueryRecord(input, APPLICATION_QUERY_FIELDS);
  return {
    ...parsePage(record, options),
    ...optionalText(record, "search", MAX_NAME_LENGTH),
    ...optionalText(record, "q", MAX_NAME_LENGTH),
    ...optionalApplicationStatus(record),
    ...optionalApplicationType(record),
    ...optionalReadiness(record),
    ...optionalEffectiveStatus(record),
  };
}

export function parseApplicationPlatformListQuery(
  input: unknown,
  options: ApplicationValidationOptions = {},
): ApplicationPlatformListQuery & { limit: number; offset?: number } {
  const record = strictQueryRecord(input, PLATFORM_QUERY_FIELDS);
  return {
    ...parsePage(record, options),
    ...optionalText(record, "search", MAX_NAME_LENGTH),
    ...optionalText(record, "q", MAX_NAME_LENGTH),
    ...optionalApplicationStatus(record),
    ...optionalReadiness(record),
    ...optionalEffectiveStatus(record),
  };
}

export function parseApplicationClientListQuery(
  input: unknown,
  options: ApplicationValidationOptions = {},
): ApplicationClientListQuery & { limit: number; offset?: number } {
  const record = strictQueryRecord(input, CLIENT_QUERY_FIELDS);
  return {
    ...parsePage(record, options),
    ...optionalText(record, "search", MAX_NAME_LENGTH),
    ...optionalText(record, "q", MAX_NAME_LENGTH),
    ...optionalClientStatus(record),
    ...optionalReadiness(record),
    ...optionalEffectiveStatus(record),
    ...(record.clientKind === undefined ? {} : { clientKind: requiredClientKind(record.clientKind, "clientKind") }),
  };
}

export function parseApplicationExternalIdentityListQuery(
  input: unknown,
  options: ApplicationValidationOptions = {},
): ApplicationExternalIdentityListQuery & { limit: number; offset?: number } {
  const record = strictQueryRecord(input, EXTERNAL_IDENTITY_QUERY_FIELDS);
  return {
    ...parsePage(record, options),
    ...optionalText(record, "search", MAX_NAME_LENGTH),
    ...optionalText(record, "q", MAX_NAME_LENGTH),
    ...optionalText(record, "provider", MAX_SHORT_STRING_LENGTH),
    ...optionalText(record, "platformId", MAX_SHORT_STRING_LENGTH),
  };
}

export function parseApplicationCreateRequest(input: unknown): ApplicationCreateRequest {
  const record = strictBodyRecord(input, APPLICATION_FIELDS, false);
  const name = requiredText(record.name, "name", MAX_NAME_LENGTH);
  const slug = requiredSlug(record.slug);
  const description = optionalTextValue(record.description, "description", MAX_DESCRIPTION_LENGTH);
  return {
    name,
    slug,
    ...(description === undefined ? {} : { description }),
    ...(record.applicationType === undefined ? {} : { applicationType: requiredApplicationType(record.applicationType) }),
  };
}

export function parseApplicationUpdateRequest(input: unknown): ApplicationUpdateRequest {
  const record = strictBodyRecord(input, APPLICATION_UPDATE_FIELDS, true);
  if (Object.keys(record).length === 0) {
    throw invalidRequest("At least one application field is required");
  }
  const output: ApplicationUpdateRequest = {};
  if (record.name !== undefined) output.name = requiredText(record.name, "name", MAX_NAME_LENGTH);
  if (record.slug !== undefined) output.slug = requiredSlug(record.slug);
  if (record.description !== undefined) output.description = optionalTextValue(record.description, "description", MAX_DESCRIPTION_LENGTH);
  if (record.applicationType !== undefined) output.applicationType = requiredApplicationType(record.applicationType);
  return output;
}

export function parseApplicationPlatformCreateRequest(
  input: unknown,
  options: ApplicationPlatformValidationOptions = {},
): ApplicationPlatformCreateRequest {
  const record = strictBodyRecord(input, APPLICATION_PLATFORM_FIELDS, false);
  const type = requiredPlatformType(record.type);
  const redirectUris = optionalUriArray(record, "redirectUris", options.applicationType);
  const output = {
    type,
    ...(optionalTextValue(record.externalAppId, "externalAppId", MAX_SHORT_STRING_LENGTH) === undefined
      ? {}
      : { externalAppId: optionalTextValue(record.externalAppId, "externalAppId", MAX_SHORT_STRING_LENGTH) }),
    ...(optionalTextValue(record.displayName, "displayName", MAX_NAME_LENGTH) === undefined
      ? {}
      : { displayName: optionalTextValue(record.displayName, "displayName", MAX_NAME_LENGTH) }),
    ...(optionalTextValue(record.loginMode, "loginMode", MAX_SHORT_STRING_LENGTH) === undefined
      ? {}
      : { loginMode: optionalTextValue(record.loginMode, "loginMode", MAX_SHORT_STRING_LENGTH) }),
    ...(optionalTextValue(record.scope, "scope", MAX_SCOPE_LENGTH) === undefined
      ? {}
      : { scope: optionalTextValue(record.scope, "scope", MAX_SCOPE_LENGTH) }),
    ...(redirectUris === undefined ? {} : { redirectUris }),
  } as ApplicationPlatformCreateRequest & Record<string, unknown>;
  const endpointUrl = optionalEndpointUrl(record.endpointUrl);
  if (endpointUrl !== undefined) output.endpointUrl = endpointUrl;
  const secretRef = optionalSecretRef(record.secretRef);
  if (secretRef !== undefined) output.secretRef = secretRef;
  Object.assign(output, parseComponentFields(record, type, false));
  validateApplicationPlatformSemantics(output, true);
  return output as ApplicationPlatformCreateRequest;
}

export function validateApplicationPlatformSemantics(
  input: {
    type?: ApplicationPlatformType;
    externalAppId?: string | null;
    loginMode?: string | null;
    scope?: string | null;
    componentAppId?: string | null;
    authorizedAppId?: string | null;
    authorizerAppId?: string | null;
    componentBinding?: unknown;
  },
  requireExternalAppId = false,
): void {
  const type = input.type;
  const componentType = isComponentPlatformType(type);
  const hasComponentFields = componentInputHasFields(input);
  if (hasComponentFields && !componentType) {
    throw invalidRequest("WeChat component fields require a component platform type", { field: "componentAppId" });
  }
  if (type === "wechat_official_account" || type === "wechat_open_platform" || type === "wechat_mini_program" || componentType) {
    const standardType = componentType
      ? type === "wechat_open_platform_component" ? "wechat_open_platform" : "wechat_official_account"
      : type;
    if (!componentType && requireExternalAppId && !input.externalAppId) {
      throw invalidRequest("WeChat platform requires externalAppId", { field: "externalAppId" });
    }
    if (input.loginMode !== undefined && input.loginMode !== null && input.loginMode !== "") {
      const allowed = standardType === "wechat_official_account"
        ? new Set(["oauth_code"])
        : standardType === "wechat_open_platform"
          ? new Set(["qr_connect", "website_app"])
          : new Set(["code_exchange"]);
      if (!allowed.has(input.loginMode)) {
        throw invalidRequest("Invalid WeChat platform login mode", { field: "loginMode" });
      }
    }
    if (input.scope !== undefined && input.scope !== null && input.scope !== "") {
      const allowed = standardType === "wechat_official_account"
        ? new Set(["snsapi_base", "snsapi_userinfo"])
        : standardType === "wechat_open_platform"
          ? new Set(["snsapi_login"])
          : new Set();
      if (!allowed.has(input.scope)) {
        throw invalidRequest("Invalid WeChat platform scope", { field: "scope" });
      }
    }
  }
}

export function parseApplicationPlatformUpdateRequest(
  input: unknown,
  options: ApplicationPlatformValidationOptions = {},
): ApplicationPlatformUpdateRequest {
  const record = strictBodyRecord(input, APPLICATION_PLATFORM_UPDATE_FIELDS, true);
  if (Object.keys(record).length === 0) {
    throw invalidRequest("At least one platform field is required");
  }
  const output = {} as ApplicationPlatformUpdateRequest & Record<string, unknown>;
  if (record.type !== undefined) output.type = requiredPlatformType(record.type);
  assignOptionalText(output, "externalAppId", record.externalAppId, MAX_SHORT_STRING_LENGTH);
  assignOptionalText(output, "displayName", record.displayName, MAX_NAME_LENGTH);
  assignOptionalText(output, "loginMode", record.loginMode, MAX_SHORT_STRING_LENGTH);
  assignOptionalText(output, "scope", record.scope, MAX_SCOPE_LENGTH);
  if (record.redirectUris !== undefined) output.redirectUris = requiredUriArray(record.redirectUris, "redirectUris", options.applicationType);
  if (record.endpointUrl !== undefined) {
    const endpointUrl = optionalEndpointUrl(record.endpointUrl);
    if (endpointUrl === undefined) delete output.endpointUrl;
    else output.endpointUrl = endpointUrl;
  }
  const type = record.type === undefined ? undefined : requiredPlatformType(record.type);
  Object.assign(output, parseComponentFields(record, type, true));
  if (type !== undefined) {
    validateApplicationPlatformSemantics({ ...output, type }, false);
  }
  return output as ApplicationPlatformUpdateRequest;
}

export function parseApplicationClientCreateRequest(
  input: unknown,
  options: ApplicationClientValidationOptions = {},
): ApplicationClientCreateRequest {
  const record = strictBodyRecord(input, APPLICATION_CLIENT_FIELDS, false);
  const clientId = requiredClientId(record.clientId);
  const optionApplicationType = options.applicationType === undefined
    ? undefined
    : requiredApplicationType(options.applicationType);
  const applicationType = record.applicationType === undefined
    ? optionApplicationType
    : requiredApplicationType(record.applicationType);
  if (record.applicationType !== undefined && options.applicationType !== undefined && applicationType !== options.applicationType) {
    throw invalidRequest("Client applicationType does not match the application", { field: "applicationType" });
  }
  const output = { clientId } as ApplicationClientCreateRequest & Record<string, unknown>;
  if (record.applicationType !== undefined) output.applicationType = applicationType;
  const kind = readClientKindAliases(record);
  const defaultKind: ApplicationClientKind = applicationType === "native" ? "native" : "web";
  const clientKind = kind.value ?? defaultKind;
  validateClientKindForApplicationType(clientKind, applicationType);
  output.clientKind = clientKind;
  output.clientType = clientKind;
  if (record.clientIdScope !== undefined) output.clientIdScope = validateApplicationClientIdScope(record.clientIdScope);
  const rpClient = parseRpClientField(record.rpClient);
  if (rpClient !== undefined) reconcileRpClientFields(record, rpClient, clientKind, applicationType);
  if (record.redirectUris !== undefined) output.redirectUris = requiredUriArray(record.redirectUris, "redirectUris", applicationType);
  else if (rpClient !== undefined) output.redirectUris = requiredUriArray(rpClient.redirectUris, "redirectUris", applicationType);
  if (record.postLogoutRedirectUris !== undefined) {
    output.postLogoutRedirectUris = requiredUriArray(record.postLogoutRedirectUris, "postLogoutRedirectUris", applicationType);
  } else if (rpClient?.postLogoutRedirectUris !== undefined) {
    output.postLogoutRedirectUris = requiredUriArray(rpClient.postLogoutRedirectUris, "postLogoutRedirectUris", applicationType);
  }
  if (record.grantTypes !== undefined) output.grantTypes = requiredStringArray(record.grantTypes, "grantTypes", MAX_SHORT_STRING_LENGTH);
  else if (rpClient?.grantTypes !== undefined) output.grantTypes = [...rpClient.grantTypes];
  if (record.responseTypes !== undefined) output.responseTypes = requiredStringArray(record.responseTypes, "responseTypes", MAX_SHORT_STRING_LENGTH);
  else if (rpClient?.responseTypes !== undefined) output.responseTypes = [...rpClient.responseTypes];
  if (record.scopes !== undefined) output.scopes = requiredStringArray(record.scopes, "scopes", MAX_SCOPE_LENGTH);
  else if (rpClient?.scopes !== undefined) output.scopes = [...rpClient.scopes];
  const redirectPolicy = parseRedirectPolicyAliases(record);
  if (redirectPolicy.value !== undefined) output.redirectUriPolicy = redirectPolicy.value;
  if (redirectPolicy.definition !== undefined) output.redirectPolicy = redirectPolicy.definition;
  if (rpClient !== undefined) {
    output.redirectUriPolicy = rpClient.redirectUriPolicy ?? "exact";
    output.redirectPolicy = rpClient.redirectPolicy ?? { mode: "exact", exact: true };
  }
  const pkce = parsePkceAliases(record);
  if (pkce.required !== undefined) output.requirePkce = pkce.required;
  if (pkce.method !== undefined) output.pkceMethod = pkce.method;
  if (pkce.policy !== undefined) output.pkce = pkce.policy;
  if (rpClient !== undefined) {
    output.requirePkce = true;
    output.pkceMethod = "S256";
    output.pkce = rpClient.pkce ?? { required: true, method: "S256" };
  } else if (pkce.required === undefined) {
    output.requirePkce = true;
  }
   const consent = parseConsentAliases(record);
   if (consent.value !== undefined) output.consent = consent.value;
   if (consent.required !== undefined) output.consentRequired = consent.required;
   if (consent.explicit !== undefined) output.requireExplicitConsent = consent.explicit;
   if (consent.required !== undefined && consent.required !== true) {
     throw invalidRequest("OIDC RP clients require explicit consent", { field: "consentRequired" });
   }
   if (consent.explicit !== undefined && consent.explicit !== true) {
     throw invalidRequest("OIDC RP clients require explicit consent", { field: "requireExplicitConsent" });
   }
   if (consent.value !== undefined) {
     const normalizedConsent = normalizeConsentObject(consent.value);
     if (!normalizedConsent.required || normalizedConsent.mode !== "explicit") {
       throw invalidRequest("OIDC RP clients require explicit consent", { field: "consent" });
     }
   }
   if (rpClient !== undefined) {
    output.consent = rpClient.consent ?? "explicit";
    output.consentRequired = true;
    output.requireExplicitConsent = true;
    output.rpClient = rpClient;
  }
  assignTokenEndpointAuthMethod(output, record.tokenEndpointAuthMethod);
  assignTokenEndpointAuthSigningAlgorithm(output, record.tokenEndpointAuthSigningAlg);
  assignOptionalReference(output, "privateKeyRef", record.privateKeyRef, MAX_SHORT_STRING_LENGTH);
  assignOptionalEndpoint(output, "jwksUri", record.jwksUri);
  assignOptionalText(output, "keyId", record.keyId, MAX_SHORT_STRING_LENGTH);
  if (record.requirePkce !== undefined) output.requirePkce = requiredStrictBoolean(record.requirePkce, "requirePkce");
  if (output.requirePkce === false) {
    throw invalidRequest("Managed OIDC clients require PKCE", { field: "requirePkce" });
  }
  const secretRef = optionalSecretRef(record.secretRef);
  if (secretRef !== undefined) output.secretRef = secretRef;
  const authMethod = output.tokenEndpointAuthMethod ?? DEFAULT_APPLICATION_CLIENT_AUTH_METHOD;
  output.tokenEndpointAuthMethod = authMethod;
  if (authMethod === "private_key_jwt" && output.tokenEndpointAuthSigningAlg === undefined) {
    output.tokenEndpointAuthSigningAlg = DEFAULT_APPLICATION_CLIENT_AUTH_SIGNING_ALGORITHM;
  }
  if (authMethod === "client_secret_basic" || authMethod === "client_secret_post") {
    output.clientIdScope = "global";
  }
  validateApplicationClientIdScope(output.clientIdScope ?? "global");
  validateApplicationClientAuthentication(output, true);
  validateNativeRedirectUris(output.redirectUris, authMethod, applicationType, output.requirePkce ?? true);
  validateNativeRedirectUris(output.postLogoutRedirectUris, authMethod, applicationType, output.requirePkce ?? true, "postLogoutRedirectUris");
  if ((output.grantTypes ?? ["authorization_code"]).includes("authorization_code") && (output.redirectUris?.length ?? 0) === 0) {
    throw invalidRequest("Authorization-code clients require at least one redirect URI", { field: "redirectUris" });
  }
  validateManagedClientMetadata(output);
  return output as ApplicationClientCreateRequest;
}

export function validateManagedClientMetadata(input: {
  grantTypes?: readonly string[];
  responseTypes?: readonly string[];
  scopes?: readonly string[];
}): void {
  const grantTypes = input.grantTypes ?? ["authorization_code"];
  const responseTypes = input.responseTypes ?? ["code"];
  const scopes = input.scopes ?? ["openid", "profile", "email"];
  if (new Set(grantTypes).size !== grantTypes.length || grantTypes.some((grantType) => grantType !== "authorization_code" && grantType !== "refresh_token")) {
    throw invalidRequest("Managed OIDC clients support only authorization_code and refresh_token", { field: "grantTypes" });
  }
  if (new Set(responseTypes).size !== responseTypes.length || responseTypes.some((responseType) => responseType !== "code")) {
    throw invalidRequest("Managed OIDC clients support only the code response type", { field: "responseTypes" });
  }
  if (!grantTypes.includes("authorization_code")) {
    throw invalidRequest("Managed OIDC clients must support authorization_code", { field: "grantTypes" });
  }
  if (!responseTypes.includes("code")) {
    throw invalidRequest("Managed OIDC clients must support the code response type", { field: "responseTypes" });
  }
  if (!scopes.includes("openid")) {
    throw invalidRequest("Managed OIDC clients must include the openid scope", { field: "scopes" });
  }
}

export function parseApplicationClientUpdateRequest(
  input: unknown,
  options: ApplicationClientValidationOptions = {},
): ApplicationClientUpdateRequest {
  const record = strictBodyRecord(input, APPLICATION_CLIENT_UPDATE_FIELDS, true);
  if (Object.keys(record).length === 0) {
    throw invalidRequest("At least one client field is required");
  }
  const output = {} as ApplicationClientUpdateRequest & Record<string, unknown>;
  const optionApplicationType = options.applicationType === undefined
    ? undefined
    : requiredApplicationType(options.applicationType);
  const applicationType = record.applicationType === undefined
    ? optionApplicationType
    : requiredApplicationType(record.applicationType);
  if (record.applicationType !== undefined && options.applicationType !== undefined && applicationType !== options.applicationType) {
    throw invalidRequest("Client applicationType does not match the application", { field: "applicationType" });
  }
  if (record.applicationType !== undefined) output.applicationType = applicationType;
  if (record.clientId !== undefined) output.clientId = requiredClientId(record.clientId);
  const kind = readClientKindAliases(record);
  if (kind.value !== undefined) {
    validateClientKindForApplicationType(kind.value, applicationType);
    output.clientKind = kind.value;
    output.clientType = kind.value;
  }
  if (record.clientIdScope !== undefined) output.clientIdScope = validateApplicationClientIdScope(record.clientIdScope);
  const rpClient = parseRpClientField(record.rpClient);
  if (rpClient !== undefined) {
    if (kind.value !== undefined) reconcileRpClientFields(record, rpClient, kind.value, applicationType);
    else reconcileRpClientFields(record, rpClient, "web", applicationType);
    output.clientKind = "web";
    output.clientType = "web";
    output.rpClient = rpClient;
  }
  if (record.redirectUris !== undefined) output.redirectUris = requiredUriArray(record.redirectUris, "redirectUris", applicationType);
  if (record.postLogoutRedirectUris !== undefined) output.postLogoutRedirectUris = requiredUriArray(record.postLogoutRedirectUris, "postLogoutRedirectUris", applicationType);
  if (record.grantTypes !== undefined) output.grantTypes = requiredStringArray(record.grantTypes, "grantTypes", MAX_SHORT_STRING_LENGTH);
  if (record.responseTypes !== undefined) output.responseTypes = requiredStringArray(record.responseTypes, "responseTypes", MAX_SHORT_STRING_LENGTH);
  if (record.scopes !== undefined) output.scopes = requiredStringArray(record.scopes, "scopes", MAX_SCOPE_LENGTH);
  const redirectPolicy = parseRedirectPolicyAliases(record);
  if (redirectPolicy.value !== undefined) output.redirectUriPolicy = redirectPolicy.value;
  if (redirectPolicy.definition !== undefined) output.redirectPolicy = redirectPolicy.definition;
  const pkce = parsePkceAliases(record);
  if (pkce.required !== undefined) output.requirePkce = pkce.required;
  if (pkce.method !== undefined) output.pkceMethod = pkce.method;
  if (pkce.policy !== undefined) output.pkce = pkce.policy;
   const consent = parseConsentAliases(record);
   if (consent.value !== undefined) output.consent = consent.value;
   if (consent.required !== undefined) output.consentRequired = consent.required;
   if (consent.explicit !== undefined) output.requireExplicitConsent = consent.explicit;
   if (consent.required !== undefined && consent.required !== true) {
     throw invalidRequest("OIDC RP clients require explicit consent", { field: "consentRequired" });
   }
   if (consent.explicit !== undefined && consent.explicit !== true) {
     throw invalidRequest("OIDC RP clients require explicit consent", { field: "requireExplicitConsent" });
   }
   if (consent.value !== undefined) {
     const normalizedConsent = normalizeConsentObject(consent.value);
     if (!normalizedConsent.required || normalizedConsent.mode !== "explicit") {
       throw invalidRequest("OIDC RP clients require explicit consent", { field: "consent" });
     }
   }
   if (rpClient !== undefined) {
    output.redirectUriPolicy = rpClient.redirectUriPolicy ?? "exact";
    output.redirectPolicy = rpClient.redirectPolicy ?? { mode: "exact", exact: true };
    output.requirePkce = true;
    output.pkceMethod = "S256";
    output.pkce = rpClient.pkce ?? { required: true, method: "S256" };
    output.consent = rpClient.consent ?? "explicit";
    output.consentRequired = true;
    output.requireExplicitConsent = true;
  }
  assignTokenEndpointAuthMethod(output, record.tokenEndpointAuthMethod);
  assignTokenEndpointAuthSigningAlgorithm(output, record.tokenEndpointAuthSigningAlg);
  if (record.privateKeyRef !== undefined) {
    const privateKeyRef = optionalReference(record.privateKeyRef);
    if (privateKeyRef === undefined) delete output.privateKeyRef;
    else output.privateKeyRef = privateKeyRef;
  }
  if (record.jwksUri !== undefined) {
    const jwksUri = optionalEndpointUrl(record.jwksUri);
    if (jwksUri === undefined) delete output.jwksUri;
    else output.jwksUri = jwksUri;
  }
  if (record.keyId !== undefined) {
    const keyId = optionalTextValue(record.keyId, "keyId", MAX_SHORT_STRING_LENGTH);
    if (keyId === undefined) delete output.keyId;
    else output.keyId = keyId;
  }
  if (record.requirePkce !== undefined) output.requirePkce = requiredStrictBoolean(record.requirePkce, "requirePkce");
  if (output.requirePkce === false) {
    throw invalidRequest("Managed OIDC clients require PKCE", { field: "requirePkce" });
  }
  if (output.clientIdScope !== undefined) validateApplicationClientIdScope(output.clientIdScope);
  if (
    output.tokenEndpointAuthMethod !== undefined &&
    output.tokenEndpointAuthMethod !== "private_key_jwt" &&
    (output.tokenEndpointAuthSigningAlg !== undefined || output.jwksUri !== undefined || output.privateKeyRef !== undefined || output.keyId !== undefined)
  ) {
    throw invalidRequest("Asymmetric client authentication fields require private_key_jwt", { field: "tokenEndpointAuthMethod" });
  }
  if (output.tokenEndpointAuthMethod === "client_secret_basic" || output.tokenEndpointAuthMethod === "client_secret_post") {
    output.clientIdScope = "global";
  }
  validateManagedClientMetadata(output);
  return output as ApplicationClientUpdateRequest;
}

interface ClientKindAliases {
  value?: ApplicationClientKind;
  provided: boolean;
}

interface ParsedRedirectPolicy {
  value?: OidcRpRedirectUriPolicy;
  definition?: { mode: "exact"; exact: true };
}

interface ParsedPkcePolicy {
  required?: boolean;
  method?: OidcRpPkceMethod;
  policy?: { required: true; method: OidcRpPkceMethod };
}

interface ParsedConsentPolicy {
  value?: OidcRpConsent;
  required?: boolean;
  explicit?: boolean;
}

function readClientKindAliases(record: Record<string, unknown>): ClientKindAliases {
  const kindProvided = hasOwn(record, "clientKind");
  const typeProvided = hasOwn(record, "clientType");
  const kind = kindProvided ? requiredClientKind(record.clientKind, "clientKind") : undefined;
  const type = typeProvided ? requiredClientKind(record.clientType, "clientType") : undefined;
  if (kind !== undefined && type !== undefined && kind !== type) {
    throw invalidRequest("clientKind and clientType aliases conflict", { field: "clientKind" });
  }
  return { value: kind ?? type, provided: kindProvided || typeProvided };
}

function requiredClientKind(value: unknown, field: string): ApplicationClientKind {
  if (typeof value !== "string" || !APPLICATION_CLIENT_KIND_VALUES.has(value)) {
    throw invalidRequest(`Invalid ${field}`, { field });
  }
  return value as ApplicationClientKind;
}

function validateClientKindForApplicationType(kind: ApplicationClientKind, applicationType: ApplicationType | undefined): void {
  if (applicationType === undefined) return;
  if (applicationType === "native" && kind !== "native" && kind !== "mp_weixin") {
    throw invalidRequest("Native applications require a native or mini-program client kind", { field: "clientKind" });
  }
  if (applicationType === "web" && (kind === "native" || kind === "mp_weixin")) {
    throw invalidRequest("Web applications cannot use a native or mini-program client kind", { field: "clientKind" });
  }
}

function parseRpClientField(value: unknown): OidcRpClient | undefined {
  if (value === undefined) return undefined;
  if (value === null) throw invalidRequest("Invalid rpClient", { field: "rpClient" });
  const record = strictNestedRecord(value, RP_CLIENT_FIELDS, "rpClient");
  const candidate = { ...record } as Record<string, unknown>;
  if (candidate.pkce === true) candidate.pkce = { required: true, method: "S256" };
  try {
    return validateOidcRpClient(candidate);
  } catch {
    throw invalidRequest("Invalid rpClient", { field: "rpClient" });
  }
}

function reconcileRpClientFields(
  record: Record<string, unknown>,
  rpClient: OidcRpClient,
  clientKind: ApplicationClientKind,
  applicationType: ApplicationType | undefined,
): void {
  if (clientKind !== "web") {
    throw invalidRequest("OIDC RP clients must use the web client kind", { field: "clientKind" });
  }
  if (applicationType === "native") {
    throw invalidRequest("OIDC RP clients cannot belong to a native application", { field: "rpClient" });
  }
  if (hasOwn(record, "clientId") && requiredClientId(record.clientId) !== rpClient.clientId) {
    throw invalidRequest("rpClient clientId does not match the managed client", { field: "rpClient" });
  }
  for (const field of ["clientType", "clientKind"] as const) {
    if (hasOwn(record, field) && requiredClientKind(record[field], field) !== rpClient.clientKind) {
      throw invalidRequest("rpClient client kind does not match the managed client", { field });
    }
  }
  if (hasOwn(record, "redirectUris") && !sameStringArray(record.redirectUris, rpClient.redirectUris)) {
    throw invalidRequest("rpClient redirectUris do not match the managed client", { field: "rpClient" });
  }
  if (hasOwn(record, "postLogoutRedirectUris") && !sameStringArray(record.postLogoutRedirectUris, rpClient.postLogoutRedirectUris ?? [])) {
    throw invalidRequest("rpClient postLogoutRedirectUris do not match the managed client", { field: "rpClient" });
  }
  if (hasOwn(record, "grantTypes") && !sameStringArray(record.grantTypes, rpClient.grantTypes ?? ["authorization_code"])) {
    throw invalidRequest("rpClient grantTypes do not match the managed client", { field: "rpClient" });
  }
  if (hasOwn(record, "responseTypes") && !sameStringArray(record.responseTypes, rpClient.responseTypes ?? ["code"])) {
    throw invalidRequest("rpClient responseTypes do not match the managed client", { field: "rpClient" });
  }
  if (hasOwn(record, "scopes") && !sameStringArray(record.scopes, rpClient.scopes ?? ["openid"])) {
    throw invalidRequest("rpClient scopes do not match the managed client", { field: "rpClient" });
  }
  const redirectPolicy = parseRedirectPolicyAliases(record);
  if (redirectPolicy.value !== undefined && redirectPolicy.value !== rpClient.redirectUriPolicy) {
    throw invalidRequest("rpClient redirect policy does not match the managed client", { field: "rpClient" });
  }
  if (redirectPolicy.definition !== undefined && (
    redirectPolicy.definition.mode !== rpClient.redirectPolicy?.mode ||
    redirectPolicy.definition.exact !== rpClient.redirectPolicy?.exact
  )) {
    throw invalidRequest("rpClient redirect policy does not match the managed client", { field: "rpClient" });
  }
  const pkce = parsePkceAliases(record);
  if (pkce.required !== undefined && pkce.required !== rpClient.requirePkce) {
    throw invalidRequest("rpClient PKCE policy does not match the managed client", { field: "rpClient" });
  }
  if (pkce.method !== undefined && pkce.method !== rpClient.pkceMethod) {
    throw invalidRequest("rpClient PKCE method does not match the managed client", { field: "rpClient" });
  }
  const consent = parseConsentAliases(record);
  if (consent.required !== undefined && consent.required !== true) {
    throw invalidRequest("OIDC RP clients require explicit consent", { field: "consent" });
  }
  if (consent.explicit !== undefined && consent.explicit !== true) {
    throw invalidRequest("OIDC RP clients require explicit consent", { field: "requireExplicitConsent" });
  }
  if (consent.value !== undefined && !sameConsentPolicy(consent.value, rpClient.consent)) {
    throw invalidRequest("rpClient consent policy does not match the managed client", { field: "rpClient" });
  }
}

function parseRedirectPolicyAliases(record: Record<string, unknown>): ParsedRedirectPolicy {
  const hasValue = hasOwn(record, "redirectUriPolicy");
  const hasDefinition = hasOwn(record, "redirectPolicy");
  const value = hasValue ? requiredRedirectUriPolicy(record.redirectUriPolicy, "redirectUriPolicy") : undefined;
  const definition = hasDefinition ? requiredRedirectPolicy(record.redirectPolicy, "redirectPolicy") : undefined;
  if (value !== undefined && definition !== undefined && definition.mode !== value) {
    throw invalidRequest("redirectUriPolicy and redirectPolicy aliases conflict", { field: "redirectUriPolicy" });
  }
  return {
    ...(value === undefined ? {} : { value }),
    ...(definition === undefined ? {} : { definition }),
  };
}

function requiredRedirectUriPolicy(value: unknown, field: string): OidcRpRedirectUriPolicy {
  if (typeof value !== "string" || !RP_REDIRECT_URI_POLICY_VALUES.has(value)) {
    throw invalidRequest("Invalid OIDC RP redirect policy", { field });
  }
  return value as OidcRpRedirectUriPolicy;
}

function requiredRedirectPolicy(value: unknown, field: string): { mode: "exact"; exact: true } {
  if (value === null || !isRecord(value)) throw invalidRequest("Invalid OIDC RP redirect policy", { field });
  const record = strictNestedRecord(value, new Set(["mode", "exact"]), field);
  if (record.mode !== "exact" || record.exact !== true) throw invalidRequest("Invalid OIDC RP redirect policy", { field });
  return { mode: "exact", exact: true };
}

function parsePkceAliases(record: Record<string, unknown>): ParsedPkcePolicy {
  const hasRequired = hasOwn(record, "requirePkce");
  const hasMethod = hasOwn(record, "pkceMethod");
  const hasPolicy = hasOwn(record, "pkce");
  const required = hasRequired ? requiredStrictBoolean(record.requirePkce, "requirePkce") : undefined;
  const method = hasMethod ? requiredPkceMethod(record.pkceMethod, "pkceMethod") : undefined;
  const policy = hasPolicy ? requiredPkcePolicy(record.pkce, "pkce") : undefined;
  if (required === false) {
    throw invalidRequest("Managed OIDC clients require PKCE", { field: "requirePkce" });
  }
  if (policy !== undefined) {
    if (required !== undefined && required !== policy.required) {
      throw invalidRequest("requirePkce and pkce aliases conflict", { field: "requirePkce" });
    }
    if (method !== undefined && method !== policy.method) {
      throw invalidRequest("pkceMethod and pkce aliases conflict", { field: "pkceMethod" });
    }
  }
  if (method !== undefined && method !== "S256") {
    throw invalidRequest("OIDC RP clients require S256 PKCE", { field: "pkceMethod" });
  }
  return {
    ...(required === undefined ? {} : { required }),
    ...(method === undefined ? {} : { method }),
    ...(policy === undefined ? {} : { policy }),
  };
}

function requiredPkceMethod(value: unknown, field: string): OidcRpPkceMethod {
  if (typeof value !== "string" || !RP_PKCE_METHOD_VALUES.has(value)) {
    throw invalidRequest("OIDC RP clients require S256 PKCE", { field });
  }
  return value as OidcRpPkceMethod;
}

function requiredPkcePolicy(value: unknown, field: string): { required: true; method: OidcRpPkceMethod } {
  if (value === true) return { required: true, method: "S256" };
  if (value === null || !isRecord(value)) throw invalidRequest("OIDC RP clients require S256 PKCE", { field });
  const record = strictNestedRecord(value, new Set(["required", "method"]), field);
  if (record.required !== true) throw invalidRequest("OIDC RP clients require S256 PKCE", { field });
  const method = record.method === undefined ? "S256" : requiredPkceMethod(record.method, `${field}.method`);
  return { required: true, method };
}

function parseConsentAliases(record: Record<string, unknown>): ParsedConsentPolicy {
  const hasConsent = hasOwn(record, "consent");
  const hasRequired = hasOwn(record, "consentRequired");
  const hasExplicit = hasOwn(record, "requireExplicitConsent");
  const value = hasConsent ? requiredConsent(record.consent, "consent") : undefined;
  const required = hasRequired ? requiredStrictBoolean(record.consentRequired, "consentRequired") : undefined;
  const explicit = hasExplicit ? requiredStrictBoolean(record.requireExplicitConsent, "requireExplicitConsent") : undefined;
  if (required !== undefined && explicit !== undefined && required !== explicit) {
    throw invalidRequest("consentRequired and requireExplicitConsent aliases conflict", { field: "consentRequired" });
  }
  if (value !== undefined) {
    const normalized = normalizeConsentObject(value);
    if (required !== undefined && required !== normalized.required) {
      throw invalidRequest("consentRequired does not match consent", { field: "consentRequired" });
    }
    if (explicit !== undefined && explicit !== normalized.required) {
      throw invalidRequest("requireExplicitConsent does not match consent", { field: "requireExplicitConsent" });
    }
  }
  const effectiveRequired = required ?? explicit ?? (value === undefined ? undefined : normalizeConsentObject(value).required);
  const effectiveValue = value ?? (effectiveRequired === undefined ? undefined : {
    required: effectiveRequired,
    mode: effectiveRequired ? "explicit" as const : "none" as const,
  });
  return {
    ...(effectiveValue === undefined ? {} : { value: effectiveValue }),
    ...(effectiveRequired === undefined ? {} : { required: effectiveRequired }),
    ...(explicit === undefined ? {} : { explicit }),
  };
}

function requiredConsent(value: unknown, field: string): OidcRpConsent {
  if (value === "explicit" || value === "none") return value;
  if (value === null || !isRecord(value)) throw invalidRequest("Invalid OIDC RP consent policy", { field });
  const record = strictNestedRecord(value, new Set(["required", "mode", "scopes", "sensitiveScopes", "requireExplicitConsent"]), field);
  const required = record.required === undefined
    ? record.requireExplicitConsent === undefined ? undefined : requiredStrictBoolean(record.requireExplicitConsent, `${field}.requireExplicitConsent`)
    : requiredStrictBoolean(record.required, `${field}.required`);
  if (required === undefined) throw invalidRequest("Invalid OIDC RP consent policy", { field });
  const mode = record.mode === undefined ? (required ? "explicit" : "none") : requiredConsentMode(record.mode, `${field}.mode`);
  if ((mode === "explicit" && required !== true) || (mode === "none" && required !== false)) {
    throw invalidRequest("Invalid OIDC RP consent policy", { field });
  }
  if (record.requireExplicitConsent !== undefined && requiredStrictBoolean(record.requireExplicitConsent, `${field}.requireExplicitConsent`) !== required) {
    throw invalidRequest("Invalid OIDC RP consent policy", { field });
  }
  const scopes = record.scopes === undefined ? undefined : requiredStringArray(record.scopes, `${field}.scopes`, MAX_SHORT_STRING_LENGTH);
  const sensitiveScopes = record.sensitiveScopes === undefined ? undefined : requiredStringArray(record.sensitiveScopes, `${field}.sensitiveScopes`, MAX_SHORT_STRING_LENGTH);
  return {
    required,
    mode,
    ...(scopes === undefined ? {} : { scopes }),
    ...(sensitiveScopes === undefined ? {} : { sensitiveScopes }),
    ...(record.requireExplicitConsent === undefined ? {} : { requireExplicitConsent: record.requireExplicitConsent as boolean }),
  };
}

function normalizeConsentObject(value: OidcRpConsent): { required: boolean; mode: "explicit" | "none"; scopes?: string[]; sensitiveScopes?: string[] } {
  if (typeof value === "string") return { required: value === "explicit", mode: value };
  return {
    required: value.required,
    mode: value.mode ?? (value.required ? "explicit" : "none"),
    ...(value.scopes === undefined ? {} : { scopes: [...value.scopes] }),
    ...(value.sensitiveScopes === undefined ? {} : { sensitiveScopes: [...value.sensitiveScopes] }),
  };
}

function requiredConsentMode(value: unknown, field: string): "explicit" | "none" {
  if (typeof value !== "string" || !RP_CONSENT_MODE_VALUES.has(value)) {
    throw invalidRequest("Invalid OIDC RP consent policy", { field });
  }
  return value as "explicit" | "none";
}

function sameConsentPolicy(left: OidcRpConsent, right: OidcRpConsent | undefined): boolean {
  if (right === undefined) return false;
  const a = normalizeConsentObject(left);
  const b = normalizeConsentObject(right);
  return a.required === b.required && a.mode === b.mode && sameStringArray(a.scopes ?? [], b.scopes ?? []) && sameStringArray(a.sensitiveScopes ?? [], b.sensitiveScopes ?? []);
}

function sameStringArray(left: unknown, right: unknown): boolean {
  if (!Array.isArray(left) || !Array.isArray(right) || left.length !== right.length) return false;
  return left.every((value, index) => value === right[index]);
}

function requiredStrictBoolean(value: unknown, field: string): boolean {
  if (typeof value !== "boolean") throw invalidRequest(`Invalid ${field}`, { field });
  return value;
}

function hasOwn(record: Record<string, unknown>, field: string): boolean {
  return Object.prototype.hasOwnProperty.call(record, field);
}

export function parseApplicationClientRotateSecretRequest(input: unknown): ApplicationClientRotateSecretRequest {
  const record = strictBodyRecord(input, new Set(["secretRef", "expectedVersion"]), true);
  const secretRef = optionalSecretRef(record.secretRef);
  if (secretRef === undefined) throw invalidRequest("A new secretRef is required", { field: "secretRef" });
  const output: ApplicationClientRotateSecretRequest = { secretRef };
  if (record.expectedVersion !== undefined) output.expectedVersion = readVersion(record.expectedVersion, "expectedVersion");
  return output;
}

export const parseApplicationPlatformRotateSecretRequest = parseApplicationClientRotateSecretRequest;
export const parseApplicationClientSecretRotationRequest = parseApplicationClientRotateSecretRequest;

export function parseApplicationLifecycleActionRequest(input: unknown): { expectedVersion?: ApplicationVersion } {
  const record = strictBodyRecord(input, new Set(["expectedVersion"]), true);
  if (record.expectedVersion === undefined) return {};
  return { expectedVersion: readVersion(record.expectedVersion, "expectedVersion") };
}

export const parseApplicationArchiveRequest = parseApplicationLifecycleActionRequest;
export const parseApplicationRestoreRequest = parseApplicationLifecycleActionRequest;
export const parseApplicationPurgeRequest = parseApplicationLifecycleActionRequest;
export const parseApplicationValidateRequest = parseApplicationLifecycleActionRequest;

export function parseApplicationIdentifier(input: unknown, field = "applicationId"): string {
  return requiredIdentifier(input, field);
}

export function parseApplicationPlatformIdentifier(input: unknown, field = "platformId"): string {
  return requiredIdentifier(input, field);
}

export function parseApplicationClientIdentifier(input: unknown, field = "clientId"): string {
  return requiredIdentifier(input, field);
}

export function parseApplicationWriteQuery(input: unknown): Record<string, never> {
  if (input === undefined || input === null) return {};
  if (!isRecord(input)) throw invalidRequest("Request query must be an object");
  const keys = Object.keys(input);
  for (const key of keys) rejectSensitiveField(key);
  if (keys.length > 0) throw invalidRequest("Request query is not supported", { field: keys[0] });
  return {};
}

export const parseApplicationMutationQuery = parseApplicationWriteQuery;

export function parseApplicationMutationBody(input: unknown): Record<string, never> {
  if (input === undefined || input === null) return {};
  if (!isRecord(input)) throw invalidRequest("Request body must be an object");
  const keys = Object.keys(input);
  for (const key of keys) rejectSensitiveField(key);
  if (keys.length > 0) {
    throw invalidRequest("Request body is not supported", { field: keys[0] });
  }
  return {};
}

export function validateApplicationEndpointUrl(input: unknown, field = "endpointUrl"): string {
  if (typeof input !== "string") throw invalidRequest(`Invalid ${field}`, { field });
  const value = input.trim();
  if (
    value.length === 0 ||
    value.length > MAX_STRING_LENGTH ||
    CONTROL_CHARACTERS.test(value) ||
    /\s/u.test(value) ||
    value.includes("\\") ||
    value.includes("?") ||
    value.includes("#")
  ) {
    throw invalidRequest(`Invalid ${field}`, { field });
  }
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw invalidRequest(`Invalid ${field}`, { field });
  }
  if (
    (parsed.protocol !== "http:" && parsed.protocol !== "https:") ||
    (parsed.protocol !== "https:" && !isApplicationLoopbackHost(parsed.hostname)) ||
    !parsed.hostname ||
    parsed.username ||
    parsed.password ||
    parsed.origin === "null" ||
    parsed.search ||
    parsed.hash
  ) {
    throw invalidRequest(`Invalid ${field}`, { field });
  }
  return parsed.toString();
}

export const parseApplicationEndpointUrl = validateApplicationEndpointUrl;

export function validateApplicationSecretRef(input: unknown, field = "secretRef"): string {
  if (typeof input !== "string") throw invalidRequest(`Invalid ${field}`, { field });
  const value = input.trim();
  if (value.length === 0 || value.length > MAX_SHORT_STRING_LENGTH || CONTROL_CHARACTERS.test(value)) {
    throw invalidRequest(`Invalid ${field}`, { field });
  }
  return value;
}

export const parseApplicationSecretRef = validateApplicationSecretRef;

function parseComponentFields(
  record: Record<string, unknown>,
  type: ApplicationPlatformType | undefined,
  update: boolean,
): Record<string, unknown> {
  const output: Record<string, unknown> = {};
  const nested = hasOwn(record, "componentBinding")
    ? record.componentBinding === null
      ? update ? {} : invalidComponentBinding("componentBinding must be an object")
      : strictNestedRecord(record.componentBinding, COMPONENT_BINDING_FIELDS, "componentBinding")
    : undefined;
  const nestedRecord = nested === undefined ? {} : nested;
  const readText = (field: string, maxLength: number): string | null | undefined => {
    const topPresent = hasOwn(record, field);
    const nestedPresent = hasOwn(nestedRecord, field);
    if (topPresent && record[field] === null) {
      if (update) return null;
      throw invalidRequest(`Invalid ${field}`, { field });
    }
    if (nestedPresent && nestedRecord[field] === null) {
      if (update) return null;
      throw invalidRequest(`Invalid componentBinding.${field}`, { field: `componentBinding.${field}` });
    }
    const topValue = topPresent ? requiredText(record[field], field, maxLength) : undefined;
    const nestedValue = nestedPresent ? requiredText(nestedRecord[field], `componentBinding.${field}`, maxLength) : undefined;
    if (topValue !== undefined && nestedValue !== undefined && topValue !== nestedValue) {
      throw invalidRequest(`${field} aliases conflict`, { field });
    }
    return topValue ?? nestedValue;
  };
  const readRef = (field: string): string | null | undefined => {
    const topPresent = hasOwn(record, field);
    const nestedPresent = hasOwn(nestedRecord, field);
    if (topPresent && record[field] === null) {
      if (update) return null;
      throw invalidRequest(`Invalid ${field}`, { field });
    }
    if (nestedPresent && nestedRecord[field] === null) {
      if (update) return null;
      throw invalidRequest(`Invalid componentBinding.${field}`, { field: `componentBinding.${field}` });
    }
    const topValue = topPresent ? optionalSecretRef(record[field]) : undefined;
    const nestedValue = nestedPresent ? optionalSecretRef(nestedRecord[field]) : undefined;
    if (topValue !== undefined && nestedValue !== undefined && topValue !== nestedValue) {
      throw invalidRequest(`${field} aliases conflict`, { field });
    }
    return topValue ?? nestedValue;
  };
  const componentAppId = readText("componentAppId", MAX_SHORT_STRING_LENGTH);
  const authorizedAppId = readText("authorizedAppId", MAX_SHORT_STRING_LENGTH);
  const authorizerAppId = readText("authorizerAppId", MAX_SHORT_STRING_LENGTH);
  if (authorizedAppId !== undefined && authorizerAppId !== undefined && authorizedAppId !== null && authorizerAppId !== null && authorizedAppId !== authorizerAppId) {
    throw invalidRequest("authorizedAppId and authorizerAppId aliases conflict", { field: "authorizedAppId" });
  }
  const componentAppSecretRef = readRef("componentAppSecretRef");
  const componentVerifyTicketRef = readRef("componentVerifyTicketRef");
  const componentAccessTokenRef = readRef("componentAccessTokenRef");
  const authorizerRefreshTokenRef = readRef("authorizerRefreshTokenRef");
  const authorizerAccessTokenRef = readRef("authorizerAccessTokenRef");
  const componentTicketRef = readRef("componentTicketRef");
  const componentTicketExpiresAt = readComponentDate(record, nestedRecord, update);
  const componentBindingStatus = readComponentStatus(record, nestedRecord, update);
  const componentBindingVersion = readComponentVersion(record, nestedRecord, update);
  const componentScope = readComponentScope(record, nestedRecord, update);
  const assign = (field: string, value: string | number | null | undefined): void => {
    if (value !== undefined) output[field] = value;
  };
  assign("componentAppId", componentAppId);
  assign("authorizedAppId", authorizedAppId);
  assign("authorizerAppId", authorizerAppId);
  assign("componentAppSecretRef", componentAppSecretRef);
  assign("componentVerifyTicketRef", componentVerifyTicketRef);
  assign("componentAccessTokenRef", componentAccessTokenRef);
  assign("authorizerRefreshTokenRef", authorizerRefreshTokenRef);
  assign("authorizerAccessTokenRef", authorizerAccessTokenRef);
  assign("componentTicketRef", componentTicketRef);
  assign("componentTicketExpiresAt", componentTicketExpiresAt);
  assign("componentBindingStatus", componentBindingStatus);
  assign("componentBindingVersion", componentBindingVersion);
  assign("componentScope", componentScope);
  const hasTopLevelBinding = [
    "componentAppId",
    "authorizedAppId",
    "authorizerAppId",
    "componentAppSecretRef",
    "componentVerifyTicketRef",
    "componentAccessTokenRef",
    "authorizerRefreshTokenRef",
    "authorizerAccessTokenRef",
    "componentTicketRef",
    "componentTicketExpiresAt",
    "componentBindingStatus",
    "componentBindingVersion",
    "componentScope",
  ].some((field) => hasOwn(record, field));
  if (nested !== undefined || hasTopLevelBinding) {
    const binding: Record<string, unknown> = {};
    if (componentAppId !== undefined && componentAppId !== null) binding.componentAppId = componentAppId;
    if (authorizedAppId !== undefined && authorizedAppId !== null) binding.authorizedAppId = authorizedAppId;
    if (authorizerAppId !== undefined && authorizerAppId !== null) binding.authorizerAppId = authorizerAppId;
    if (componentAppSecretRef !== undefined && componentAppSecretRef !== null) binding.componentAppSecretRef = componentAppSecretRef;
    if (componentVerifyTicketRef !== undefined && componentVerifyTicketRef !== null) binding.componentVerifyTicketRef = componentVerifyTicketRef;
    if (componentAccessTokenRef !== undefined && componentAccessTokenRef !== null) binding.componentAccessTokenRef = componentAccessTokenRef;
    if (authorizerRefreshTokenRef !== undefined && authorizerRefreshTokenRef !== null) binding.authorizerRefreshTokenRef = authorizerRefreshTokenRef;
    if (authorizerAccessTokenRef !== undefined && authorizerAccessTokenRef !== null) binding.authorizerAccessTokenRef = authorizerAccessTokenRef;
    if (componentTicketRef !== undefined && componentTicketRef !== null) binding.componentTicketRef = componentTicketRef;
    if (componentTicketExpiresAt !== undefined && componentTicketExpiresAt !== null) binding.componentTicketExpiresAt = componentTicketExpiresAt;
    if (componentBindingStatus !== undefined && componentBindingStatus !== null) binding.status = componentBindingStatus;
    if (componentBindingVersion !== undefined && componentBindingVersion !== null) binding.version = componentBindingVersion;
    if (componentScope !== undefined && componentScope !== null) binding.scope = componentScope;
    if (Object.keys(binding).length > 0) output.componentBinding = binding as unknown as WechatComponentPlatformBinding;
  }
  const hasComponentFields = componentInputHasFields(record);
  if (hasComponentFields && !isComponentPlatformType(type) && (!update || type !== undefined)) {
    throw invalidRequest("WeChat component fields require a component platform type", { field: "componentAppId" });
  }
  if (isComponentPlatformType(type) && !update) {
    validateComponentBindingIdentity(output);
  }
  return output;
}

function invalidComponentBinding(message: string): never {
  throw invalidRequest(message, { field: "componentBinding" });
}

function readComponentDate(
  record: Record<string, unknown>,
  nested: Record<string, unknown>,
  update: boolean,
): string | null | undefined {
  const topPresent = hasOwn(record, "componentTicketExpiresAt");
  const nestedPresent = hasOwn(nested, "componentTicketExpiresAt");
  const read = (value: unknown, field: string): string | null => {
    if (value === null) {
      if (update) return null;
      throw invalidRequest(`Invalid ${field}`, { field });
    }
    if (typeof value !== "string" || value !== value.trim() || value.length === 0 || value.length > 128 || /[\u0000-\u001f\u007f]/u.test(value)) {
      throw invalidRequest(`Invalid ${field}`, { field });
    }
    const date = new Date(value);
    if (!Number.isFinite(date.getTime())) throw invalidRequest(`Invalid ${field}`, { field });
    return date.toISOString();
  };
  const top = topPresent ? read(record.componentTicketExpiresAt, "componentTicketExpiresAt") : undefined;
  const nestedValue = nestedPresent ? read(nested.componentTicketExpiresAt, "componentBinding.componentTicketExpiresAt") : undefined;
  if (top !== undefined && nestedValue !== undefined && top !== nestedValue) throw invalidRequest("componentTicketExpiresAt aliases conflict", { field: "componentTicketExpiresAt" });
  return top ?? nestedValue;
}

function readComponentStatus(
  record: Record<string, unknown>,
  nested: Record<string, unknown>,
  update: boolean,
): WechatComponentBindingStatus | null | undefined {
  const topPresent = hasOwn(record, "componentBindingStatus");
  const nestedPresent = hasOwn(nested, "status");
  const read = (value: unknown, field: string): WechatComponentBindingStatus | null => {
    if (value === null) {
      if (update) return null;
      throw invalidRequest(`Invalid ${field}`, { field });
    }
    if (typeof value !== "string" || !COMPONENT_BINDING_STATUS_VALUES.has(value)) throw invalidRequest(`Invalid ${field}`, { field });
    return value as WechatComponentBindingStatus;
  };
  const top = topPresent ? read(record.componentBindingStatus, "componentBindingStatus") : undefined;
  const nestedValue = nestedPresent ? read(nested.status, "componentBinding.status") : undefined;
  if (top !== undefined && nestedValue !== undefined && top !== nestedValue) throw invalidRequest("component binding status aliases conflict", { field: "componentBindingStatus" });
  return top ?? nestedValue;
}

function readComponentVersion(
  record: Record<string, unknown>,
  nested: Record<string, unknown>,
  update: boolean,
): number | string | null | undefined {
  const topPresent = hasOwn(record, "componentBindingVersion");
  const nestedPresent = hasOwn(nested, "version");
  const read = (value: unknown, field: string): number | string | null => {
    if (value === null) {
      if (update) return null;
      throw invalidRequest(`Invalid ${field}`, { field });
    }
    return readVersion(value, field);
  };
  const top = topPresent ? read(record.componentBindingVersion, "componentBindingVersion") : undefined;
  const nestedValue = nestedPresent ? read(nested.version, "componentBinding.version") : undefined;
  if (top !== undefined && nestedValue !== undefined && String(top) !== String(nestedValue)) throw invalidRequest("component binding version aliases conflict", { field: "componentBindingVersion" });
  return top ?? nestedValue;
}

function readComponentScope(
  record: Record<string, unknown>,
  nested: Record<string, unknown>,
  update: boolean,
): string | null | undefined {
  const topPresent = hasOwn(record, "componentScope");
  const nestedPresent = hasOwn(nested, "scope");
  const read = (value: unknown, field: string): string | null => {
    if (value === null) {
      if (update) return null;
      throw invalidRequest(`Invalid ${field}`, { field });
    }
    return requiredText(value, field, MAX_SHORT_STRING_LENGTH);
  };
  const top = topPresent ? read(record.componentScope, "componentScope") : undefined;
  const nestedValue = nestedPresent ? read(nested.scope, "componentBinding.scope") : undefined;
  if (top !== undefined && nestedValue !== undefined && top !== nestedValue) throw invalidRequest("component scope aliases conflict", { field: "componentScope" });
  return top ?? nestedValue;
}

function componentInputHasFields(input: Record<string, unknown>): boolean {
  return [
    "componentAppId",
    "authorizedAppId",
    "authorizerAppId",
    "componentBinding",
    "componentAppSecretRef",
    "componentVerifyTicketRef",
    "componentAccessTokenRef",
    "authorizerRefreshTokenRef",
    "authorizerAccessTokenRef",
    "componentTicketRef",
    "componentTicketExpiresAt",
    "componentBindingStatus",
    "componentBindingVersion",
    "componentScope",
  ].some((field) => hasOwn(input, field));
}

function isComponentPlatformType(value: unknown): value is Extract<ApplicationPlatformType, "wechat_component" | "wechat_open_platform_component"> {
  return typeof value === "string" && COMPONENT_PLATFORM_TYPE_VALUES.has(value);
}

function validateComponentBindingIdentity(input: {
  componentAppId?: unknown;
  authorizedAppId?: unknown;
  authorizerAppId?: unknown;
  componentBinding?: unknown;
}): void {
  const binding = isRecord(input.componentBinding) ? input.componentBinding : undefined;
  const componentAppId = input.componentAppId ?? binding?.componentAppId;
  const authorizedAppId = input.authorizedAppId ?? binding?.authorizedAppId;
  const authorizerAppId = input.authorizerAppId ?? binding?.authorizerAppId;
  if (typeof componentAppId !== "string" || componentAppId.trim().length === 0) {
    throw invalidRequest("WeChat component platform requires componentAppId", { field: "componentAppId" });
  }
  if (authorizedAppId !== undefined && authorizerAppId !== undefined && authorizedAppId !== authorizerAppId) {
    throw invalidRequest("WeChat component account aliases conflict", { field: "authorizedAppId" });
  }
  if ((typeof authorizedAppId !== "string" || authorizedAppId.trim().length === 0) && (typeof authorizerAppId !== "string" || authorizerAppId.trim().length === 0)) {
    throw invalidRequest("WeChat component platform requires an authorized account", { field: "authorizedAppId" });
  }
}

export function isApplicationPlatformType(value: unknown): value is ApplicationPlatformType {
  return typeof value === "string" &&
    !UNSAFE_NAMES.has(value.toLowerCase()) &&
    (PLATFORM_TYPES.has(value) || /^[A-Za-z][A-Za-z0-9._-]{0,63}$/u.test(value));
}

function strictBodyRecord(
  input: unknown,
  allowed: ReadonlySet<string>,
  allowEmpty: boolean,
): Record<string, unknown> {
  if (input === undefined || input === null) {
    if (allowEmpty) return {};
    throw invalidRequest("Request body must be an object");
  }
  if (!isRecord(input)) throw invalidRequest("Request body must be an object");
  for (const key of Object.keys(input)) {
    if (!REFERENCE_FIELD_NAMES.has(key)) rejectSensitiveField(key);
    if (!allowed.has(key)) {
      throw invalidRequest("Unsupported request field", { field: key });
    }
  }
  if (!allowEmpty && Object.keys(input).length === 0) {
    throw invalidRequest("Request body must include required fields");
  }
  return input;
}

function strictNestedRecord(
  input: unknown,
  allowed: ReadonlySet<string>,
  field: string,
): Record<string, unknown> {
  if (!isRecord(input)) throw invalidRequest(`Invalid ${field}`, { field });
  for (const key of Object.keys(input)) {
    if (!REFERENCE_FIELD_NAMES.has(key)) rejectSensitiveField(key);
    if (!allowed.has(key)) throw invalidRequest("Unsupported request field", { field: `${field}.${key}` });
  }
  return input;
}

function strictQueryRecord(input: unknown, allowed: ReadonlySet<string>): Record<string, unknown> {
  if (input === undefined || input === null) return {};
  if (!isRecord(input)) throw invalidRequest("Request query must be an object");
  for (const key of Object.keys(input)) {
    rejectTenantOrSensitiveField(key);
    if (!allowed.has(key)) {
      throw invalidRequest("Unsupported query field", { field: key });
    }
  }
  return input;
}

function rejectSensitiveField(key: string): void {
  const normalized = key.replace(/[-_]/g, "").toLowerCase();
  if (normalized === "tenantid" || normalized === "tenant") {
    throw invalidRequest("Tenant selection is not supported", { field: key });
  }
  if (
    normalized === "metadata" ||
    normalized === "secret" ||
    normalized === "clientsecret" ||
    normalized === "token" ||
    normalized.includes("accesstoken") ||
    normalized.includes("refreshtoken") ||
    normalized.includes("idtoken") ||
    normalized.includes("privatekey")
  ) {
    throw invalidRequest("Sensitive request field is not supported", { field: key });
  }
}

function rejectTenantOrSensitiveField(key: string): void {
  rejectSensitiveField(key);
}

function requiredIdentifier(value: unknown, field: string): string {
  return requiredText(value, field, 256);
}

function requiredText(value: unknown, field: string, maxLength: number): string {
  if (typeof value !== "string") throw invalidRequest(`Invalid ${field}`, { field });
  const normalized = value.trim();
  if (normalized.length === 0 || normalized.length > maxLength || CONTROL_CHARACTERS.test(normalized)) {
    throw invalidRequest(`Invalid ${field}`, { field });
  }
  return normalized;
}

function requiredSlug(value: unknown): string {
  const slug = requiredText(value, "slug", MAX_SLUG_LENGTH);
  if (!/^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$/u.test(slug) || UNSAFE_NAMES.has(slug.toLowerCase())) {
    throw invalidRequest("Invalid slug", { field: "slug" });
  }
  return slug;
}

function requiredPlatformType(value: unknown): ApplicationPlatformType {
  if (!isApplicationPlatformType(value)) throw invalidRequest("Invalid platform type", { field: "type" });
  return value;
}

function requiredClientId(value: unknown): string {
  const clientId = requiredText(value, "clientId", MAX_SHORT_STRING_LENGTH);
  if (/\s/u.test(clientId) || UNSAFE_NAMES.has(clientId.toLowerCase())) {
    throw invalidRequest("Invalid clientId", { field: "clientId" });
  }
  return clientId;
}

function optionalText(
  record: Record<string, unknown>,
  field: string,
  maxLength: number,
): Record<string, string> {
  if (record[field] === undefined || record[field] === null || record[field] === "") return {};
  return { [field]: requiredText(record[field], field, maxLength) };
}

function optionalTextValue(
  value: unknown,
  field: string,
  maxLength: number,
): string | undefined {
  if (value === undefined || value === null || value === "") return undefined;
  return requiredText(value, field, maxLength);
}

function assignOptionalText<T extends object>(
  target: T,
  field: string,
  value: unknown,
  maxLength: number,
): void {
  if (value === undefined) return;
  const normalized = optionalTextValue(value, field, maxLength);
  if (normalized !== undefined) (target as Record<string, unknown>)[field] = normalized;
}

function assignTokenEndpointAuthMethod<T extends object>(target: T, value: unknown): void {
  if (value === undefined || value === null || value === "") return;
  if (typeof value !== "string" || !TOKEN_ENDPOINT_AUTH_METHODS.has(value)) {
    throw invalidRequest("Invalid tokenEndpointAuthMethod", { field: "tokenEndpointAuthMethod" });
  }
  (target as Record<string, unknown>).tokenEndpointAuthMethod = value;
}

function assignTokenEndpointAuthSigningAlgorithm<T extends object>(target: T, value: unknown): void {
  if (value === undefined || value === null || value === "") return;
  (target as Record<string, unknown>).tokenEndpointAuthSigningAlg =
    validateApplicationClientAuthSigningAlgorithm(value);
}

function assignOptionalReference<T extends object>(target: T, field: string, value: unknown, maxLength: number): void {
  if (value === undefined) return;
  const normalized = optionalTextValue(value, field, maxLength);
  if (normalized !== undefined) (target as Record<string, unknown>)[field] = normalized;
}

function assignOptionalEndpoint<T extends object>(target: T, field: string, value: unknown): void {
  if (value === undefined) return;
  const normalized = optionalEndpointUrl(value);
  if (normalized !== undefined) (target as Record<string, unknown>)[field] = normalized;
}

function optionalReference(value: unknown): string | undefined {
  if (value === undefined || value === null || value === "") return undefined;
  return validateApplicationSecretRef(value, "privateKeyRef");
}

export function validateNativeRedirectUris(
  uris: readonly string[] | undefined,
  authMethod: string | undefined,
  applicationType: ApplicationType | undefined,
  requirePkce = true,
  field = "redirectUris",
): void {
  if (applicationType !== "native") return;
  if (!requirePkce) {
    throw invalidRequest("Native OIDC clients require PKCE", { field: "requirePkce" });
  }
  if (uris?.some((uri) => isNativePrivateUseUri(uri)) && authMethod !== "none") {
    throw invalidRequest("Native private-use redirect URIs require public OIDC clients", { field });
  }
}

export function validateApplicationClientAuthentication(
  input: {
    tokenEndpointAuthMethod?: string;
    tokenEndpointAuthSigningAlg?: string;
    jwksUri?: string;
    privateKeyRef?: string;
    keyId?: string;
    secretRef?: string | null;
    hasSecret?: boolean;
    secretStatus?: string;
    requirePkce?: boolean;
    applicationType?: ApplicationType;
    clientIdScope?: string;
    clientKind?: ApplicationClientKind;
    clientType?: ApplicationClientKind;
    redirectUriPolicy?: OidcRpRedirectUriPolicy;
    redirectPolicy?: { mode: "exact"; exact: true };
    pkce?: { required: true; method: OidcRpPkceMethod };
    pkceMethod?: OidcRpPkceMethod;
    consent?: OidcRpConsent;
    consentRequired?: boolean;
    requireExplicitConsent?: boolean;
    rpClient?: OidcRpClient;
  },
  requireSecret = true,
): void {
  const authMethod = input.tokenEndpointAuthMethod ?? DEFAULT_APPLICATION_CLIENT_AUTH_METHOD;
  if (typeof authMethod !== "string" || !TOKEN_ENDPOINT_AUTH_METHODS.has(authMethod)) {
    throw invalidRequest("Invalid tokenEndpointAuthMethod", { field: "tokenEndpointAuthMethod" });
  }
  if (input.tokenEndpointAuthSigningAlg !== undefined) {
    validateApplicationClientAuthSigningAlgorithm(input.tokenEndpointAuthSigningAlg);
  }
  if (input.clientIdScope !== undefined) validateApplicationClientIdScope(input.clientIdScope);
  if (input.requirePkce === false) {
    throw invalidRequest("Managed OIDC clients require PKCE", { field: "requirePkce" });
  }
  if (input.pkceMethod !== undefined) requiredPkceMethod(input.pkceMethod, "pkceMethod");
  if (input.pkce !== undefined && (input.pkce.required !== true || input.pkce.method !== "S256")) {
    throw invalidRequest("Managed OIDC clients require S256 PKCE", { field: "pkce" });
  }
  if (input.redirectUriPolicy !== undefined) requiredRedirectUriPolicy(input.redirectUriPolicy, "redirectUriPolicy");
  if (input.redirectPolicy !== undefined) requiredRedirectPolicy(input.redirectPolicy, "redirectPolicy");
  if (input.consentRequired !== undefined && input.consentRequired !== true) {
    throw invalidRequest("OIDC RP clients require explicit consent", { field: "consentRequired" });
  }
  if (input.requireExplicitConsent !== undefined && input.requireExplicitConsent !== true) {
    throw invalidRequest("OIDC RP clients require explicit consent", { field: "requireExplicitConsent" });
  }
  if (input.consent !== undefined) {
    const consent = normalizeConsentObject(input.consent);
    if (input.rpClient !== undefined && (!consent.required || consent.mode !== "explicit")) {
      throw invalidRequest("OIDC RP clients require explicit consent", { field: "consent" });
    }
  }
  if (input.rpClient !== undefined) {
    if (input.clientKind !== undefined && input.clientKind !== "web") {
      throw invalidRequest("OIDC RP clients must use the web client kind", { field: "clientKind" });
    }
    if (input.clientType !== undefined && input.clientType !== "web") {
      throw invalidRequest("OIDC RP clients must use the web client type", { field: "clientType" });
    }
    if (input.rpClient.clientKind !== "web" || input.rpClient.clientType !== "web") {
      throw invalidRequest("OIDC RP clients must use the web client kind", { field: "rpClient" });
    }
  }
  if (input.clientKind !== undefined && input.clientType !== undefined && input.clientKind !== input.clientType) {
    throw invalidRequest("clientKind and clientType aliases conflict", { field: "clientKind" });
  }
  if (input.applicationType !== undefined && input.applicationType !== "web" && input.applicationType !== "native") {
    throw invalidRequest("Invalid applicationType", { field: "applicationType" });
  }
  if (input.clientKind !== undefined) validateClientKindForApplicationType(input.clientKind, input.applicationType);
  if (authMethod === "private_key_jwt") {
    if (input.secretRef !== undefined && input.secretRef !== null) {
      throw invalidRequest("private_key_jwt clients must not define a secretRef", { field: "secretRef" });
    }
    if (input.hasSecret === true || ["configured", "active", "retiring"].includes(input.secretStatus ?? "")) {
      throw invalidRequest("private_key_jwt clients must not have a client secret", { field: "secretRef" });
    }
    if (input.jwksUri === undefined && input.privateKeyRef === undefined) {
      throw invalidRequest("private_key_jwt clients require a JWKS URI or privateKeyRef", { field: "jwksUri" });
    }
    return;
  }
  if (input.tokenEndpointAuthSigningAlg !== undefined || input.jwksUri !== undefined || input.privateKeyRef !== undefined || input.keyId !== undefined) {
    throw invalidRequest("Asymmetric client authentication fields require private_key_jwt", { field: "tokenEndpointAuthMethod" });
  }
  if (authMethod === "none") {
    if (input.secretRef !== undefined && input.secretRef !== null) {
      throw invalidRequest("Public OIDC clients must not define a secretRef", { field: "secretRef" });
    }
    if (input.hasSecret === true || ["configured", "active", "retiring"].includes(input.secretStatus ?? "")) {
      throw invalidRequest("Public OIDC clients must not have a secret", { field: "secretRef" });
    }
    return;
  }
  if (requireSecret && input.secretRef === undefined) {
    throw invalidRequest("Confidential OIDC clients require a secretRef", { field: "secretRef" });
  }
  validateApplicationClientIdScope("global");
}

function requiredStringArray(value: unknown, field: string, maxLength: number): string[] {
  if (!Array.isArray(value) || value.length > MAX_ARRAY_ITEMS) {
    throw invalidRequest(`Invalid ${field}`, { field });
  }
  const output: string[] = [];
  for (const item of value) {
    const normalized = requiredText(item, field, maxLength);
    if (/\s/u.test(normalized)) throw invalidRequest(`Invalid ${field}`, { field });
    if (output.includes(normalized)) throw invalidRequest(`Duplicate ${field}`, { field });
    output.push(normalized);
  }
  return output;
}

function optionalUriArray(record: Record<string, unknown>, field: string, applicationType?: ApplicationType): string[] | undefined {
  if (record[field] === undefined || record[field] === null) return undefined;
  return requiredUriArray(record[field], field, applicationType);
}

function requiredUriArray(value: unknown, field: string, applicationType?: ApplicationType): string[] {
  if (!Array.isArray(value) || value.length > MAX_ARRAY_ITEMS) {
    throw invalidRequest(`Invalid ${field}`, { field });
  }
  const output: string[] = [];
  for (const item of value) {
    if (typeof item !== "string" || item !== item.trim()) throw invalidRequest(`Invalid ${field}`, { field });
    const normalized = item;
    if (
      normalized.length === 0 ||
      normalized.length > MAX_STRING_LENGTH ||
      CONTROL_CHARACTERS.test(normalized) ||
      /\\|\s/u.test(normalized) ||
      !/^[A-Za-z][A-Za-z0-9+.-]*:/u.test(normalized)
    ) {
      throw invalidRequest(`Invalid ${field}`, { field });
    }
    const lower = normalized.toLowerCase();
    if (["javascript:", "data:", "file:", "vbscript:"].some((scheme) => lower.startsWith(scheme))) {
      throw invalidRequest(`Invalid ${field}`, { field });
    }
    if (applicationType === "native" && isNativePrivateUseUri(normalized)) {
      const separator = normalized.indexOf(":");
      if (separator <= 0 || separator > 255 || normalized.slice(separator + 1).startsWith("//")) {
        throw invalidRequest(`Invalid ${field}`, { field });
      }
      if (output.includes(normalized)) {
        throw invalidRequest(`Duplicate ${field}`, { field });
      }
      output.push(normalized);
      continue;

    }
    let parsed: URL;
    try {
      parsed = new URL(normalized);
    } catch {
      throw invalidRequest(`Invalid ${field}`, { field });
    }
    if (
      (parsed.protocol !== "https:" && parsed.protocol !== "http:") ||
      (parsed.protocol !== "https:" && !isApplicationLoopbackHost(parsed.hostname)) ||
       (applicationType === "native" && parsed.protocol === "http:" && !isApplicationLoopbackHost(parsed.hostname)) ||
       (applicationType === "native" && parsed.protocol === "https:" && isApplicationLoopbackHost(parsed.hostname)) ||
       parsed.username ||

      parsed.password ||
      parsed.hash
    ) {
      throw invalidRequest(`Invalid ${field}`, { field });
    }
    if ((parsed.protocol === "http:" || parsed.protocol === "https:") && !parsed.hostname) {
      throw invalidRequest(`Invalid ${field}`, { field });
    }
    if (output.includes(normalized)) {
      throw invalidRequest(`Duplicate ${field}`, { field });
    }
    output.push(normalized);
  }
  return output;
}

function requiredBoolean(value: unknown, field: string): boolean {
  if (typeof value === "boolean") return value;
  if (value === "true") return true;
  if (value === "false") return false;
  throw invalidRequest(`Invalid ${field}`, { field });
}

function optionalApplicationStatus(record: Record<string, unknown>): { status?: ApplicationStatus } {
  if (record.status === undefined || record.status === null || record.status === "") return {};
  if (typeof record.status !== "string") throw invalidRequest("Invalid status", { field: "status" });
  const normalized = record.status.trim().toLowerCase();
  if (normalized !== "active" && normalized !== "disabled" && normalized !== "archived" && normalized !== "purged") {
    throw invalidRequest("Invalid status", { field: "status" });
  }
  return { status: normalized };
}

function optionalClientStatus(record: Record<string, unknown>): { status?: ApplicationClientStatus } {
  return optionalApplicationStatus(record);
}

function optionalApplicationType(record: Record<string, unknown>): { applicationType?: ApplicationType } {
  if (record.applicationType === undefined || record.applicationType === null || record.applicationType === "") return {};
  return { applicationType: requiredApplicationType(record.applicationType) };
}

function requiredApplicationType(value: unknown): ApplicationType {
  if (typeof value !== "string" || !APPLICATION_TYPES.includes(value as (typeof APPLICATION_TYPES)[number])) {
    throw invalidRequest("Invalid applicationType", { field: "applicationType" });
  }
  return value as ApplicationType;
}

function optionalReadiness(record: Record<string, unknown>): { readiness?: ApplicationReadinessStatus } {
  if (record.readiness === undefined || record.readiness === null || record.readiness === "") return {};
  if (typeof record.readiness !== "string") throw invalidRequest("Invalid readiness", { field: "readiness" });
  const normalized = record.readiness.trim().toLowerCase();
  if (!["ready", "not_ready", "unknown"].includes(normalized)) {
    throw invalidRequest("Invalid readiness", { field: "readiness" });
  }
  return { readiness: normalized as ApplicationReadinessStatus };
}

function optionalEffectiveStatus(record: Record<string, unknown>): { effectiveStatus?: ApplicationEffectiveStatus } {
  if (record.effectiveStatus === undefined || record.effectiveStatus === null || record.effectiveStatus === "") return {};
  if (typeof record.effectiveStatus !== "string") throw invalidRequest("Invalid effectiveStatus", { field: "effectiveStatus" });
  const normalized = record.effectiveStatus.trim().toLowerCase();
  if (!["active", "disabled", "archived", "purged", "not_ready", "invalid", "unknown"].includes(normalized)) {
    throw invalidRequest("Invalid effectiveStatus", { field: "effectiveStatus" });
  }
  return { effectiveStatus: normalized };
}

function readVersion(value: unknown, field: string): ApplicationVersion {
  if (typeof value === "number" && Number.isSafeInteger(value) && value >= 0) return value;
  if (typeof value === "string") {
    const normalized = value.trim();
    if (normalized.length > 0 && normalized.length <= 128 && !CONTROL_CHARACTERS.test(normalized)) return normalized;
  }
  throw invalidRequest(`Invalid ${field}`, { field });
}

function optionalEndpointUrl(value: unknown): string | undefined {
  if (value === undefined || value === null || value === "") return undefined;
  return validateApplicationEndpointUrl(value);
}

function optionalSecretRef(value: unknown): string | undefined {
  if (value === undefined || value === null || value === "") return undefined;
  return validateApplicationSecretRef(value);
}

function parsePage(
  record: Record<string, unknown>,
  options: ApplicationValidationOptions,
): { limit: number; cursor?: string; offset?: number } {
  const defaultLimit = options.defaultLimit ?? CONTROL_PLANE_DEFAULT_LIMIT;
  const maxLimit = options.maxLimit ?? CONTROL_PLANE_MAX_LIMIT;
  if (!Number.isSafeInteger(defaultLimit) || defaultLimit < 1 || defaultLimit > maxLimit) {
    throw invalidRequest("Invalid page configuration", { field: "defaultLimit" });
  }
  if (!Number.isSafeInteger(maxLimit) || maxLimit < 1) {
    throw invalidRequest("Invalid page configuration", { field: "maxLimit" });
  }
  const limit = readLimit(record.limit ?? record.pageSize, defaultLimit, maxLimit);
  const cursor = readText(record.cursor, "cursor", 1024);
  const page = readInteger(record.page, "page", 1, 100000);
  const explicitOffset = readInteger(record.offset, "offset", 0, 1000000);
  const offset = cursor === undefined
    ? explicitOffset ?? (page === undefined ? undefined : (page - 1) * limit)
    : undefined;
  return {
    limit,
    ...(cursor === undefined ? {} : { cursor }),
    ...(offset === undefined ? {} : { offset }),
  };
}

function readLimit(value: unknown, fallback: number, maxLimit: number): number {
  if (value === undefined || value === null || value === "") return fallback;
  const parsed = typeof value === "number" ? value : parseInteger(value, "limit");
  if (!Number.isSafeInteger(parsed) || parsed < 1 || parsed > maxLimit) {
    throw invalidRequest("Invalid page size", { field: "limit" });
  }
  return parsed;
}

function readInteger(value: unknown, field: string, minimum: number, maximum: number): number | undefined {
  if (value === undefined || value === null || value === "") return undefined;
  const parsed = typeof value === "number" ? value : parseInteger(value, field);
  if (!Number.isSafeInteger(parsed) || parsed < minimum || parsed > maximum) {
    throw invalidRequest(`Invalid ${field}`, { field });
  }
  return parsed;
}

function parseInteger(value: unknown, field: string): number {
  if (typeof value !== "string" || !/^\d+$/u.test(value.trim())) {
    throw invalidRequest(`Invalid ${field}`, { field });
  }
  const parsed = Number(value.trim());
  if (!Number.isSafeInteger(parsed)) throw invalidRequest(`Invalid ${field}`, { field });
  return parsed;
}

function readText(value: unknown, field: string, maxLength: number): string | undefined {
  if (value === undefined || value === null || value === "") return undefined;
  if (typeof value !== "string") throw invalidRequest(`Invalid ${field}`, { field });
  const normalized = value.trim();
  if (normalized.length === 0 || normalized.length > maxLength || CONTROL_CHARACTERS.test(normalized)) {
    throw invalidRequest(`Invalid ${field}`, { field });
  }
  return normalized;
}

function isNativePrivateUseUri(value: string): boolean {
  const separator = value.indexOf(":");
  if (separator <= 0) return false;
  const scheme = value.slice(0, separator);
  if (!/^[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/iu.test(scheme)) return false;
  try {
    const parsed = new URL(value);
    return parsed.hostname === "" && parsed.pathname.startsWith("/") && !value.includes("#") && !value.includes("\\") && !value.includes("?");
  } catch {
    return false;
  }
}

function isApplicationLoopbackHost(hostname: string): boolean {
  return hostname === "localhost" || hostname === "127.0.0.1" || hostname === "[::1]";
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
