import {
  isRfc8252PrivateUseRedirectUri,
  type OidcDynamicClient,
  type OidcDynamicClientStore,
} from "@getbrick/idaas-core";
import {
  APPLICATION_CLIENT_KINDS,
  OIDC_RP_CONSENT_MODES,
  OIDC_RP_PKCE_METHODS,
  OIDC_RP_REDIRECT_URI_POLICIES,
  validateOidcRpClient,
  type ApplicationClientKind,
  type OidcRpClient,
  type OidcRpConsent,
  type OidcRpPkceMethod,
  type OidcRpRedirectUriPolicy,
} from "@getbrick/idaas-contracts";
import {
  isSecretBindingUsable,
  type SecretBindingRepository,
  type SecretBindingResolution,
} from "./secret-binding.js";
import type {
  ApplicationClientRecord,
  ApplicationRecord,
  ApplicationRepository,
} from "./application-types.js";

const OIDC_CLIENT_AUTH_METHODS = new Set(["none", "client_secret_basic", "client_secret_post", "private_key_jwt"]);
const OIDC_CLIENT_AUTH_SIGNING_ALGORITHMS = new Set(["RS256", "PS256", "ES256", "EdDSA"]);

export type ApplicationClientSecretResolver = (
  secretRef: string,
) => string | Promise<string>;

export type ApplicationClientJwksResolver = (
  clientId: string,
  client: ApplicationClientRecord,
) => unknown | Promise<unknown>;

export interface ApplicationOidcClientStoreOptions {
  resolveSecret?: ApplicationClientSecretResolver;
  resolveClientJwks?: ApplicationClientJwksResolver;
  secretBindings?: SecretBindingRepository;
}

export class ApplicationOidcClientStore implements OidcDynamicClientStore {
  private readonly repository: ApplicationRepository;
  private readonly resolveSecret?: ApplicationClientSecretResolver;
  private readonly resolveClientJwks?: ApplicationClientJwksResolver;
  private readonly secretBindings?: SecretBindingRepository;

  constructor(
    repository: ApplicationRepository,
    options: ApplicationOidcClientStoreOptions = {},
  ) {
    this.repository = repository;
    this.resolveSecret = options.resolveSecret;
    this.resolveClientJwks = options.resolveClientJwks;
    this.secretBindings = options.secretBindings;
  }

  async isReady(): Promise<boolean> {
    const readiness = (this.repository as ApplicationRepository & { isReady?: () => boolean | Promise<boolean> }).isReady;
    if (typeof readiness !== "function") return false;
    if (!(await readiness.call(this.repository))) return false;
    if (this.secretBindings !== undefined && !(await this.secretBindings.isReady())) return false;
    return true;
  }

  async find(clientId: string): Promise<OidcDynamicClient | undefined> {
    if (typeof clientId !== "string" || clientId.length === 0 || clientId.length > 512 || /[\u0000-\u001f\u007f]/u.test(clientId)) {
      return undefined;
    }
    const lookup = this.repository.findClientByClientId;
    if (typeof lookup !== "function") return undefined;
    let client: ApplicationClientRecord | undefined;
    try {
      client = await lookup.call(this.repository, clientId);
    } catch {
      throw new Error("[getbrick-idaas] managed OIDC client lookup failed");
    }
    if (!client || !isActiveRecord(client)) return undefined;
    let application: ApplicationRecord | undefined;
    try {
      application = await this.repository.getApplication(client.applicationId);
    } catch {
      throw new Error("[getbrick-idaas] managed OIDC application lookup failed");
    }
    if (!application || !isActiveRecord(application)) return undefined;
    const authMethod = resolveClientAuthMethod(client);
    if (!OIDC_CLIENT_AUTH_METHODS.has(authMethod)) {
      throw new Error("[getbrick-idaas] managed OIDC client auth method is invalid");
    }
    if (authMethod === "none" && hasManagedSecret(client)) {
      throw new Error("[getbrick-idaas] public OIDC clients must not have a secret");
    }
    if (authMethod === "private_key_jwt" && hasManagedSecret(client)) {
      throw new Error("[getbrick-idaas] private_key_jwt clients must not have a client secret");
    }
    if ((authMethod === "none" || authMethod === "private_key_jwt") && this.secretBindings !== undefined) {
      let resolution: SecretBindingResolution | undefined;
      try {
        resolution = await this.secretBindings.resolve("application-client", client.id, "oidc-client-secret");
      } catch {
        throw new Error("[getbrick-idaas] managed OIDC client secret binding is unavailable");
      }
      if (resolution !== undefined) {
        throw new Error(authMethod === "none"
          ? "[getbrick-idaas] public OIDC clients must not have a secret"
          : "[getbrick-idaas] private_key_jwt clients must not have a client secret");
      }
    }
    const configuration = normalizeManagedClientConfiguration(application, client);
    if (client.clientIdScope !== undefined && client.clientIdScope !== "global") {
      throw new Error("[getbrick-idaas] managed OIDC client id scope is invalid");
    }
    if (authMethod === "private_key_jwt" && !OIDC_CLIENT_AUTH_SIGNING_ALGORITHMS.has(client.tokenEndpointAuthSigningAlg ?? "RS256")) {
      throw new Error("[getbrick-idaas] managed OIDC client signing algorithm is invalid");
    }
    const output = {
      client_id: client.clientId,
      application_type: configuration.applicationType,
      client_kind: configuration.clientKind,
      clientKind: configuration.clientKind,
      client_type: configuration.clientKind,
      redirect_uris: [...configuration.redirectUris],
      grant_types: [...configuration.grantTypes],
      response_types: [...configuration.responseTypes],
      scope: configuration.scopes.join(" "),
      token_endpoint_auth_method: authMethod,
      require_pkce: true,
      requirePkce: true,
      pkce_method: "S256",
      pkceMethod: "S256",
      redirect_uri_policy: configuration.redirectUriPolicy,
      redirectUriPolicy: configuration.redirectUriPolicy,
      redirect_policy: configuration.redirectPolicy,
      redirectPolicy: configuration.redirectPolicy,
      consent: configuration.consent,
      consent_required: true,
      consentRequired: true,
      require_explicit_consent: true,
      requireExplicitConsent: true,
      ...(configuration.rpClient === undefined ? {} : { rp_client: configuration.rpClient, rpClient: configuration.rpClient }),
      status: "active",
    } as OidcDynamicClient & Record<string, unknown>;
    const postLogoutRedirectUris = configuration.postLogoutRedirectUris;
    if (postLogoutRedirectUris.length > 0) output.post_logout_redirect_uris = [...postLogoutRedirectUris];
    if (authMethod === "private_key_jwt") {
      output.token_endpoint_auth_signing_alg = client.tokenEndpointAuthSigningAlg ?? "RS256";
      if (client.jwksUri !== undefined && client.jwksUri !== null) output.jwks_uri = client.jwksUri;
      if (output.jwks_uri === undefined && this.resolveClientJwks) {
        try {
          const jwks = await this.resolveClientJwks(client.clientId, client);
          if (jwks !== undefined) output.jwks = jwks;
        } catch {
          throw new Error("[getbrick-idaas] managed OIDC client JWKS is unavailable");
        }
      }
      if (output.jwks === undefined && output.jwks_uri === undefined) {
        throw new Error("[getbrick-idaas] managed OIDC client JWKS is unavailable");
      }
    } else {
      const secret = await this.resolveClientSecret(client);
      if (secret !== undefined) output.client_secret = secret;
    }
    return output;
  }

  private async resolveClientSecret(client: ApplicationClientRecord): Promise<string | undefined> {
    const authMethod = resolveClientAuthMethod(client);
    if (authMethod === "none" || authMethod === "private_key_jwt") return undefined;
    let secretRef = client.secretRef;
    if (this.secretBindings !== undefined) {
      let resolution: SecretBindingResolution | undefined;
      try {
        resolution = await this.secretBindings.resolve("application-client", client.id, "oidc-client-secret");
      } catch {
        throw new Error("[getbrick-idaas] managed OIDC client secret binding is unavailable");
      }
      if (!isUsableSecretResolution(resolution)) {
        throw new Error("[getbrick-idaas] managed OIDC client secret binding is unavailable");
      }
      secretRef = resolution.binding.secretRef;
    } else if (isExplicitlyUnavailableSecret(client)) {
      throw new Error("[getbrick-idaas] managed OIDC client secret binding is unavailable");
    }
    if (typeof secretRef !== "string" || secretRef.length === 0 || secretRef.length > 2048 || /[\u0000-\u001f\u007f]/u.test(secretRef)) {
      throw new Error("[getbrick-idaas] managed OIDC client requires a secret resolver");
    }
    if (!this.resolveSecret) {
      throw new Error("[getbrick-idaas] managed OIDC client secret resolver is not configured");
    }
    let secret: string;
    try {
      secret = await this.resolveSecret(secretRef);
    } catch {
      throw new Error("[getbrick-idaas] managed OIDC client secret is unavailable");
    }
    if (typeof secret !== "string" || secret.length === 0 || secret.length > 4096 || /[\u0000-\u001f\u007f]/u.test(secret)) {
      throw new Error("[getbrick-idaas] managed OIDC client secret is unavailable");
    }
    return secret;
  }
}

interface NormalizedManagedClientConfiguration {
  applicationType: "web" | "native" | "webview";
  clientKind: ApplicationClientKind;
  redirectUris: string[];
  postLogoutRedirectUris: string[];
  grantTypes: string[];
  responseTypes: string[];
  scopes: string[];
  redirectUriPolicy: OidcRpRedirectUriPolicy;
  redirectPolicy: { mode: "exact"; exact: true };
  consent: { required: true; mode: "explicit"; scopes?: string[]; sensitiveScopes?: string[] };
  rpClient?: OidcRpClient;
}

function normalizeManagedClientConfiguration(
  application: ApplicationRecord,
  client: ApplicationClientRecord,
): NormalizedManagedClientConfiguration {
  const applicationRecordType = readApplicationType(application.applicationType);
  const clientApplicationType = readApplicationType(client.applicationType);
  if (clientApplicationType !== undefined && applicationRecordType !== undefined && clientApplicationType !== applicationRecordType) {
    throw new Error("[getbrick-idaas] managed OIDC client application type does not match its application");
  }
  const configuredApplicationType = applicationRecordType ?? clientApplicationType ?? "web";
  let clientKind = resolveClientKind(client, configuredApplicationType);
  if (clientKind === "web" && configuredApplicationType === "native" && client.applicationType === undefined && !hasManagedRpFields(client)) {
    clientKind = "native";
  }
  const applicationType = applicationTypeForKind(clientKind);
  validateClientKindApplicationType(clientKind, configuredApplicationType);
  const rpClient = readManagedRpClient(client);
  if (rpClient !== undefined) {
    if (clientKind !== "web") throw new Error("[getbrick-idaas] managed OIDC RP client kind is invalid");
    if (rpClient.clientId !== client.clientId) throw new Error("[getbrick-idaas] managed OIDC RP client id does not match");
  }
  const redirectUriPolicy = normalizeRedirectPolicy(client);
  const redirectPolicy = normalizeRedirectPolicyDefinition(client);
  const requirePkce = normalizeRequirePkce(client);
  const pkceMethod = normalizePkceMethod(client);
  normalizePkcePolicy(client);
  const consent = normalizeManagedConsent(client);
  const redirectUris = normalizeUriList(
    readAliasValue(client, ["redirectUris", "redirect_uris"], "redirectUris") ?? rpClient?.redirectUris ?? [],
    "redirectUris",
    applicationType,
  );
  const postLogoutRedirectUris = normalizeUriList(
    readAliasValue(client, ["postLogoutRedirectUris", "post_logout_redirect_uris"], "postLogoutRedirectUris") ?? rpClient?.postLogoutRedirectUris ?? [],
    "postLogoutRedirectUris",
    applicationType,
  );
  const grantTypes = normalizeStringList(
    readAliasValue(client, ["grantTypes", "grant_types"], "grantTypes") ?? rpClient?.grantTypes ?? ["authorization_code"],
    "grantTypes",
  );
  const responseTypes = normalizeStringList(
    readAliasValue(client, ["responseTypes", "response_types"], "responseTypes") ?? rpClient?.responseTypes ?? ["code"],
    "responseTypes",
  );
  const scopes = normalizeScopeList(
    readAliasValue(client, ["scopes", "scope"], "scopes") ?? rpClient?.scopes ?? ["openid"],
  );
  if (redirectUris.length === 0) throw new Error("[getbrick-idaas] managed OIDC client requires a redirect URI");
  if (rpClient !== undefined) {
    assertRpMatchesClient(rpClient, client, clientKind, redirectUris, postLogoutRedirectUris, grantTypes, responseTypes, scopes, redirectUriPolicy, redirectPolicy, requirePkce, pkceMethod, consent);
    if (!consent.required || consent.mode !== "explicit") throw new Error("[getbrick-idaas] managed OIDC RP clients require explicit consent");
  }
  if (clientKind === "web" && hasManagedRpFields(client) && (!consent.required || consent.mode !== "explicit")) {
    throw new Error("[getbrick-idaas] managed OIDC RP clients require explicit consent");
  }
  if (new Set(grantTypes).size !== grantTypes.length || grantTypes.some((value) => value !== "authorization_code" && value !== "refresh_token") || !grantTypes.includes("authorization_code")) {
    throw new Error("[getbrick-idaas] managed OIDC client grant types are invalid");
  }
  if (new Set(responseTypes).size !== responseTypes.length || responseTypes.some((value) => value !== "code") || !responseTypes.includes("code")) {
    throw new Error("[getbrick-idaas] managed OIDC client response types are invalid");
  }
  if (!scopes.includes("openid")) throw new Error("[getbrick-idaas] managed OIDC client must include openid");
  return {
    applicationType,
    clientKind,
    redirectUris,
    postLogoutRedirectUris,
    grantTypes,
    responseTypes,
    scopes,
    redirectUriPolicy,
    redirectPolicy,
    consent: {
      required: true,
      mode: "explicit",
      ...(consent.scopes === undefined ? {} : { scopes: [...consent.scopes] }),
      ...(consent.sensitiveScopes === undefined ? {} : { sensitiveScopes: [...consent.sensitiveScopes] }),
    },
    ...(rpClient === undefined ? {} : { rpClient }),
  };
}

function resolveClientKind(client: ApplicationClientRecord, applicationType: "web" | "native" | "webview"): ApplicationClientKind {
  const values: ApplicationClientKind[] = [];
  for (const field of ["clientKind", "client_kind", "clientType", "client_type"]) {
    if (!hasOwn(client, field)) continue;
    const value = client[field];
    if (typeof value !== "string" || !(APPLICATION_CLIENT_KINDS as readonly string[]).includes(value)) {
      throw new Error("[getbrick-idaas] managed OIDC client kind is invalid");
    }
    values.push(value as ApplicationClientKind);
  }
  if (new Set(values).size > 1) throw new Error("[getbrick-idaas] managed OIDC client kind aliases conflict");
  return values[0] ?? (applicationType === "native" ? "native" : applicationType === "webview" ? "webview" : "web");
}

function applicationTypeForKind(kind: ApplicationClientKind): "web" | "native" | "webview" {
  return kind === "native" || kind === "mp_weixin" ? "native" : kind === "webview" ? "webview" : "web";
}

function validateClientKindApplicationType(kind: ApplicationClientKind, applicationType: "web" | "native" | "webview"): void {
  const expected = kind === "native" || kind === "mp_weixin" ? "native" : kind === "webview" ? "webview" : "web";
  if (applicationType !== expected && !(kind === "webview" && applicationType === "web")) {
    throw new Error("[getbrick-idaas] managed OIDC client kind does not match application type");
  }
}

function readApplicationType(value: unknown): "web" | "native" | "webview" | undefined {
  if (value === undefined || value === null) return undefined;
  if (value === "web" || value === "native" || value === "webview") return value;
  throw new Error("[getbrick-idaas] managed OIDC application type is invalid");
}

function readManagedRpClient(client: ApplicationClientRecord): OidcRpClient | undefined {
  const value = readAliasValue(client, ["rpClient", "rp_client"], "rpClient");
  if (value === undefined) return undefined;
  if (!isRecord(value)) throw new Error("[getbrick-idaas] managed OIDC RP client configuration is invalid");
  const allowed = new Set([
    "clientId", "clientType", "clientKind", "redirectUris", "postLogoutRedirectUris", "redirectUriPolicy", "redirectPolicy",
    "requirePkce", "pkceMethod", "pkce", "consent", "consentRequired", "requireExplicitConsent", "grantTypes", "responseTypes", "scopes",
  ]);
  for (const field of Object.keys(value)) {
    if (!allowed.has(field)) throw new Error("[getbrick-idaas] managed OIDC RP client configuration is invalid");
  }
  const candidate = { ...value } as Record<string, unknown>;
  if (candidate.pkce === true) candidate.pkce = { required: true, method: "S256" };
  try {
    return validateOidcRpClient(candidate);
  } catch {
    throw new Error("[getbrick-idaas] managed OIDC RP client configuration is invalid");
  }
}

function assertRpMatchesClient(
  rpClient: OidcRpClient,
  client: ApplicationClientRecord,
  clientKind: ApplicationClientKind,
  redirectUris: string[],
  postLogoutRedirectUris: string[],
  grantTypes: string[],
  responseTypes: string[],
  scopes: string[],
  redirectUriPolicy: OidcRpRedirectUriPolicy,
  redirectPolicy: { mode: "exact"; exact: true },
  requirePkce: boolean,
  pkceMethod: OidcRpPkceMethod,
  consent: { required: boolean; mode: "explicit" | "none"; scopes?: string[]; sensitiveScopes?: string[] },
): void {
  if (rpClient.clientId !== client.clientId || clientKind !== "web" || rpClient.clientKind !== "web" || rpClient.clientType !== "web") {
    throw new Error("[getbrick-idaas] managed OIDC RP client configuration does not match the client");
  }
  if (!sameStringArray(readAliasValue(client, ["redirectUris", "redirect_uris"], "redirectUris") ?? rpClient.redirectUris, rpClient.redirectUris)) {
    throw new Error("[getbrick-idaas] managed OIDC RP redirect URIs do not match");
  }
  if (hasAny(client, ["postLogoutRedirectUris", "post_logout_redirect_uris"]) && !sameStringArray(readAliasValue(client, ["postLogoutRedirectUris", "post_logout_redirect_uris"], "postLogoutRedirectUris") ?? [], rpClient.postLogoutRedirectUris ?? [])) {
    throw new Error("[getbrick-idaas] managed OIDC RP post-logout redirect URIs do not match");
  }
  if (hasAny(client, ["grantTypes", "grant_types"]) && !sameStringArray(grantTypes, rpClient.grantTypes ?? ["authorization_code"])) {
    throw new Error("[getbrick-idaas] managed OIDC RP grant types do not match");
  }
  if (hasAny(client, ["responseTypes", "response_types"]) && !sameStringArray(responseTypes, rpClient.responseTypes ?? ["code"])) {
    throw new Error("[getbrick-idaas] managed OIDC RP response types do not match");
  }
  if (hasAny(client, ["scopes", "scope"]) && !sameStringArray(scopes, rpClient.scopes ?? ["openid"])) {
    throw new Error("[getbrick-idaas] managed OIDC RP scopes do not match");
  }
  if (hasAny(client, ["redirectUriPolicy", "redirect_uri_policy"]) && redirectUriPolicy !== rpClient.redirectUriPolicy) {
    throw new Error("[getbrick-idaas] managed OIDC RP redirect policy does not match");
  }
  if (hasAny(client, ["redirectPolicy", "redirect_policy"]) && (redirectPolicy.mode !== rpClient.redirectPolicy?.mode || redirectPolicy.exact !== rpClient.redirectPolicy?.exact)) {
    throw new Error("[getbrick-idaas] managed OIDC RP redirect policy does not match");
  }
  if (hasAny(client, ["requirePkce", "require_pkce"]) && requirePkce !== rpClient.requirePkce) {
    throw new Error("[getbrick-idaas] managed OIDC RP PKCE policy does not match");
  }
  if (hasAny(client, ["pkceMethod", "pkce_method"]) && pkceMethod !== rpClient.pkceMethod) {
    throw new Error("[getbrick-idaas] managed OIDC RP PKCE method does not match");
  }
  if (hasAny(client, ["consent", "consent_required", "require_explicit_consent"]) && (!consent.required || consent.mode !== "explicit")) {
    throw new Error("[getbrick-idaas] managed OIDC RP consent policy is invalid");
  }
}

function normalizeRedirectPolicy(client: ApplicationClientRecord): OidcRpRedirectUriPolicy {
  const value = readAliasValue(client, ["redirectUriPolicy", "redirect_uri_policy"], "redirectUriPolicy") ?? "exact";
  if (typeof value !== "string" || !(OIDC_RP_REDIRECT_URI_POLICIES as readonly string[]).includes(value)) {
    throw new Error("[getbrick-idaas] managed OIDC RP redirect policy is invalid");
  }
  return value as OidcRpRedirectUriPolicy;
}

function normalizeRedirectPolicyDefinition(client: ApplicationClientRecord): { mode: "exact"; exact: true } {
  const value = readAliasValue(client, ["redirectPolicy", "redirect_policy"], "redirectPolicy") ?? { mode: "exact", exact: true };
  if (!isRecord(value) || Object.keys(value).some((field) => field !== "mode" && field !== "exact") || value.mode !== "exact" || value.exact !== true) {
    throw new Error("[getbrick-idaas] managed OIDC RP redirect policy is invalid");
  }
  return { mode: "exact", exact: true };
}

function normalizeRequirePkce(client: ApplicationClientRecord): boolean {
  const value = readAliasValue(client, ["requirePkce", "require_pkce"], "requirePkce") ?? true;
  if (typeof value !== "boolean" || value !== true) throw new Error("[getbrick-idaas] managed OIDC clients require PKCE");
  return true;
}

function normalizePkceMethod(client: ApplicationClientRecord): OidcRpPkceMethod {
  const method = readAliasValue(client, ["pkceMethod", "pkce_method"], "pkceMethod") ?? "S256";
  if (typeof method !== "string" || !(OIDC_RP_PKCE_METHODS as readonly string[]).includes(method)) {
    throw new Error("[getbrick-idaas] managed OIDC RP clients require S256 PKCE");
  }
  return method as OidcRpPkceMethod;
}

function normalizePkcePolicy(client: ApplicationClientRecord): void {
  const value = readAliasValue(client, ["pkce"], "pkce");
  if (value === undefined) return;
  if (value === true) return;
  if (!isRecord(value) || Object.keys(value).some((field) => field !== "required" && field !== "method") || value.required !== true || (value.method !== undefined && value.method !== "S256")) {
    throw new Error("[getbrick-idaas] managed OIDC RP clients require S256 PKCE");
  }
}

function normalizeManagedConsent(client: ApplicationClientRecord): { required: boolean; mode: "explicit" | "none"; scopes?: string[]; sensitiveScopes?: string[] } {
  const raw = readAliasValue(client, ["consent"], "consent");
  const required = readAliasValue(client, ["consentRequired", "consent_required"], "consentRequired");
  const explicit = readAliasValue(client, ["requireExplicitConsent", "require_explicit_consent"], "requireExplicitConsent");
  if (required !== undefined && typeof required !== "boolean") throw new Error("[getbrick-idaas] managed OIDC consent policy is invalid");
  if (explicit !== undefined && typeof explicit !== "boolean") throw new Error("[getbrick-idaas] managed OIDC consent policy is invalid");
  if (required !== undefined && explicit !== undefined && required !== explicit) throw new Error("[getbrick-idaas] managed OIDC consent aliases conflict");
  if (raw !== undefined && typeof raw !== "string" && !isRecord(raw)) throw new Error("[getbrick-idaas] managed OIDC consent policy is invalid");
  if (raw === "implicit" || raw === "auto") throw new Error("[getbrick-idaas] managed OIDC consent policy is invalid");
  let normalized: { required: boolean; mode: "explicit" | "none"; scopes?: string[]; sensitiveScopes?: string[] };
  if (raw === "explicit" || raw === "none") {
    normalized = { required: raw === "explicit", mode: raw };
  } else if (isRecord(raw)) {
    for (const field of Object.keys(raw)) {
      if (!["required", "mode", "scopes", "sensitiveScopes", "requireExplicitConsent"].includes(field)) throw new Error("[getbrick-idaas] managed OIDC consent policy is invalid");
    }
    const requiredValue = raw.required ?? raw.requireExplicitConsent;
    if (typeof requiredValue !== "boolean") throw new Error("[getbrick-idaas] managed OIDC consent policy is invalid");
    const mode = raw.mode ?? (requiredValue ? "explicit" : "none");
    if (typeof mode !== "string" || !(OIDC_RP_CONSENT_MODES as readonly string[]).includes(mode)) throw new Error("[getbrick-idaas] managed OIDC consent policy is invalid");
    if ((mode === "explicit" && requiredValue !== true) || (mode === "none" && requiredValue !== false)) throw new Error("[getbrick-idaas] managed OIDC consent policy is invalid");
    if (raw.requireExplicitConsent !== undefined && raw.requireExplicitConsent !== requiredValue) throw new Error("[getbrick-idaas] managed OIDC consent policy is invalid");
    const scopes = raw.scopes === undefined ? undefined : normalizeConsentScopeList(raw.scopes);
    const sensitiveScopes = raw.sensitiveScopes === undefined ? undefined : normalizeConsentScopeList(raw.sensitiveScopes);
    normalized = { required: requiredValue, mode: mode as "explicit" | "none", ...(scopes === undefined ? {} : { scopes }), ...(sensitiveScopes === undefined ? {} : { sensitiveScopes }) };
  } else {
    const fallback = required ?? explicit;
    normalized = fallback === undefined ? { required: true, mode: "explicit" } : { required: fallback, mode: fallback ? "explicit" : "none" };
  }
  if (required !== undefined && required !== normalized.required) throw new Error("[getbrick-idaas] managed OIDC consent policy aliases conflict");
  if (explicit !== undefined && explicit !== normalized.required) throw new Error("[getbrick-idaas] managed OIDC consent policy aliases conflict");
  return normalized;
}

function normalizeUriList(value: unknown, field: string, applicationType: "web" | "native" | "webview"): string[] {
  if (!Array.isArray(value) || value.length > 100) throw new Error(`[getbrick-idaas] managed OIDC ${field} are invalid`);
  const output: string[] = [];
  for (const item of value) {
    if (typeof item !== "string" || item.length === 0 || item.length > 2048 || item !== item.trim() || /[\u0000-\u001f\u007f\s]/u.test(item)) throw new Error(`[getbrick-idaas] managed OIDC ${field} are invalid`);
    if (applicationType === "native" && isRfc8252PrivateUseRedirectUri(item)) {
      if (output.includes(item)) throw new Error(`[getbrick-idaas] managed OIDC ${field} contain duplicates`);
      output.push(item);
      continue;
    }
    try {
      const parsed = new URL(item);
      if ((parsed.protocol !== "https:" && parsed.protocol !== "http:") || parsed.username !== "" || parsed.password !== "" || parsed.hash !== "" || parsed.hostname === "") throw new Error();
    } catch {
      throw new Error(`[getbrick-idaas] managed OIDC ${field} are invalid`);
    }
    if (output.includes(item)) throw new Error(`[getbrick-idaas] managed OIDC ${field} contain duplicates`);
    output.push(item);
  }
  return output;
}

function normalizeStringList(value: unknown, field: string): string[] {
  if (!Array.isArray(value) || value.length > 100) throw new Error(`[getbrick-idaas] managed OIDC ${field} are invalid`);
  const output: string[] = [];
  for (const item of value) {
    if (typeof item !== "string" || item.length === 0 || item.length > 512 || item !== item.trim() || /[\u0000-\u001f\u007f\s]/u.test(item) || output.includes(item)) throw new Error(`[getbrick-idaas] managed OIDC ${field} are invalid`);
    output.push(item);
  }
  return output;
}

function normalizeScopeList(value: unknown): string[] {
  if (typeof value === "string") return normalizeStringList(value.split(/\s+/u).filter((item) => item.length > 0), "scopes");
  return normalizeStringList(value, "scopes");
}

function normalizeConsentScopeList(value: unknown): string[] {
  if (!Array.isArray(value)) throw new Error("[getbrick-idaas] managed OIDC consent scopes are invalid");
  return normalizeStringList(value, "consent scopes");
}

function readAliasValue(record: Record<string, unknown>, fields: readonly string[], field: string): unknown {
  let selected: unknown;
  let selectedField: string | undefined;
  for (const candidate of fields) {
    if (!hasOwn(record, candidate)) continue;
    const value = record[candidate];
    if (value === null) throw new Error(`[getbrick-idaas] managed OIDC ${field} is invalid`);
    if (selectedField !== undefined && !sameMetadataValue(selected, value)) throw new Error(`[getbrick-idaas] managed OIDC ${field} aliases conflict`);
    selected = value;
    selectedField = candidate;
  }
  return selected;
}

function hasAny(record: Record<string, unknown>, fields: readonly string[]): boolean {
  return fields.some((field) => hasOwn(record, field));
}

function hasManagedRpFields(client: ApplicationClientRecord): boolean {
  return hasAny(client, ["rpClient", "rp_client", "redirectUriPolicy", "redirect_uri_policy", "redirectPolicy", "redirect_policy", "pkce", "pkceMethod", "pkce_method", "consent", "consentRequired", "consent_required", "requireExplicitConsent", "require_explicit_consent"]);
}

function hasManagedSecret(client: ApplicationClientRecord): boolean {
  return (typeof client.secretRef === "string" && client.secretRef.trim().length > 0) ||
    client.hasSecret === true ||
    ["configured", "active", "retiring"].includes(client.secretStatus ?? "") ||
    typeof client.client_secret === "string" ||
    typeof client.clientSecret === "string";
}

function sameStringArray(left: unknown, right: unknown): boolean {
  if (!Array.isArray(left) || !Array.isArray(right) || left.length !== right.length) return false;
  return left.every((value, index) => value === right[index]);
}

function sameMetadataValue(left: unknown, right: unknown): boolean {
  if (left === right) return true;
  if (Array.isArray(left) && Array.isArray(right)) return left.length === right.length && left.every((item, index) => item === right[index]);
  if (isRecord(left) && isRecord(right)) {
    const leftKeys = Object.keys(left).sort();
    const rightKeys = Object.keys(right).sort();
    return leftKeys.length === rightKeys.length && leftKeys.every((key, index) => key === rightKeys[index] && sameMetadataValue(left[key], right[key]));
  }
  return false;
}

function hasOwn(record: Record<string, unknown>, field: string): boolean {
  return Object.prototype.hasOwnProperty.call(record, field);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isActiveRecord(record: { status?: unknown; lifecycleStatus?: unknown; effectiveStatus?: unknown }): boolean {
  if (record.status !== undefined && record.status !== "active") return false;
  if (record.lifecycleStatus !== undefined && record.lifecycleStatus !== "active") return false;
  if (record.effectiveStatus === null) return false;
  if (record.effectiveStatus !== undefined && record.effectiveStatus !== "active" && record.effectiveStatus !== "not_ready") return false;
  return true;
}

function resolveClientAuthMethod(client: ApplicationClientRecord): string {
  if (client.tokenEndpointAuthMethod !== undefined && client.tokenEndpointAuthMethod !== null) {
    return client.tokenEndpointAuthMethod;
  }
  if (
    client.secretRef !== undefined && client.secretRef !== null ||
    client.hasSecret === true ||
    client.secretStatus === "configured" ||
    client.secretStatus === "active" ||
    client.secretStatus === "retiring"
  ) {
    return "client_secret_basic";
  }
  return "private_key_jwt";
}

function isExplicitlyUnavailableSecret(client: ApplicationClientRecord): boolean {
  return client.hasSecret === false ||
    client.secretStatus === "revoked" ||
    client.secretStatus === "expired" ||
    client.secretStatus === "missing" ||
    client.secretStatus === "not_configured" ||
    client.secretStatus === "rotating" ||
    client.secretStatus === "unknown";
}

function isUsableSecretResolution(value: SecretBindingResolution | undefined): value is SecretBindingResolution {
  if (value === undefined || !value.binding || typeof value.binding !== "object") return false;
  if (
    !Number.isSafeInteger(value.binding.gracePeriodSeconds) ||
    value.binding.gracePeriodSeconds < 0
  ) return false;
  try {
    return isSecretBindingUsable(value.binding);
  } catch {
    return false;
  }
}

export function createApplicationOidcClientStore(
  repository: ApplicationRepository,
  options: ApplicationOidcClientStoreOptions = {},
): ApplicationOidcClientStore {
  return new ApplicationOidcClientStore(repository, options);
}
