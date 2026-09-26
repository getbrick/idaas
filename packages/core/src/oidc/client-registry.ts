import { createPublicKey, type JsonWebKey as NodeJsonWebKey } from "node:crypto";
import { lookup as dnsLookup } from "node:dns/promises";
import { request as httpsRequest, type RequestOptions } from "node:https";
import { isIP, type LookupFunction } from "node:net";
import type { IncomingMessage } from "node:http";
import type { Adapter, AdapterFactory, AdapterPayload } from "oidc-provider";
import { isSafeOidcUrl } from "./config.js";
import {
  type OidcClientJwksInput,
  type OidcClientJwksResolver,
} from "./client-jwks.js";
import {
  assertOidcClientRedirectPolicy,
  type OidcApplicationType,
  type OidcRedirectPolicyOptions,
} from "./redirect-policy.js";

export const OIDC_REDIRECT_POLICY_METADATA = "getbrick:redirect_policy";
export const OIDC_REQUIRE_PKCE_METADATA = "getbrick:require_pkce";
export const OIDC_CLIENT_KIND_METADATA = "getbrick:client_kind";

export const OIDC_CLIENT_AUTH_SIGNING_ALGORITHMS = ["RS256", "PS256", "ES256", "EdDSA"] as const;
export const OIDC_SIGNING_ALGORITHMS = OIDC_CLIENT_AUTH_SIGNING_ALGORITHMS;
export type OidcDynamicClientSigningAlgorithm = (typeof OIDC_CLIENT_AUTH_SIGNING_ALGORITHMS)[number];
export const OIDC_CLIENT_AUTH_SIGNING_KEY_TYPES = {
  RS256: "RSA",
  PS256: "RSA",
  ES256: "EC",
  EdDSA: "OKP",
} as const;
export const OIDC_SIGNING_KEY_TYPES = OIDC_CLIENT_AUTH_SIGNING_KEY_TYPES;
export type OidcClientAuthSigningKeyType =
  (typeof OIDC_CLIENT_AUTH_SIGNING_KEY_TYPES)[OidcDynamicClientSigningAlgorithm];
export const OIDC_DEFAULT_CLIENT_AUTH_METHOD = "private_key_jwt" as const;
export const OIDC_DEFAULT_CLIENT_AUTH_SIGNING_ALGORITHM = "RS256" as const;
export const DEFAULT_OIDC_CLIENT_AUTH_METHOD = OIDC_DEFAULT_CLIENT_AUTH_METHOD;
export const DEFAULT_OIDC_CLIENT_AUTH_SIGNING_ALGORITHM = OIDC_DEFAULT_CLIENT_AUTH_SIGNING_ALGORITHM;

export type OidcClientRegistryProfile = "development" | "test" | "staging" | "production";

export interface OidcRemoteJwksPolicy {
  profile?: OidcClientRegistryProfile;
  allowRemoteJwksUri?: boolean;
  trustedJwksOrigins?: readonly string[];
  trustedJwksHosts?: readonly string[];
}

export interface OidcDynamicClientAdapterFactory extends AdapterFactory {
  ready?: () => Promise<boolean>;
  resolveRemoteJwks?: (clientId: string) => Promise<void>;
}

const REMOTE_JWKS_TIMEOUT_MS = 2_500;
const REMOTE_JWKS_MAX_BYTES = 262_144;
const REMOTE_JWKS_MAX_ALLOWLIST_ENTRIES = 128;
const TOKEN_ENDPOINT_AUTH_METHODS = new Set<string>([
  "none",
  "client_secret_basic",
  "client_secret_post",
  OIDC_DEFAULT_CLIENT_AUTH_METHOD,
]);
const CLIENT_AUTH_SIGNING_ALGORITHMS = new Set<string>(OIDC_CLIENT_AUTH_SIGNING_ALGORITHMS);

export type OidcDynamicClientAuthMethod =
  | "none"
  | "client_secret_basic"
  | "client_secret_post"
  | "private_key_jwt";

export interface OidcDynamicClient {
  client_id: string;
  clientIdScope?: "global";
  client_secret?: string;
  client_name?: string;
  application_type?: OidcApplicationType;
  applicationType?: OidcApplicationType;
  client_kind?: "web" | "native" | "mp_weixin" | "webview";
  clientKind?: "web" | "native" | "mp_weixin" | "webview";
  redirect_uris: string[];
  post_logout_redirect_uris?: string[];
  jwks?: unknown;
  clientJwks?: unknown;
  jwks_uri?: string;
  jwksUri?: string;
  grant_types: string[];
  response_types: string[];
  scope: string;
  token_endpoint_auth_method?: string;
  tokenEndpointAuthMethod?: string;
  token_endpoint_auth_signing_alg?: string;
  tokenEndpointAuthSigningAlg?: string;
  id_token_signed_response_alg?: string;
  idTokenSignedResponseAlg?: string;
  require_pkce?: boolean;
  requirePkce?: boolean;
  status?: "active" | "disabled";
}

export interface OidcDynamicClientStore {
  find(clientId: string): Promise<OidcDynamicClient | undefined>;
  findJwks?: OidcClientJwksResolver;
  isReady?(): boolean | Promise<boolean>;
  validate?(): boolean | Promise<boolean>;
}

export interface OidcDynamicClientAdapterOptions extends OidcRemoteJwksPolicy {
  clientJwks?: Record<string, OidcClientJwksInput>;
  resolveClientJwks?: OidcClientJwksResolver;
  allowInsecureHttp?: boolean;
  idTokenSignedResponseAlg?: OidcDynamicClientSigningAlgorithm;
  staticClientIds?: ReadonlySet<string> | readonly string[];
  staticClients?: readonly OidcDynamicClient[];
  requireApplicationType?: boolean;
}

export interface OidcDynamicClientNormalizationOptions extends OidcRemoteJwksPolicy {
  clientJwks?: unknown;
  allowInsecureHttp?: boolean;
  idTokenSignedResponseAlg?: OidcDynamicClientSigningAlgorithm;
  requireApplicationType?: boolean;
  allowMissingJwks?: boolean;
}

export function createDynamicOidcClientAdapter(
  baseAdapter: AdapterFactory,
  store: OidcDynamicClientStore,
  options: OidcDynamicClientAdapterOptions = {},
): OidcDynamicClientAdapterFactory {
  if (typeof baseAdapter !== "function") {
    throw new Error("[getbrick-idaas] dynamic OIDC clients require a base adapter factory");
  }
  if (!store || typeof store.find !== "function") {
    throw new Error("[getbrick-idaas] dynamic OIDC clients require a client store");
  }
  assertOidcRemoteJwksPolicy(options);
  const strictRemoteJwks = usesStrictRemoteJwksPolicy(options);
  const staticClientIds = new Set<string>();
  for (const clientId of options.staticClientIds ?? []) {
    const normalized = normalizeText(clientId, 512);
    if (normalized === undefined) throw new Error("[getbrick-idaas] static OIDC client id is invalid");
    staticClientIds.add(normalized);
  }
  const staticClients = new Map<string, OidcDynamicClient>();
  const staticRemoteJwks = new Map<string, string>();
  for (const client of options.staticClients ?? []) {
    const clientId = normalizeText(client?.client_id, 512);
    if (clientId === undefined || staticClients.has(clientId)) {
      throw new Error("[getbrick-idaas] static OIDC client metadata is invalid");
    }
    staticClients.set(clientId, client);
    staticClientIds.add(clientId);
    const jwksUri = readAlias(client.jwks_uri, client.jwksUri);
    if (strictRemoteJwks && jwksUri !== undefined) {
      staticRemoteJwks.set(
        clientId,
        normalizeOidcJwksUri(jwksUri, false, options),
      );
    }
  }
  const remoteJwksCache = new Map<string, { expiresAt: number; value: Promise<Record<string, unknown>> }>();
  const payloadOptions = (
    clientJwks: unknown,
    allowMissingJwks?: boolean,
  ): OidcDynamicClientNormalizationOptions => ({
    clientJwks,
    allowInsecureHttp: strictRemoteJwks ? false : options.allowInsecureHttp,
    idTokenSignedResponseAlg: options.idTokenSignedResponseAlg,
    requireApplicationType: options.requireApplicationType,
    allowMissingJwks,
    profile: options.profile,
    allowRemoteJwksUri: options.allowRemoteJwksUri,
    trustedJwksOrigins: options.trustedJwksOrigins,
    trustedJwksHosts: options.trustedJwksHosts,
  });
  const validateRemoteClient = (
    client: OidcDynamicClient,
    clientId: string,
    configuredJwks: unknown,
  ): AdapterPayload => toDynamicOidcClientPayload(client, clientId, payloadOptions(configuredJwks, true));
  const resolveRemoteJwks = async (
    clientId: string,
    client: OidcDynamicClient,
    configuredJwks: unknown,
  ): Promise<Record<string, unknown>> => {
    const jwksUri = readAlias(client.jwks_uri, client.jwksUri);
    if (jwksUri === undefined) {
      throw new Error("[getbrick-idaas] dynamic OIDC client jwks_uri is invalid");
    }
    const normalizedUri = normalizeOidcJwksUri(jwksUri, false, options);
    const validated = validateRemoteClient(client, clientId, configuredJwks);
    const algorithm = normalizeSigningAlgorithm(
      validated.token_endpoint_auth_signing_alg ?? OIDC_DEFAULT_CLIENT_AUTH_SIGNING_ALGORITHM,
    );
    const cached = remoteJwksCache.get(normalizedUri);
    if (cached !== undefined && cached.expiresAt > Date.now()) return cached.value;
    const value = requestRemoteOidcJwks(normalizedUri, options)
      .then((jwks) => projectOidcClientJwks(jwks, algorithm))
      .catch(() => {
        remoteJwksCache.delete(normalizedUri);
        throw new Error("[getbrick-idaas] managed OIDC client JWKS is unavailable");
      });
    remoteJwksCache.set(normalizedUri, { expiresAt: Date.now() + 60_000, value });
    return value;
  };
  const projectClient = async (
    client: OidcDynamicClient,
    clientId: string,
    configuredJwks: unknown,
  ): Promise<AdapterPayload> => {
    const jwksUri = readAlias(client.jwks_uri, client.jwksUri);
    if (!strictRemoteJwks || jwksUri === undefined) {
      return toDynamicOidcClientPayload(client, clientId, payloadOptions(configuredJwks));
    }
    validateRemoteClient(client, clientId, configuredJwks);
    const remoteJwks = await resolveRemoteJwks(clientId, client, configuredJwks);
    return toDynamicOidcClientPayload(withoutJwksUri(client), clientId, payloadOptions(remoteJwks));
  };
  const dynamicAdapter = ((model: string): Adapter => {
    const adapter = baseAdapter(model);
    if (model !== "Client") return adapter;
    const delegated = Object.create(adapter) as Adapter;
    Object.defineProperty(delegated, "find", {
      configurable: true,
      enumerable: true,
      value: async (id: string): Promise<AdapterPayload | undefined> => {
        const normalizedId = normalizeText(id, 512);
        if (normalizedId === undefined) return undefined;
        if (staticClientIds.has(normalizedId)) {
          const staticClient = staticClients.get(normalizedId);
          if (staticClient === undefined || (staticClient.status !== undefined && staticClient.status !== "active")) return undefined;
          return projectClient(staticClient, normalizedId, options.clientJwks?.[normalizedId]);
        }
        let client: OidcDynamicClient | undefined;
        try {
          client = await store.find(normalizedId);
        } catch {
          throw new Error("[getbrick-idaas] managed OIDC client lookup failed");
        }
        if (!client || client.status === "disabled") return undefined;
        let clientJwks = options.clientJwks?.[normalizedId] ?? client.jwks ?? client.clientJwks;
        const authMethod = readAlias(
          client.token_endpoint_auth_method,
          client.tokenEndpointAuthMethod,
        );
        const normalizedAuthMethod = authMethod ?? OIDC_DEFAULT_CLIENT_AUTH_METHOD;
        const signingAlgorithm = readAlias(
          client.token_endpoint_auth_signing_alg,
          client.tokenEndpointAuthSigningAlg,
        );
        const jwksUri = readAlias(client.jwks_uri, client.jwksUri);
        if (clientJwks === undefined && normalizedAuthMethod === OIDC_DEFAULT_CLIENT_AUTH_METHOD && jwksUri === undefined) {
          toDynamicOidcClientPayload(client, normalizedId, payloadOptions(clientJwks, true));
          clientJwks = await resolveJwks(
            normalizedId,
            options,
            store,
            normalizeSigningAlgorithm(signingAlgorithm ?? OIDC_DEFAULT_CLIENT_AUTH_SIGNING_ALGORITHM),
          );
        }
        return projectClient(client, normalizedId, clientJwks);
      },
      writable: true,
    });
    return delegated;
  }) as OidcDynamicClientAdapterFactory;
  if (staticRemoteJwks.size > 0) {
    Object.defineProperty(dynamicAdapter, "resolveRemoteJwks", {
      configurable: true,
      enumerable: false,
      value: async (clientId: string): Promise<void> => {
        const normalizedId = normalizeText(clientId, 512);
        if (normalizedId === undefined || !staticRemoteJwks.has(normalizedId)) {
          throw new Error("[getbrick-idaas] static OIDC client JWKS is unavailable");
        }
        const client = staticClients.get(normalizedId);
        if (client === undefined) throw new Error("[getbrick-idaas] static OIDC client JWKS is unavailable");
        await resolveRemoteJwks(normalizedId, client, options.clientJwks?.[normalizedId]);
      },
      writable: false,
    });
  }
  const baseReadiness = (baseAdapter as AdapterFactory & { ready?: () => boolean | Promise<boolean> }).ready;
  if (typeof baseReadiness === "function" || typeof store.isReady === "function" || typeof store.validate === "function") {
    Object.defineProperty(dynamicAdapter, "ready", {
      configurable: true,
      enumerable: true,
      value: async () => {
        if (typeof baseReadiness === "function") {
          try {
            if ((await baseReadiness.call(baseAdapter)) !== true) return false;
          } catch {
            return false;
          }
        }
        if (typeof store.isReady === "function") {
          try {
            if ((await store.isReady()) !== true) return false;
          } catch {
            return false;
          }
        }
        if (typeof store.validate === "function") {
          try {
            if ((await store.validate()) !== true) return false;
          } catch {
            return false;
          }
        }
        return true;
      },
      writable: false,
    });
  }
  return dynamicAdapter;
}

export function toDynamicOidcClientPayload(
  client: OidcDynamicClient,
  expectedClientId?: string,
  options: OidcDynamicClientNormalizationOptions = {},
): AdapterPayload {
  if (!client || typeof client !== "object") {
    throw new Error("[getbrick-idaas] dynamic OIDC client is invalid");
  }
  if (client.status !== undefined && client.status !== "active" && client.status !== "disabled") {
    throw new Error("[getbrick-idaas] dynamic OIDC client status is invalid");
  }
  const clientId = normalizeText(client.client_id, 512);
  if (clientId === undefined || (expectedClientId !== undefined && clientId !== expectedClientId)) {
    throw new Error("[getbrick-idaas] dynamic OIDC client id is invalid");
  }
  if (client.clientIdScope !== undefined && client.clientIdScope !== "global") {
    throw new Error("[getbrick-idaas] dynamic OIDC client id scope is invalid");
  }
  const applicationTypeValue = readAlias(client.application_type, client.applicationType);
  const clientKindValue = readAlias(client.client_kind, client.clientKind);
  if (
    applicationTypeValue !== undefined &&
    applicationTypeValue !== "web" &&
    applicationTypeValue !== "native" &&
    applicationTypeValue !== "webview"
  ) {
    throw new Error("[getbrick-idaas] dynamic OIDC client application type is invalid");
  }
  if (
    clientKindValue !== undefined &&
    clientKindValue !== "web" &&
    clientKindValue !== "native" &&
    clientKindValue !== "mp_weixin" &&
    clientKindValue !== "webview"
  ) {
    throw new Error("[getbrick-idaas] dynamic OIDC client kind is invalid");
  }
  const kindApplicationType = clientKindValue === "native" || clientKindValue === "mp_weixin"
    ? "native"
    : clientKindValue === "webview"
      ? "webview"
      : clientKindValue === "web"
        ? "web"
        : undefined;
  if (
    applicationTypeValue !== undefined &&
    kindApplicationType !== undefined &&
    applicationTypeValue !== kindApplicationType &&
    !(clientKindValue === "webview" && applicationTypeValue === "web")
  ) {
    throw new Error("[getbrick-idaas] dynamic OIDC client kind does not match application type");
  }
  if (options.requireApplicationType === true && applicationTypeValue === undefined) {
    throw new Error("[getbrick-idaas] managed OIDC client application type is required");
  }
  const applicationType = (applicationTypeValue ?? kindApplicationType ?? "web") as OidcApplicationType;
  const requirePkce = readBooleanAlias(client.require_pkce, client.requirePkce) ?? true;
  if (!requirePkce) {
    throw new Error("[getbrick-idaas] managed OIDC clients require PKCE");
  }
  const authMethodValue = readAlias(
    client.token_endpoint_auth_method,
    client.tokenEndpointAuthMethod,
  );
  const tokenEndpointAuthMethod = authMethodValue ?? OIDC_DEFAULT_CLIENT_AUTH_METHOD;
  if (typeof tokenEndpointAuthMethod !== "string" || !TOKEN_ENDPOINT_AUTH_METHODS.has(tokenEndpointAuthMethod)) {
    throw new Error("[getbrick-idaas] dynamic OIDC client auth method is invalid");
  }
  const configuredSigningAlgorithm = readAlias(
    client.token_endpoint_auth_signing_alg,
    client.tokenEndpointAuthSigningAlg,
  );
  if (tokenEndpointAuthMethod !== "private_key_jwt" && configuredSigningAlgorithm !== undefined) {
    throw new Error("[getbrick-idaas] asymmetric client authentication fields require private_key_jwt");
  }
  const tokenEndpointAuthSigningAlg = tokenEndpointAuthMethod === "private_key_jwt"
    ? normalizeSigningAlgorithm(configuredSigningAlgorithm ?? OIDC_DEFAULT_CLIENT_AUTH_SIGNING_ALGORITHM)
    : undefined;
  const redirectUris = normalizeUriArray(
    client.redirect_uris,
    100,
    {
      applicationType,
      tokenEndpointAuthMethod,
      requirePkce,
    },
    options.allowInsecureHttp,
  );
  if (redirectUris.length === 0) {
    throw new Error("[getbrick-idaas] dynamic OIDC client requires a redirect URI");
  }
  const postLogoutRedirectUris = normalizeUriArray(
    client.post_logout_redirect_uris,
    100,
    {
      applicationType,
      tokenEndpointAuthMethod,
      requirePkce,
    },
    options.allowInsecureHttp,
  );
  assertOidcClientRedirectPolicy({
    applicationType,
    tokenEndpointAuthMethod,
    requirePkce,
    redirectUris,
    postLogoutRedirectUris,
  }, { allowInsecureHttp: options.allowInsecureHttp });
  if (tokenEndpointAuthMethod === "none" && client.client_secret !== undefined) {
    throw new Error("[getbrick-idaas] public dynamic OIDC client must not have a secret");
  }
  if (tokenEndpointAuthMethod === "private_key_jwt" && client.client_secret !== undefined) {
    if (normalizeText(client.client_secret, 4096) === undefined) {
      throw new Error("[getbrick-idaas] private_key_jwt dynamic OIDC client secret is invalid");
    }
  }
  if (tokenEndpointAuthMethod !== "none" && tokenEndpointAuthMethod !== "private_key_jwt") {
    if (client.client_secret === undefined) {
      throw new Error("[getbrick-idaas] confidential dynamic OIDC client requires a secret");
    }
    const secret = normalizeText(client.client_secret, 4096);
    if (secret === undefined) throw new Error("[getbrick-idaas] dynamic OIDC client secret is invalid");
  }
  const grantTypes = normalizeArray(client.grant_types, 128, 32);
  const responseTypes = normalizeArray(client.response_types, 128, 32);
  if (
    !grantTypes.includes("authorization_code") ||
    grantTypes.some((grantType) => grantType !== "authorization_code" && grantType !== "refresh_token") ||
    !responseTypes.includes("code") ||
    responseTypes.some((responseType) => responseType !== "code")
  ) {
    throw new Error("[getbrick-idaas] dynamic OIDC client must support authorization code flow");
  }
  const scope = normalizeScope(client.scope);
  if (!scope.split(" ").includes("openid")) {
    throw new Error("[getbrick-idaas] dynamic OIDC client must include the openid scope");
  }
  const jwksUri = readAlias(client.jwks_uri, client.jwksUri);
  const normalizedJwksUri = jwksUri === undefined
    ? undefined
    : normalizeOidcJwksUri(jwksUri, options.allowInsecureHttp, options);
  const clientJwksSource = readAlias(client.jwks, client.clientJwks);
  const jwksSource = options.clientJwks ?? clientJwksSource;
  if (tokenEndpointAuthMethod !== "private_key_jwt" && (jwksSource !== undefined || normalizedJwksUri !== undefined)) {
    throw new Error("[getbrick-idaas] asymmetric client authentication fields require private_key_jwt");
  }
  if (jwksSource !== undefined && normalizedJwksUri !== undefined) {
    throw new Error("[getbrick-idaas] dynamic OIDC client cannot configure both JWKS and jwks_uri");
  }
  const jwks = jwksSource === undefined || tokenEndpointAuthSigningAlg === undefined
    ? undefined
    : projectOidcClientJwks(jwksSource, tokenEndpointAuthSigningAlg);
  if (tokenEndpointAuthMethod === "private_key_jwt" && jwks === undefined && normalizedJwksUri === undefined && options.allowMissingJwks !== true) {
    throw new Error("[getbrick-idaas] private_key_jwt dynamic OIDC client requires a JWKS");
  }
  const idTokenValue = readAlias(client.id_token_signed_response_alg, client.idTokenSignedResponseAlg);
  const idTokenSignedResponseAlg = idTokenValue === undefined
    ? normalizeSigningAlgorithm(options.idTokenSignedResponseAlg ?? OIDC_DEFAULT_CLIENT_AUTH_SIGNING_ALGORITHM)
    : normalizeSigningAlgorithm(idTokenValue);
  const payload: Record<string, unknown> = {
    client_id: clientId,
    application_type: applicationType === "webview" ? "web" : applicationType,
    ...(clientKindValue !== undefined
      ? { [OIDC_CLIENT_KIND_METADATA]: clientKindValue }
      : applicationType === "webview"
        ? { [OIDC_CLIENT_KIND_METADATA]: applicationType }
        : {}),
    redirect_uris: redirectUris,
    grant_types: grantTypes,
    response_types: responseTypes,
    scope,
    token_endpoint_auth_method: tokenEndpointAuthMethod,
    [OIDC_REDIRECT_POLICY_METADATA]: "rfc8252-v1",
    [OIDC_REQUIRE_PKCE_METADATA]: requirePkce,
  };
  const clientName = normalizeText(client.client_name, 200);
  if (clientName !== undefined) payload.client_name = clientName;
  if (postLogoutRedirectUris.length > 0) payload.post_logout_redirect_uris = postLogoutRedirectUris;
  if (client.client_secret !== undefined && tokenEndpointAuthMethod !== "private_key_jwt") {
    const secret = normalizeText(client.client_secret, 4096);
    if (secret === undefined) throw new Error("[getbrick-idaas] dynamic OIDC client secret is invalid");
    payload.client_secret = secret;
  }
  if (tokenEndpointAuthMethod === "private_key_jwt") {
    payload.token_endpoint_auth_signing_alg = tokenEndpointAuthSigningAlg;
    if (jwks !== undefined) payload.jwks = jwks;
    if (normalizedJwksUri !== undefined) payload.jwks_uri = normalizedJwksUri;
  }
  payload.id_token_signed_response_alg = idTokenSignedResponseAlg;
  return payload as AdapterPayload;
}

async function resolveJwks(
  clientId: string,
  options: OidcDynamicClientAdapterOptions,
  store: OidcDynamicClientStore,
  algorithm: OidcDynamicClientSigningAlgorithm,
): Promise<unknown> {
  const configured = options.clientJwks;
  try {
    if (configured && Object.prototype.hasOwnProperty.call(configured, clientId)) {
      return projectOidcClientJwks(configured[clientId], algorithm);
    }
    if (typeof options.resolveClientJwks === "function") {
      const resolved = await options.resolveClientJwks(clientId);
      return resolved === undefined ? undefined : projectOidcClientJwks(resolved, algorithm);
    }
    if (typeof store.findJwks === "function") {
      const resolved = await store.findJwks(clientId);
      return resolved === undefined ? undefined : projectOidcClientJwks(resolved, algorithm);
    }
    return undefined;
  } catch {
    throw new Error("[getbrick-idaas] managed OIDC client JWKS is unavailable");
  }
}

function normalizeUriArray(
  value: unknown,
  maxItems: number,
  client: {
    applicationType: OidcApplicationType;
    tokenEndpointAuthMethod: string;
    requirePkce: boolean;
  },
  allowInsecureHttp?: boolean,
): string[] {
  if (value !== undefined && !Array.isArray(value) && typeof value !== "string") {
    throw new Error("[getbrick-idaas] dynamic OIDC client redirect URI is invalid");
  }
  const source = Array.isArray(value) ? value : typeof value === "string" ? [value] : [];
  if (source.length > maxItems) throw new Error("[getbrick-idaas] dynamic OIDC client redirect URI list is too large");
  const output: string[] = [];
  for (const item of source) {
    const normalized = normalizeText(item, 2048);
    if (normalized === undefined || /\s/u.test(normalized)) {
      throw new Error("[getbrick-idaas] dynamic OIDC client redirect URI is invalid");
    }
    try {
      new URL(normalized);
    } catch {
      throw new Error("[getbrick-idaas] dynamic OIDC client redirect URI is invalid");
    }
    assertOidcClientRedirectPolicy({
      ...client,
      redirectUris: [normalized],
    }, { allowInsecureHttp });
    if (output.includes(normalized)) {
      throw new Error("[getbrick-idaas] dynamic OIDC client contains duplicate redirect URIs");
    }
    output.push(normalized);
    if (output.length >= maxItems) break;
  }
  return output;
}

function normalizeScope(value: unknown): string {
  if (value !== undefined && typeof value !== "string" && !Array.isArray(value)) {
    throw new Error("[getbrick-idaas] dynamic OIDC client scope is invalid");
  }
  const source = Array.isArray(value)
    ? value
    : typeof value === "string"
      ? value.split(/\s+/u)
      : [];
  const scopes: string[] = [];
  for (const item of source) {
    const normalized = normalizeText(item, 128);
    if (normalized === undefined || /\s/u.test(normalized)) {
      throw new Error("[getbrick-idaas] dynamic OIDC client scope is invalid");
    }
    if (scopes.includes(normalized)) throw new Error("[getbrick-idaas] dynamic OIDC client scope contains duplicates");
    scopes.push(normalized);
  }
  return scopes.join(" ") || "openid";
}

export function projectOidcClientJwks(
  value: unknown,
  algorithm?: OidcDynamicClientSigningAlgorithm,
): Record<string, unknown> {
  let cloned: unknown;
  try {
    cloned = JSON.parse(JSON.stringify(value));
  } catch {
    throw new Error("[getbrick-idaas] managed OIDC client JWKS is invalid");
  }
  if (!isRecord(cloned) || !Array.isArray(cloned.keys) || cloned.keys.length === 0 || cloned.keys.length > 16) {
    throw new Error("[getbrick-idaas] managed OIDC client JWKS is invalid");
  }
  const seen = new Set<string>();
  const keys = cloned.keys.map((value) => {
    if (!isRecord(value)) throw new Error("[getbrick-idaas] managed OIDC client JWKS contains an invalid key");
    const key = { ...value };
    const kid = key.kid;
    if (typeof kid !== "string" || kid.length === 0 || kid.length > 256 || /\s/u.test(kid) || /[\u0000-\u001f\u007f]/u.test(kid)) {
      throw new Error("[getbrick-idaas] managed OIDC client JWKS keys require a valid kid");
    }
    if (seen.has(kid)) throw new Error("[getbrick-idaas] managed OIDC client JWKS contains duplicate kid values");
    seen.add(kid);
    if (key.use !== undefined && key.use !== "sig") {
      throw new Error("[getbrick-idaas] managed OIDC client JWKS keys must be signing keys");
    }
    if (key.key_ops !== undefined) {
      if (
        !Array.isArray(key.key_ops) ||
        !key.key_ops.every((operation) => typeof operation === "string") ||
        !key.key_ops.includes("verify") ||
        key.key_ops.includes("sign")
      ) {
        throw new Error("[getbrick-idaas] managed OIDC client JWKS key operations are invalid");
      }
    }
    if (["d", "p", "q", "dp", "dq", "qi", "oth", "k"].some((field) => key[field] !== undefined)) {
      throw new Error("[getbrick-idaas] managed OIDC client JWKS must contain public keys only");
    }
    if (key.kty !== "RSA" && key.kty !== "EC" && key.kty !== "OKP") {
      throw new Error("[getbrick-idaas] managed OIDC client JWKS key type is invalid");
    }
    const keyAlgorithm = key.alg === undefined ? algorithm : normalizeSigningAlgorithm(key.alg);
    if (algorithm !== undefined && keyAlgorithm !== undefined && keyAlgorithm !== algorithm) {
      throw new Error("[getbrick-idaas] managed OIDC client JWKS algorithm does not match client authentication");
    }
    if (keyAlgorithm !== undefined) {
      const expectedKeyType = OIDC_CLIENT_AUTH_SIGNING_KEY_TYPES[keyAlgorithm];
      if (key.kty !== expectedKeyType) {
        throw new Error("[getbrick-idaas] managed OIDC client JWKS key type does not match client authentication");
      }
      if (key.alg === undefined) key.alg = keyAlgorithm;
    }
    validatePublicKey(key, keyAlgorithm);
    return key;
  });
  return { keys };
}

export function assertOidcRemoteJwksPolicy(policy: OidcRemoteJwksPolicy): void {
  if (
    policy.profile !== undefined &&
    policy.profile !== "development" &&
    policy.profile !== "test" &&
    policy.profile !== "staging" &&
    policy.profile !== "production"
  ) {
    throw new Error("[getbrick-idaas] OIDC remote JWKS policy is invalid");
  }
  if (policy.allowRemoteJwksUri !== undefined && typeof policy.allowRemoteJwksUri !== "boolean") {
    throw new Error("[getbrick-idaas] OIDC remote JWKS policy is invalid");
  }
  const origins = normalizeTrustedJwksOrigins(policy.trustedJwksOrigins);
  const hosts = normalizeTrustedJwksHosts(policy.trustedJwksHosts);
  if (policy.allowRemoteJwksUri === true && origins.size === 0 && hosts.size === 0) {
    throw new Error("[getbrick-idaas] remote OIDC jwks_uri requires a trusted host or origin allowlist");
  }
}

export function normalizeOidcJwksUri(
  value: unknown,
  allowInsecureHttp?: boolean,
  remotePolicy?: OidcRemoteJwksPolicy,
): string {
  const normalized = normalizeText(value, 2048);
  if (normalized === undefined || !isSafeOidcUrl(normalized, true)) {
    throw new Error("[getbrick-idaas] dynamic OIDC client jwks_uri is invalid");
  }
  let parsed: URL;
  try {
    parsed = new URL(normalized);
  } catch {
    throw new Error("[getbrick-idaas] dynamic OIDC client jwks_uri is invalid");
  }
  if (parsed.protocol === "http:" && allowInsecureHttp !== true) {
    throw new Error("[getbrick-idaas] dynamic OIDC client jwks_uri is invalid");
  }
  if (remotePolicy === undefined) {
    if (allowInsecureHttp === false) {
      throw new Error("[getbrick-idaas] dynamic OIDC client jwks_uri is invalid");
    }
    return parsed.toString();
  }
  assertOidcRemoteJwksPolicy(remotePolicy);
  if (!usesStrictRemoteJwksPolicy(remotePolicy)) return parsed.toString();
  if (remotePolicy.profile === "production" && remotePolicy.allowRemoteJwksUri !== true) {
    throw new Error("[getbrick-idaas] production OIDC jwks_uri is disabled");
  }
  if (
    parsed.protocol !== "https:" ||
    isDisallowedRemoteHostname(parsed.hostname) ||
    hasUserInfoPath(parsed.pathname)
  ) {
    throw new Error("[getbrick-idaas] dynamic OIDC client jwks_uri is invalid");
  }
  const trustedOrigins = normalizeTrustedJwksOrigins(remotePolicy.trustedJwksOrigins);
  const trustedHosts = normalizeTrustedJwksHosts(remotePolicy.trustedJwksHosts);
  const trusted = trustedOrigins.has(parsed.origin) || trustedHosts.has(parsed.host);
  if (!trusted) {
    throw new Error("[getbrick-idaas] dynamic OIDC client jwks_uri is not trusted");
  }
  return parsed.toString();
}

function usesStrictRemoteJwksPolicy(policy: OidcRemoteJwksPolicy): boolean {
  return policy.profile === "production" || policy.allowRemoteJwksUri === true;
}

function normalizeTrustedJwksOrigins(value: readonly string[] | undefined): Set<string> {
  if (value === undefined) return new Set();
  if (!Array.isArray(value) || value.length > REMOTE_JWKS_MAX_ALLOWLIST_ENTRIES) {
    throw new Error("[getbrick-idaas] trusted OIDC JWKS origins are invalid");
  }
  const origins = new Set<string>();
  for (const item of value) {
    const normalized = normalizeText(item, 2048);
    if (normalized === undefined || !isSafeOidcUrl(normalized, false) || normalized.includes("*")) {
      throw new Error("[getbrick-idaas] trusted OIDC JWKS origins are invalid");
    }
    let parsed: URL;
    try {
      parsed = new URL(normalized);
    } catch {
      throw new Error("[getbrick-idaas] trusted OIDC JWKS origins are invalid");
    }
    if (parsed.protocol !== "https:" || parsed.pathname !== "/" || isDisallowedRemoteHostname(parsed.hostname)) {
      throw new Error("[getbrick-idaas] trusted OIDC JWKS origins are invalid");
    }
    origins.add(parsed.origin);
  }
  return origins;
}

function normalizeTrustedJwksHosts(value: readonly string[] | undefined): Set<string> {
  if (value === undefined) return new Set();
  if (!Array.isArray(value) || value.length > REMOTE_JWKS_MAX_ALLOWLIST_ENTRIES) {
    throw new Error("[getbrick-idaas] trusted OIDC JWKS hosts are invalid");
  }
  const hosts = new Set<string>();
  for (const item of value) {
    const normalized = normalizeText(item, 512);
    if (
      normalized === undefined ||
      normalized.includes("*") ||
      normalized.includes("://") ||
      normalized.includes("/") ||
      normalized.includes("?") ||
      normalized.includes("#") ||
      normalized.includes("@")
    ) {
      throw new Error("[getbrick-idaas] trusted OIDC JWKS hosts are invalid");
    }
    let parsed: URL;
    try {
      parsed = new URL(`https://${normalized}/`);
    } catch {
      throw new Error("[getbrick-idaas] trusted OIDC JWKS hosts are invalid");
    }
    if (parsed.username !== "" || parsed.password !== "" || parsed.pathname !== "/" || isDisallowedRemoteHostname(parsed.hostname)) {
      throw new Error("[getbrick-idaas] trusted OIDC JWKS hosts are invalid");
    }
    hosts.add(parsed.host);
  }
  return hosts;
}

function isDisallowedRemoteHostname(value: string): boolean {
  const hostname = value.startsWith("[") && value.endsWith("]") ? value.slice(1, -1) : value;
  const lower = hostname.toLowerCase();
  if (hostname === "" || hostname.endsWith(".") || lower.includes("%")) return true;
  const family = isIP(hostname);
  if (family === 4) return !isPublicIpv4(hostname);
  if (family === 6) return !isPublicIpv6(hostname);
  if (hostname.includes(":") || !/^[a-z0-9.-]+$/u.test(lower)) return true;
  return (
    lower === "localhost" ||
    lower.endsWith(".localhost") ||
    lower === "localhost.localdomain" ||
    lower.endsWith(".localhost.localdomain") ||
    lower === "local" ||
    lower.endsWith(".local") ||
    lower === "internal" ||
    lower.endsWith(".internal") ||
    lower === "home.arpa" ||
    lower.endsWith(".home.arpa") ||
    lower === "metadata" ||
    lower.endsWith(".metadata") ||
    lower === "instance-data" ||
    lower.endsWith(".instance-data")
  );
}

function isPublicIpv4(value: string): boolean {
  const parts = value.split(".").map(Number);
  if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) return false;
  const [a, b, c] = parts;
  return !(
    a === 0 ||
    a === 10 ||
    a === 127 ||
    (a === 100 && b >= 64 && b <= 127) ||
    (a === 169 && b === 254) ||
    (a === 168 && b === 63 && c === 129 && parts[3] === 16) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 0) ||
    (a === 192 && b === 88 && c === 99) ||
    (a === 192 && b === 168) ||
    (a === 198 && (b === 18 || b === 19)) ||
    (a === 198 && b === 51 && c === 100) ||
    (a === 203 && b === 0 && c === 113) ||
    a >= 224
  );
}

function isPublicIpv6(value: string): boolean {
  const address = value.toLowerCase().split("%", 1)[0];
  const words = parseIpv6Words(address);
  if (words === undefined) return false;
  if (words.every((word) => word === 0) || words.slice(0, 7).every((word) => word === 0) && words[7] === 1) return false;
  if ((words[0] & 0xfe00) === 0xfc00) return false;
  if ((words[0] & 0xffc0) === 0xfe80 || (words[0] & 0xffc0) === 0xfec0) return false;
  if ((words[0] & 0xff00) === 0xff00) return false;
  if (words[0] === 0x2001 && words[1] === 0x0000) return false;
  if (words[0] === 0x2001 && words[1] === 0x0002) return false;
  if (words[0] === 0x2001 && words[1] === 0x0db8) return false;
  if (words[0] === 0x2001 && (words[1] & 0xfff0) === 0x0010) return false;
  if (words[0] === 0x2002 || (words[0] === 0x3fff && (words[1] & 0xf000) === 0x0000)) return false;
  if (words[0] === 0x0064 && words[1] === 0xff9b) return false;
  if (words[0] === 0x0100 && words.slice(1, 4).every((word) => word === 0)) return false;
  if (words.slice(0, 5).every((word) => word === 0) && (words[5] === 0 || words[5] === 0xffff)) return false;
  return true;
}

function parseIpv6Words(value: string): number[] | undefined {
  if (isIP(value) !== 6) return undefined;
  let normalized = value;
  const lastColon = normalized.lastIndexOf(":");
  const embeddedIpv4 = normalized.slice(lastColon + 1);
  if (embeddedIpv4.includes(".")) {
    const parts = embeddedIpv4.split(".").map(Number);
    if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) return undefined;
    const high = ((parts[0] << 8) | parts[1]).toString(16);
    const low = ((parts[2] << 8) | parts[3]).toString(16);
    normalized = `${normalized.slice(0, lastColon + 1)}${high}:${low}`;
  }
  const [left = "", right = ""] = normalized.split("::");
  if (normalized.includes("::") && normalized.indexOf("::") !== normalized.lastIndexOf("::")) return undefined;
  const leftWords = left === "" ? [] : left.split(":");
  const rightWords = normalized.includes("::") && right === "" ? [] : right.split(":");
  const missing = 8 - leftWords.length - rightWords.length;
  if ((!normalized.includes("::") && missing !== 0) || (normalized.includes("::") && missing < 1)) return undefined;
  const parts = [
    ...leftWords,
    ...Array.from({ length: missing }, () => "0"),
    ...rightWords,
  ];
  if (parts.length !== 8 || parts.some((part) => part === "" || !/^[0-9a-f]{1,4}$/u.test(part))) return undefined;
  return parts.map((part) => Number.parseInt(part, 16));
}

function hasUserInfoPath(pathname: string): boolean {
  let decoded = pathname;
  try {
    decoded = decodeURIComponent(pathname);
  } catch {
    return true;
  }
  return decoded.split("/").some((segment) => segment.toLowerCase() === "userinfo");
}

async function requestRemoteOidcJwks(value: string, policy: OidcRemoteJwksPolicy): Promise<unknown> {
  const normalized = normalizeOidcJwksUri(value, false, policy);
  const parsed = new URL(normalized);
  const hostname = stripIpv6Brackets(parsed.hostname);
  const addresses = await resolvePublicRemoteAddresses(hostname);
  const address = addresses[0];
  if (address === undefined) throw new Error("[getbrick-idaas] managed OIDC client JWKS is unavailable");
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), REMOTE_JWKS_TIMEOUT_MS);
  try {
    const requestOptions: RequestOptions = {
      agent: false,
      headers: { accept: "application/json, application/jwk-set+json" },
      lookup: ((_hostname: string, _options: unknown, callback: (error: NodeJS.ErrnoException | null, address: string, family: number) => void) => {
        callback(null, address.address, address.family);
      }) as LookupFunction,
      method: "GET",
      rejectUnauthorized: true,
      servername: isIP(hostname) === 0 ? hostname : undefined,
      signal: controller.signal,
    };
    const response = await new Promise<IncomingMessage>((resolve, reject) => {
      const request = httpsRequest(parsed, requestOptions, resolve);
      request.once("error", reject);
      request.end();
    });
    const contentLength = Number(response.headers["content-length"]);
    const contentType = String(response.headers["content-type"] ?? "").split(";", 1)[0]?.trim().toLowerCase();
    const contentEncoding = response.headers["content-encoding"];
    if (
      response.statusCode !== 200 ||
      !["application/json", "application/jwk-set+json"].includes(contentType ?? "") ||
      (contentEncoding !== undefined && String(contentEncoding).toLowerCase() !== "identity") ||
      (Number.isFinite(contentLength) && contentLength > REMOTE_JWKS_MAX_BYTES)
    ) {
      response.resume();
      throw new Error("[getbrick-idaas] managed OIDC client JWKS is unavailable");
    }
    const chunks: Buffer[] = [];
    let size = 0;
    for await (const chunk of response) {
      const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      size += buffer.length;
      if (size > REMOTE_JWKS_MAX_BYTES) {
        response.destroy();
        throw new Error("[getbrick-idaas] managed OIDC client JWKS is unavailable");
      }
      chunks.push(buffer);
    }
    return JSON.parse(Buffer.concat(chunks).toString("utf8")) as unknown;
  } catch {
    throw new Error("[getbrick-idaas] managed OIDC client JWKS is unavailable");
  } finally {
    clearTimeout(timeout);
  }
}

async function resolvePublicRemoteAddresses(hostname: string): Promise<Array<{ address: string; family: 4 | 6 }>> {
  const literalFamily = isIP(hostname);
  if (literalFamily === 4) return [{ address: hostname, family: 4 }];
  if (literalFamily === 6) return [{ address: hostname, family: 6 }];
  const resolved = await dnsLookup(hostname, { all: true, verbatim: true });
  if (resolved.length === 0) throw new Error("[getbrick-idaas] managed OIDC client JWKS is unavailable");
  const addresses: Array<{ address: string; family: 4 | 6 }> = [];
  for (const entry of resolved) {
    const family = entry.family === 6 ? 6 : 4;
    if (family === 4 ? !isPublicIpv4(entry.address) : !isPublicIpv6(entry.address)) {
      throw new Error("[getbrick-idaas] managed OIDC client JWKS is unavailable");
    }
    addresses.push({ address: entry.address, family });
  }
  return addresses;
}

function stripIpv6Brackets(value: string): string {
  return value.startsWith("[") && value.endsWith("]") ? value.slice(1, -1) : value;
}

function withoutJwksUri(client: OidcDynamicClient): OidcDynamicClient {
  const output = { ...client };
  delete output.jwks_uri;
  delete output.jwksUri;
  return output;
}

function normalizeSigningAlgorithm(value: unknown): OidcDynamicClientSigningAlgorithm {
  if (typeof value !== "string" || !CLIENT_AUTH_SIGNING_ALGORITHMS.has(value)) {
    throw new Error("[getbrick-idaas] dynamic OIDC client signing algorithm is invalid");
  }
  return value as OidcDynamicClientSigningAlgorithm;
}

function validatePublicKey(key: Record<string, unknown>, algorithm: OidcDynamicClientSigningAlgorithm | undefined): void {
  let imported;
  try {
    imported = createPublicKey({ key: key as NodeJsonWebKey, format: "jwk" });
  } catch {
    throw new Error("[getbrick-idaas] managed OIDC client JWKS key could not be imported");
  }
  if (key.kty === "RSA") {
    if (imported.asymmetricKeyType !== "rsa" || (imported.asymmetricKeyDetails?.modulusLength ?? 0) < 2048) {
      throw new Error("[getbrick-idaas] managed OIDC client RSA JWKS key is invalid");
    }
  } else if (key.kty === "EC") {
    if (
      imported.asymmetricKeyType !== "ec" ||
      (imported.asymmetricKeyDetails?.namedCurve !== "P-256" && imported.asymmetricKeyDetails?.namedCurve !== "prime256v1") ||
      (algorithm !== undefined && algorithm !== "ES256")
    ) {
      throw new Error("[getbrick-idaas] managed OIDC client EC JWKS key is invalid");
    }
  } else if (key.kty === "OKP") {
    const curve = key.crv;
    if (
      (curve !== "Ed25519" && curve !== "Ed448") ||
      (typeof imported.asymmetricKeyType !== "string" || !imported.asymmetricKeyType.startsWith("ed")) ||
      (algorithm !== undefined && algorithm !== "EdDSA")
    ) {
      throw new Error("[getbrick-idaas] managed OIDC client OKP JWKS key is invalid");
    }
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function readAlias<T>(snake: T | undefined, camel: T | undefined): T | undefined {
  if (snake !== undefined && camel !== undefined && snake !== camel) {
    throw new Error("[getbrick-idaas] dynamic OIDC client metadata aliases conflict");
  }
  return snake === undefined ? camel : snake;
}

function readBooleanAlias(snake: unknown, camel: unknown): boolean | undefined {
  if (snake !== undefined && typeof snake !== "boolean") {
    throw new Error("[getbrick-idaas] dynamic OIDC client PKCE policy is invalid");
  }
  if (camel !== undefined && typeof camel !== "boolean") {
    throw new Error("[getbrick-idaas] dynamic OIDC client PKCE policy is invalid");
  }
  return readAlias(snake as boolean | undefined, camel as boolean | undefined);
}

function normalizeText(value: unknown, maxLength: number): string | undefined {
  if (typeof value !== "string") return undefined;
  if (value !== value.trim() || value.length === 0 || value.length > maxLength || /[\u0000-\u001f\u007f]/u.test(value)) return undefined;
  return value;
}

function normalizeArray(value: unknown, maxItemLength: number, maxItems: number): string[] {
  const source = Array.isArray(value) ? value : typeof value === "string" ? [value] : [];
  if (source.length > maxItems) throw new Error("[getbrick-idaas] dynamic OIDC client metadata array is too large");
  const output: string[] = [];
  for (const item of source) {
    const normalized = normalizeText(item, maxItemLength);
    if (normalized === undefined) throw new Error("[getbrick-idaas] dynamic OIDC client metadata array is invalid");
    if (output.includes(normalized)) throw new Error("[getbrick-idaas] dynamic OIDC client metadata array contains duplicates");
    output.push(normalized);
  }
  return output;
}
