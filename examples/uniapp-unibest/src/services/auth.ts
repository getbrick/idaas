import {
  PLATFORM_SESSION_LOGOUT_ROUTE,
  PLATFORM_SESSION_REFRESH_ROUTE,
  PLATFORM_WEBVIEW_CALLBACK_ROUTE,
  PLATFORM_WEBVIEW_START_ROUTE,
  PLATFORM_WEBVIEW_TICKET_EXCHANGE_ROUTE,
  clientConfig,
  getPlatformRoute,
  normalizeOrigin,
  type ClientConfig,
} from "../config";
import { AuthError } from "../auth/errors";
import { assertAuthorizationUrl } from "../auth/handoff";
import { assertSafeRedirectUri } from "../auth/pkce";
import { normalizeOpaqueSession, normalizePublicUser, type OpaqueSession, type PublicUser } from "../auth/session";
import { ApiRequestClient } from "./request";

export interface OidcFlowBinding {
  flowId: string;
  nonce: string;
  origin: string;
}

export interface OidcStartInput {
  redirectUri: string;
  clientType: "web" | "native" | "webview";
  clientId?: string;
  scope?: string;
  state?: string;
  nonce?: string;
  flowId?: string;
  flowBinding?: string;
  origin?: string;
  codeChallenge?: string;
}

export interface OidcStartResult {
  authorizationUrl: string;
  state: string;
  expiresAt: string;
  flowId?: string;
  transactionId?: string;
  nonce?: string;
  origin?: string;
  redirectUri?: string;
}

export interface OidcExchangeInput extends Partial<OidcFlowBinding> {
  code: string;
  codeVerifier?: string;
  redirectUri: string;
  state: string;
  flowBinding?: string;
  clientId?: string;
  clientType: "web" | "native" | "webview";
}

export type OidcExchangeResult =
  | { clientType: "web"; status: 204 }
  | { clientType: "native"; session: OpaqueSession };

export interface AuthApi {
  loginWithWechatCode(code: string): Promise<OpaqueSession>;
  startOidc(input: OidcStartInput): Promise<OidcStartResult>;
  exchangeOidc(input: OidcExchangeInput): Promise<OidcExchangeResult>;
  exchangeWebviewTicket(ticketReference: string, sessionReference?: string, clientId?: string, binding?: Partial<OidcFlowBinding>): Promise<OpaqueSession>;
  refresh(sessionReference: string, clientKind?: "native" | "mp_weixin" | "webview"): Promise<OpaqueSession>;
  logout(sessionReference: string, clientKind?: "native" | "mp_weixin" | "webview"): Promise<void>;
  me(sessionReference?: string, clientKind?: "native" | "mp_weixin" | "webview"): Promise<PublicUser | null>;
  refreshWeb(): Promise<void>;
  logoutWeb(): Promise<void>;
  meWeb(): Promise<PublicUser | null>;
}

export function createAuthApi(request: ApiRequestClient, config: ClientConfig = clientConfig): AuthApi {
  const basePath = config.authBasePath;
  return {
    loginWithWechatCode(code) {
      assertProviderCode(code);
      return request.request<unknown>({
        path: resolveMiniProgramPath(config),
        method: "POST",
        data: { code, clientKind: "mp_weixin" },
        auth: false,
        refreshOnUnauthorized: false,
        withCredentials: false,
      }).then(normalizeOpaqueSession);
    },

    async startOidc(input) {
      assertOidcStartInput(input);
      const webview = input.clientType === "native" || input.clientType === "webview";
      const path = webview ? resolvePlatformRoute(config, PLATFORM_WEBVIEW_START_ROUTE) : `${basePath}/oidc/start`;
      const data = webview
        ? {
            redirectUri: input.redirectUri,
            client: "webview",
            flowBinding: input.flowBinding as string,
            ...(input.scope === undefined ? {} : { scope: input.scope }),
          }
        : {
            redirectUri: input.redirectUri,
            clientType: "web",
            clientId: input.clientId as string,
            scope: input.scope as string,
            state: input.state as string,
            nonce: input.nonce as string,
            codeChallenge: input.codeChallenge as string,
            codeChallengeMethod: "S256",
          };
      return request.request<unknown>({
        path,
        method: "POST",
        data,
        auth: false,
        refreshOnUnauthorized: false,
        withCredentials: true,
      }).then((value) => normalizeOidcStart(value, input));
    },

    async exchangeOidc(input) {
      assertProviderCode(input.code);
      assertState(input.state);
      assertRedirect(input.redirectUri);
      if (input.clientType !== "web" && input.clientType !== "native" && input.clientType !== "webview") {
        throw new AuthError("oidc_configuration_missing", "OIDC client type is invalid");
      }
      const webview = input.clientType === "native" || input.clientType === "webview";
      if (webview) {
        assertFlowBinding(input.flowBinding, input.flowId);
      } else {
        if (input.flowBinding !== undefined) throw new AuthError("invalid_oidc_transaction", "OIDC flow binding is not valid for web exchange", 400, false);
        assertCodeVerifier(input.codeVerifier);
        assertClientId(input.clientId);
      }

      const path = webview ? resolvePlatformRoute(config, PLATFORM_WEBVIEW_CALLBACK_ROUTE) : `${basePath}/oidc/callback`;
      const data = webview
        ? { state: input.state, code: input.code, flowBinding: input.flowBinding as string }
        : {
            code: input.code,
            codeVerifier: input.codeVerifier as string,
            redirectUri: input.redirectUri,
            state: input.state,
            clientId: input.clientId as string,
            clientType: "web",
          };
      return request.request<unknown>({
        path,
        method: "POST",
        data,
        auth: false,
        refreshOnUnauthorized: false,
        withCredentials: true,
      }).then((value) => normalizeOidcExchange(value, input.clientType));
    },

    exchangeWebviewTicket(ticketReference, sessionReference, clientId, binding) {
      assertTicketReference(ticketReference);
      if (typeof sessionReference !== "string") throw new AuthError("session_missing", "Client session is unavailable", 401, false);
      assertSessionReference(sessionReference);
      assertClientId(clientId);
      if (binding?.flowId !== undefined) assertFlowId(binding.flowId);
      if (binding?.nonce !== undefined) assertNonce(binding.nonce);
      if (binding?.origin !== undefined) assertOrigin(binding.origin);
      return request.request<unknown>({
        path: resolvePlatformRoute(config, PLATFORM_WEBVIEW_TICKET_EXCHANGE_ROUTE),
        method: "POST",
        data: {
          ticketReference,
          sessionReference,
          clientId,
        },
        auth: true,
        refreshOnUnauthorized: false,
        withCredentials: true,
      }).then(normalizeOpaqueSession);
    },

    refresh(sessionReference, clientKind) {
      assertSessionReference(sessionReference);
      const platform = clientKind === "native" || clientKind === "mp_weixin" || clientKind === "webview";
      return request.request<unknown>({
        path: platform ? resolvePlatformRoute(config, PLATFORM_SESSION_REFRESH_ROUTE) : `${basePath}/refresh`,
        method: "POST",
        data: platform && clientKind !== "webview" ? { sessionReference, client: clientKind } : { sessionReference },
        refreshOnUnauthorized: false,
        withCredentials: false,
      }).then(normalizeOpaqueSession);
    },

    logout(sessionReference, clientKind) {
      assertSessionReference(sessionReference);
      const platform = clientKind === "native" || clientKind === "mp_weixin" || clientKind === "webview";
      return request.request<void>({
        path: platform ? resolvePlatformRoute(config, PLATFORM_SESSION_LOGOUT_ROUTE) : `${basePath}/logout`,
        method: "POST",
        data: platform && clientKind !== "webview" ? { sessionReference, client: clientKind } : { sessionReference },
        refreshOnUnauthorized: false,
        withCredentials: false,
      });
    },

    me(sessionReference, clientKind) {
      if (sessionReference !== undefined) assertSessionReference(sessionReference);
      return request.request<unknown>({
        path: `${basePath}/me`,
        method: "GET",
        withCredentials: false,
      }).then(normalizeMeResponse);
    },

    refreshWeb() {
      return request.request<void>({
        path: `${basePath}/refresh`,
        method: "POST",
        auth: false,
        refreshOnUnauthorized: false,
        withCredentials: true,
      });
    },

    logoutWeb() {
      return request.request<void>({
        path: `${basePath}/logout`,
        method: "POST",
        auth: false,
        refreshOnUnauthorized: false,
        withCredentials: true,
      });
    },

    meWeb() {
      return request.request<unknown>({
        path: `${basePath}/me`,
        method: "GET",
        auth: false,
        refreshOnUnauthorized: false,
        withCredentials: true,
      }).then(normalizeMeResponse);
    },
  };
}

function resolvePlatformRoute(config: ClientConfig, route: string): string {
  try {
    return getPlatformRoute(config, route);
  } catch {
    throw new AuthError("oidc_configuration_missing", "Application platform route is invalid", 500, false);
  }
}

function resolveMiniProgramPath(config: ClientConfig): string {
  if (config.applicationId.length === 0 || config.platformId.length === 0) {
    throw new AuthError("oidc_configuration_missing", "WeChat application and platform identifiers must be configured together", 500, false);
  }
  assertPathIdentifier(config.applicationId, "application");
  assertPathIdentifier(config.platformId, "platform");
  return `${config.platformBasePath}/applications/${encodeURIComponent(config.applicationId)}/platforms/${encodeURIComponent(config.platformId)}/login/mini-program/exchange`;
}

function normalizeOidcExchange(value: unknown, clientType: "web" | "native" | "webview"): OidcExchangeResult {
  if (clientType === "web") {
    if (value === undefined || (isRecord(value) && value.status === 204)) return { clientType: "web", status: 204 };
    throw new AuthError("invalid_auth_response", "Web OIDC exchange returned an unexpected body", 502, false);
  }
  return { clientType: "native", session: normalizeOpaqueSession(value) };
}

function normalizeOidcStart(value: unknown, input: OidcStartInput): OidcStartResult {
  const root = isRecord(value) && isRecord(value.data) ? value.data : value;
  if (!isRecord(root)) throw new AuthError("invalid_auth_response", "OIDC start response is invalid", 502, false);
  const web = input.clientType === "web";
  const authorizationUrl = root.authorizationUrl;
  const flowRecord = isRecord(root.flow) ? root.flow : undefined;
  const transactionRecord = isRecord(root.transaction) ? root.transaction : undefined;
  const state = root.state ?? transactionRecord?.state ?? flowRecord?.state;
  const expiresAt = root.expiresAt ?? transactionRecord?.expiresAt ?? flowRecord?.expiresAt;
  if (
    typeof authorizationUrl !== "string" ||
    typeof state !== "string" ||
    (web && state !== input.state) ||
    typeof expiresAt !== "string" ||
    !Number.isFinite(new Date(expiresAt).getTime())
  ) {
    throw new AuthError("invalid_auth_response", "OIDC start response is invalid", 502, false);
  }
  if (web && input.flowBinding !== undefined) throw new AuthError("invalid_oidc_transaction", "OIDC flow binding is not valid for web start", 400, false);
  if (!web && input.flowBinding !== undefined && (authorizationUrl.includes(input.flowBinding) || authorizationUrl.includes(encodeURIComponent(input.flowBinding)))) {
    throw new AuthError("invalid_auth_response", "OIDC authorization URL exposed flow binding", 502, false);
  }
  assertAuthorizationUrl(authorizationUrl, input.redirectUri);
  const authorization = new URL(authorizationUrl);
  if (authorization.searchParams.getAll("state").length !== 1 || authorization.searchParams.get("state") !== state) {
    throw new AuthError("invalid_auth_response", "OIDC authorization URL state is invalid", 502, false);
  }
  if (web && (authorization.searchParams.getAll("nonce").length !== 1 || authorization.searchParams.get("nonce") !== input.nonce)) {
    throw new AuthError("invalid_auth_response", "OIDC authorization URL nonce is invalid", 502, false);
  }
  const flowId = readOptionalServerReference(root.flowId ?? flowRecord?.flowId ?? flowRecord?.id ?? (typeof root.flow === "string" ? root.flow : undefined), "flow");
  const transactionId = readOptionalServerReference(root.transactionId ?? root.transaction_id ?? transactionRecord?.id ?? (typeof root.transaction === "string" ? root.transaction : undefined), "transaction");
  const nonce = readOptionalNonce(root.nonce ?? transactionRecord?.nonce);
  const origin = readOptionalOrigin(root.origin ?? transactionRecord?.origin);
  if (web && nonce !== undefined && nonce !== input.nonce) throw new AuthError("oidc_nonce_mismatch", "OIDC start nonce does not match the login transaction", 400, false);
  if (origin !== undefined && origin !== input.origin) throw new AuthError("oidc_origin_mismatch", "OIDC start origin does not match the login transaction", 400, false);
  const redirectUri = root.redirectUri;
  if (redirectUri !== undefined && redirectUri !== input.redirectUri) {
    throw new AuthError("invalid_oidc_transaction", "OIDC start redirect does not match the login transaction", 409, false);
  }
  return {
    authorizationUrl,
    state,
    expiresAt: new Date(expiresAt).toISOString(),
    ...(flowId === undefined ? {} : { flowId }),
    ...(transactionId === undefined ? {} : { transactionId }),
    ...(nonce === undefined ? {} : { nonce }),
    ...(origin === undefined ? {} : { origin }),
    ...(typeof redirectUri === "string" ? { redirectUri } : {}),
  };
}

function assertOidcStartInput(input: OidcStartInput): void {
  assertRedirect(input.redirectUri);
  if (input.clientType !== "web" && input.clientType !== "native" && input.clientType !== "webview") throw new AuthError("oidc_configuration_missing", "OIDC client type is invalid");
  if (input.clientType === "web") {
    assertClientId(input.clientId);
    assertScope(input.scope);
    assertState(input.state);
    assertNonce(input.nonce);
    assertFlowId(input.flowId);
    assertOrigin(input.origin);
    if (input.flowBinding !== undefined) throw new AuthError("invalid_oidc_transaction", "OIDC flow binding is not valid for web start", 400, false);
    if (typeof input.codeChallenge !== "string" || !/^[A-Za-z0-9_-]{43,128}$/u.test(input.codeChallenge)) throw new AuthError("oidc_configuration_missing", "OIDC PKCE challenge is invalid");
    return;
  }
  assertFlowBinding(input.flowBinding, input.flowId);
  if (input.scope !== undefined) assertScope(input.scope);
}

function assertScope(value: string | undefined): void {
  if (typeof value !== "string" || value.trim().length === 0 || value.length > 2048) throw new AuthError("oidc_configuration_missing", "OIDC scope is invalid", 500, false);
}

function assertProviderCode(value: string): void {
  if (typeof value !== "string" || value.trim().length === 0 || value.length > 4096 || /[\u0000-\u001f\u007f\s]/u.test(value)) throw new AuthError("invalid_auth_response", "Provider code is invalid", 400, false);
}

function assertState(value: string | undefined): void {
  if (typeof value !== "string" || value.length < 16 || value.length > 512 || !/^[A-Za-z0-9._~-]+$/u.test(value)) throw new AuthError("invalid_oidc_callback", "OIDC state is invalid", 400, false);
}

function assertNonce(value: string | undefined): void {
  if (typeof value !== "string" || value.length < 16 || value.length > 512 || !/^[A-Za-z0-9._~-]+$/u.test(value)) throw new AuthError("oidc_configuration_missing", "OIDC nonce is invalid", 400, false);
}

function assertFlowId(value: string | undefined): void {
  if (typeof value !== "string" || value.length < 16 || value.length > 128 || !/^[A-Za-z0-9_-]+$/u.test(value) || /(?:token|secret|authorization|session[_-]?key|refresh|access|id[_-]?token|code)/iu.test(value)) throw new AuthError("oidc_configuration_missing", "OIDC flow ID is invalid", 400, false);
}

function assertFlowBinding(value: string | undefined, expectedFlowId?: string): void {
  if (typeof value !== "string" || value.length < 22 || value.length > 128 || !/^[A-Za-z0-9_-]+$/u.test(value) || (expectedFlowId !== undefined && value !== expectedFlowId)) {
    throw new AuthError("invalid_oidc_transaction", "OIDC flow binding is invalid", 400, false);
  }
}

function assertOrigin(value: string | undefined): void {
  if (typeof value !== "string") throw new AuthError("oidc_configuration_missing", "OIDC origin is invalid", 400, false);
  try {
    normalizeOrigin(value);
  } catch {
    throw new AuthError("oidc_configuration_missing", "OIDC origin is invalid", 400, false);
  }
}

function assertCodeVerifier(value: string | undefined): void {
  if (typeof value !== "string" || value.length < 43 || value.length > 128 || !/^[A-Za-z0-9_-]+$/u.test(value)) throw new AuthError("invalid_oidc_transaction", "OIDC PKCE verifier is invalid", 400, false);
}

function assertRedirect(value: string): void {
  try {
    assertSafeRedirectUri(value);
  } catch {
    throw new AuthError("oidc_configuration_missing", "OIDC redirect URI is invalid", 400, false);
  }
}

function assertClientId(value: string | undefined): void {
  if (typeof value !== "string" || value.trim().length === 0 || value.length > 256) throw new AuthError("oidc_configuration_missing", "OIDC client configuration is incomplete", 500, false);
}

function readOptionalServerReference(value: unknown, field: string): string | undefined {
  if (value === undefined || value === null) return undefined;
  if (typeof value !== "string" || value.length < 8 || value.length > 512 || !/^[A-Za-z0-9._~-]+$/u.test(value) || /(?:token|secret|authorization|session[_-]?key|refresh|access|id[_-]?token|code|state)/iu.test(value)) {
    throw new AuthError("invalid_auth_response", `OIDC ${field} reference is invalid`, 502, false);
  }
  return value;
}

function readOptionalFlowId(value: unknown): string | undefined {
  if (value === undefined || value === null) return undefined;
  try {
    assertFlowId(value as string);
    return value as string;
  } catch {
    throw new AuthError("invalid_auth_response", "OIDC start response is invalid", 502, false);
  }
}

function readOptionalNonce(value: unknown): string | undefined {
  if (value === undefined || value === null) return undefined;
  try {
    assertNonce(value as string);
    return value as string;
  } catch {
    throw new AuthError("invalid_auth_response", "OIDC start response is invalid", 502, false);
  }
}

function readOptionalOrigin(value: unknown): string | undefined {
  if (value === undefined || value === null) return undefined;
  try {
    assertOrigin(value as string);
    return normalizeOrigin(value as string);
  } catch {
    throw new AuthError("invalid_auth_response", "OIDC start response is invalid", 502, false);
  }
}

function normalizeMeResponse(value: unknown): PublicUser | null {
  if (value === null || value === undefined) return null;
  const root = isRecord(value) && isRecord(value.data) ? value.data : value;
  if (root === null || root === undefined) return null;
  const user = isRecord(root) && isRecord(root.user) ? root.user : root;
  return normalizePublicUser(user);
}

function assertPathIdentifier(value: string, field: string): void {
  if (typeof value !== "string" || value.length === 0 || value.length > 256 || /[\u0000-\u001f\u007f/]/u.test(value)) throw new AuthError("oidc_configuration_missing", `${field} identifier is invalid`, 500, false);
}

function assertTicketReference(value: string): void {
  if (typeof value !== "string" || value.length < 24 || value.length > 512 || !/^[A-Za-z0-9_-]+$/u.test(value) || /(?:token|secret|authorization|session[_-]?key|refresh|access|id[_-]?token|code|state)/iu.test(value)) throw new AuthError("invalid_oidc_callback", "Web-view ticket is invalid", 400, false);
}

function assertSessionReference(value: string): void {
  if (typeof value !== "string" || value.length < 24 || value.length > 512 || !/^[A-Za-z0-9._~-]+$/u.test(value)) throw new AuthError("invalid_session", "Client session is invalid", 400, false);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
