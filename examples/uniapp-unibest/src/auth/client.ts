import {
  assertOidcConfig,
  clientConfig,
  getConfiguredOrigins,
  getOidcRedirectUri,
  getWebviewBridgeOrigin,
  getWebviewRedirectUri,
  normalizeOrigin,
  type ClientConfig,
} from "../config";
import { AuthError, toAuthError } from "./errors";
import { assertCallbackMatchesTransaction, normalizeOidcCallback, type NormalizedOidcCallback, type OidcCallbackInput } from "./callback";
import { createPkceTransaction, OidcFlowFenceStore, OidcTransactionStore, type PkceTransaction } from "./pkce";
import { requestWechatMiniProgramCode, getClientPlatform, type ClientPlatform } from "./platform";
import { createUniAuthHandoff, type AuthHandoff } from "./handoff";
import { OpaqueSessionStore, type OpaqueClientKind, type OpaqueSession, type PublicUser } from "./session";
import { SessionCoordinator, type SessionFence } from "./session-coordinator";
import { createAuthApi, type AuthApi, type OidcExchangeResult, type OidcStartResult } from "../services/auth";
import { ApiRequestClient } from "../services/request";
import { createUniStorage, getUniRuntime, type KeyValueStorage, type UniRuntime } from "../types/runtime";

export interface AuthClientOptions {
  config?: ClientConfig;
  storage?: KeyValueStorage;
  runtime?: UniRuntime;
  handoff?: AuthHandoff;
  api?: AuthApi;
  request?: ApiRequestClient;
  coordinator?: SessionCoordinator;
  now?: () => number;
  platform?: ClientPlatform;
}

export class AuthClient {
  private readonly config: ClientConfig;
  private readonly sessions: OpaqueSessionStore;
  private readonly coordinator: SessionCoordinator;
  private readonly transactions: OidcTransactionStore;
  private readonly flowFence: OidcFlowFenceStore;
  private readonly api: AuthApi;
  private readonly request: ApiRequestClient;
  private readonly handoff: AuthHandoff;
  private readonly runtime: UniRuntime;
  private readonly platform: ClientPlatform | "unknown";
  private readonly now: () => number;
  private cookieAuthenticated = false;
  private cookieUser: PublicUser | null = null;

  constructor(options: AuthClientOptions = {}) {
    this.config = options.config ?? clientConfig;
    const runtime = options.runtime ?? getUniRuntime();
    const storage = options.storage ?? createUniStorage();
    this.sessions = options.coordinator?.sessionStore ?? new OpaqueSessionStore({ storage, now: options.now });
    this.coordinator = options.coordinator ?? new SessionCoordinator({ sessions: this.sessions, now: options.now });
    this.transactions = new OidcTransactionStore({ storage, now: options.now });
    this.flowFence = new OidcFlowFenceStore({ storage });
    this.request = options.request ?? new ApiRequestClient({
      baseUrl: this.config.apiBaseUrl,
      sessions: this.sessions,
      coordinator: this.coordinator,
      runtime,
      timeoutMs: this.config.requestTimeoutMs,
    });
    this.api = options.api ?? createAuthApi(this.request, this.config);
    this.handoff = options.handoff ?? createUniAuthHandoff(runtime);
    this.runtime = runtime;
    this.platform = options.platform ?? getClientPlatform();
    if (this.platform === "h5") this.sessions.clear();
    this.now = options.now ?? Date.now;
    this.request.setRefreshHandler(async () => {
      await this.refresh();
      return null;
    });
  }

  get sessionStore(): OpaqueSessionStore {
    return this.sessions;
  }

  get sessionCoordinator(): SessionCoordinator {
    return this.coordinator;
  }

  get transactionStore(): OidcTransactionStore {
    return this.transactions;
  }

  get flowFenceStore(): OidcFlowFenceStore {
    return this.flowFence;
  }

  getSession(): OpaqueSession | null {
    return this.platform === "h5" ? null : this.sessions.load();
  }

  getUser(): PublicUser | null {
    return this.platform === "h5" ? this.cookieUser : this.getSession()?.user ?? null;
  }

  isCookieAuthenticated(): boolean {
    return this.platform === "h5" && this.cookieAuthenticated;
  }

  isAuthenticated(): boolean {
    return this.platform === "h5" ? this.isCookieAuthenticated() : this.getSession() !== null;
  }

  async loginWithWechat(): Promise<OpaqueSession> {
    const fence = this.coordinator.snapshot();
    const flowFence = this.flowFence.begin();
    this.transactions.clear();
    try {
      const code = await requestWechatMiniProgramCode(this.runtime);
      const session = await this.api.loginWithWechatCode(code);
      this.flowFence.assertCurrent(flowFence);
      return this.acceptSession(session, fence);
    } catch (error) {
      throw toAuthError(error, "wechat_login_failed", "WeChat login failed");
    }
  }

  async startOidcLogin(): Promise<OidcStartResult> {
    if (this.platform !== "h5" && this.platform !== "app") throw new AuthError("unsupported_platform", "OIDC login is not available on this platform", 400, false);
    const webview = this.platform === "app";
    let redirectUri: string;
    let origin: string;
    try {
      assertOidcConfig(webview ? "app" : "h5", this.config);
      redirectUri = webview ? getWebviewRedirectUri(this.config) : getOidcRedirectUri("h5", this.config);
      origin = this.resolveOrigin(webview, redirectUri);
    } catch (error) {
      if (error instanceof AuthError) throw error;
      throw new AuthError("oidc_configuration_missing", "OIDC client configuration is incomplete", 500, false);
    }
    const flowFence = this.flowFence.begin();
    this.transactions.clear();
    if (this.platform === "h5") {
      this.coordinator.clear();
      this.cookieAuthenticated = false;
      this.cookieUser = null;
    }
    const transaction = await createPkceTransaction({
      redirectUri,
      origin,
      clientType: webview ? "webview" : "web",
      startGeneration: flowFence.generation,
      attempt: flowFence.attempt,
      now: this.now,
    });
    this.flowFence.assertCurrent(flowFence);
    this.transactions.save(transaction);
    try {
      const start = webview
        ? await this.api.startOidc({ redirectUri, clientType: "webview", flowBinding: transaction.flowId, scope: this.config.oidc.scope })
        : await this.api.startOidc({
            redirectUri,
            clientType: "web",
            clientId: this.config.oidc.clientId,
            scope: this.config.oidc.scope,
            state: transaction.state,
            nonce: transaction.nonce,
            flowId: transaction.flowId,
            origin: transaction.origin,
            codeChallenge: transaction.codeChallenge,
          });
      this.assertFlowCurrent(flowFence);
      if (webview) {
        this.transactions.update(transaction.flowId, {
          state: start.state,
          ...(start.flowId === undefined ? {} : { serverFlowId: start.flowId }),
          ...(start.transactionId === undefined ? {} : { serverTransactionId: start.transactionId }),
        });
      } else {
        assertStartBinding(start, transaction, false);
      }
      await this.handoff.open(start.authorizationUrl);
      return start;
    } catch (error) {
      this.transactions.clear(transaction.flowId);
      throw toAuthError(error, "invalid_auth_response", "OIDC login failed");
    }
  }

  async completeOidcCallback(input: OidcCallbackInput): Promise<OpaqueSession | null> {
    const webview = this.platform === "app";
    let allowedOrigins: readonly string[];
    try {
      allowedOrigins = getConfiguredOrigins(webview ? "app" : "h5", this.config);
      if (webview) {
        const bridgeOrigin = getWebviewBridgeOrigin(this.config);
        if (!allowedOrigins.includes(bridgeOrigin)) throw new Error("OIDC app bridge origin is not allowed");
        allowedOrigins = [bridgeOrigin];
      }
    } catch {
      throw new AuthError("oidc_configuration_missing", "OIDC origin allowlist is invalid", 500, false);
    }
    const callback = normalizeOidcCallback(input, {
      requireFlowId: false,
      requireNonce: false,
      requireOrigin: webview,
      requireState: webview,
      allowProviderError: true,
      ...(allowedOrigins.length === 0 ? {} : { allowedOrigins }),
    });
    const transaction = this.resolveTransaction(callback);
    if (transaction === null) {
      if ("error" in callback) throw new AuthError("oidc_callback_denied", "OIDC authorization was denied", 400, false);
      throw new AuthError("invalid_oidc_transaction", "OIDC transaction is unavailable", 409, false);
    }
    this.assertTransactionActive(transaction);
    const flowFence = { generation: transaction.startGeneration, attempt: transaction.attempt };
    if ("error" in callback) {
      if (callback.state === undefined) throw new AuthError("oidc_callback_denied", "OIDC authorization was denied", 400, false);
      this.assertCallbackBinding(callback, transaction);
      this.consumeTransaction(transaction);
      throw new AuthError("oidc_callback_denied", "OIDC authorization was denied", 400, false);
    }
    if (callback.state !== undefined) this.assertCallbackBinding(callback, transaction);
    if ((webview && transaction.clientType !== "webview") || (!webview && transaction.clientType !== "web")) {
      throw new AuthError("oidc_flow_mismatch", "OIDC transaction client type does not match the platform", 409, false);
    }
    const consumed = this.consumeTransaction(transaction);
    if (consumed === null) throw new AuthError("invalid_oidc_transaction", "OIDC transaction is unavailable", 409, false);
    const fence = this.coordinator.snapshot();
    if ("ticketReference" in callback) {
      const current = this.sessions.load();
      if (current === null) throw new AuthError("session_missing", "Client session is unavailable", 401, false);
      let session: OpaqueSession;
      try {
        session = await this.api.exchangeWebviewTicket(callback.ticketReference, current.sessionReference, this.config.oidc.clientId);
      } catch (error) {
        throw toAuthError(error, "invalid_auth_response", "Webview callback exchange failed");
      }
      this.assertFlowCurrent(flowFence);
      return this.acceptSession(session, fence);
    }
    let result: OidcExchangeResult;
    try {
      result = await this.api.exchangeOidc({
        code: callback.code,
        codeVerifier: transaction.codeVerifier,
        redirectUri: transaction.redirectUri,
        state: transaction.state,
        clientId: this.config.oidc.clientId,
        clientType: webview ? "webview" : "web",
        ...(webview ? { flowBinding: transaction.flowId } : {}),
      });
    } catch (error) {
      throw toAuthError(error, "invalid_auth_response", "OIDC callback exchange failed");
    }
    this.assertFlowCurrent(flowFence);
    if (result.clientType === "web") {
      if (!this.coordinator.isCurrent(fence)) throw generationMismatch();
      this.cookieAuthenticated = true;
      try {
        const user = await this.api.meWeb();
        this.assertFlowCurrent(flowFence);
        if (!this.coordinator.isCurrent(fence)) throw generationMismatch();
        this.cookieUser = user;
      } catch (error) {
        if (error instanceof AuthError && error.code === "session_generation_mismatch") throw error;
        this.cookieUser = null;
      }
      return null;
    }
    return this.acceptSession(result.session, fence);
  }

  async refresh(): Promise<OpaqueSession | null> {
    if (this.platform === "h5") {
      try {
        await this.coordinator.refreshCookie(async () => {
          try {
            await this.api.refreshWeb();
          } catch (error) {
            throw toAuthError(error, "session_expired", "Session refresh failed");
          }
        });
        this.cookieAuthenticated = true;
        return null;
      } catch (error) {
        throw toAuthError(error, "session_expired", "Session refresh failed");
      }
    }
    return this.coordinator.refresh(async ({ sessionReference }) => {
      if (sessionReference === null) throw new AuthError("session_missing", "Client session is unavailable", 401, false);
      try {
        return await this.api.refresh(sessionReference, this.currentClientKind());
      } catch (error) {
        throw toAuthError(error, "session_expired", "Session refresh failed");
      }
    });
  }

  async me(): Promise<PublicUser | null> {
    if (this.platform === "h5") {
      const fence = this.coordinator.snapshot();
      let user: PublicUser | null;
      try {
        user = await this.api.meWeb();
      } catch (error) {
        throw toAuthError(error, "session_expired", "Session lookup failed");
      }
      if (!this.coordinator.isCurrent(fence)) throw generationMismatch();
      this.cookieUser = user;
      this.cookieAuthenticated = user !== null;
      return user;
    }
    const current = this.sessions.load();
    if (current === null) throw new AuthError("session_missing", "Client session is unavailable", 401, false);
    const fence = this.coordinator.snapshot();
    let user: PublicUser | null;
    try {
      user = await this.api.me(current.sessionReference, this.currentClientKind());
    } catch (error) {
      throw toAuthError(error, "session_expired", "Session lookup failed");
    }
    if (user === null) return null;
    const refreshed = this.coordinator.save({ ...current, user }, fence);
    return refreshed.user ?? null;
  }

  async logout(): Promise<void> {
    const h5 = this.platform === "h5";
    this.flowFence.invalidate();
    this.transactions.clear();
    const current = this.sessions.load();
    const clientKind = this.currentClientKind();
    this.cookieAuthenticated = false;
    this.cookieUser = null;
    try {
      await this.coordinator.logout(async (sessionReference) => {
        try {
          if (h5) await this.api.logoutWeb();
          else if (sessionReference !== null) await this.api.logout(sessionReference, clientKind);
        } catch (error) {
          throw toAuthError(error, "session_expired", "Session logout failed");
        }
      });
    } finally {
      this.cookieAuthenticated = false;
      this.cookieUser = null;
    }
  }

  async bootstrap(): Promise<OpaqueSession | null> {
    if (this.platform !== "h5") return this.sessions.load();
    const fence = this.coordinator.snapshot();
    let user: PublicUser | null;
    try {
      user = await this.api.meWeb();
    } catch (error) {
      throw toAuthError(error, "session_expired", "Session lookup failed");
    }
    if (!this.coordinator.isCurrent(fence)) throw generationMismatch();
    this.cookieAuthenticated = user !== null;
    this.cookieUser = user;
    return null;
  }

  private resolveTransaction(callback: { flowId?: string; state?: string }): PkceTransaction | null {
    if (callback.flowId !== undefined) {
      return this.transactions.load(callback.flowId) ?? this.transactions.loadByServerReference(callback.flowId);
    }
    if (callback.state !== undefined) return this.transactions.loadByState(callback.state);
    return null;
  }

  private assertTransactionActive(transaction: PkceTransaction): void {
    this.flowFence.assertCurrent({ generation: transaction.startGeneration, attempt: transaction.attempt });
  }

  private assertFlowCurrent(fence: { generation: number; attempt: number }): void {
    this.flowFence.assertCurrent(fence);
  }

  private assertCallbackBinding(callback: NormalizedOidcCallback, transaction: PkceTransaction): void {
    const flowMatchesServerReference = callback.flowId !== undefined && (callback.flowId === transaction.serverFlowId || callback.flowId === transaction.serverTransactionId);
    assertCallbackMatchesTransaction(flowMatchesServerReference ? { ...callback, flowId: transaction.flowId } : callback, transaction);
  }

  private consumeTransaction(transaction: PkceTransaction): PkceTransaction | null {
    const consumed = this.transactions.consume(transaction.flowId);
    if (consumed === null || consumed.startGeneration !== transaction.startGeneration || consumed.attempt !== transaction.attempt) return null;
    return consumed;
  }

  private currentClientKind(): "native" | "mp_weixin" | "webview" | undefined {
    return opaqueClientKind(this.sessions.load()?.clientKind) ?? (this.platform === "app" ? "native" : this.platform === "mp-weixin" ? "mp_weixin" : undefined);
  }

  private acceptSession(value: OpaqueSession, expected?: SessionFence): OpaqueSession {
    try {
      return this.coordinator.save(value, expected);
    } catch (error) {
      if (expected === undefined || this.coordinator.isCurrent(expected)) this.sessions.clear();
      throw error;
    }
  }

  private resolveOrigin(webview: boolean, redirectUri: string): string {
    const origin = webview ? getWebviewBridgeOrigin(this.config) : safeOrigin(originFromRedirect(redirectUri));
    const allowed = getConfiguredOrigins(webview ? "app" : "h5", this.config);
    if (webview && !allowed.includes(origin)) throw new AuthError("oidc_origin_mismatch", "OIDC origin is not allowed", 403, false);
    if (!webview && allowed.length > 0 && !allowed.includes(origin)) throw new AuthError("oidc_origin_mismatch", "OIDC origin is not allowed", 403, false);
    return origin;
  }
}

export function createAuthClient(options: AuthClientOptions = {}): AuthClient {
  return new AuthClient(options);
}

function assertStartBinding(start: OidcStartResult, transaction: PkceTransaction, webview: boolean): void {
  if (start.redirectUri !== undefined && start.redirectUri !== transaction.redirectUri) throw new AuthError("invalid_oidc_transaction", "OIDC start redirect does not match the login transaction", 409, false);
  if (!webview && start.state !== transaction.state) throw new AuthError("invalid_oidc_transaction", "OIDC start response does not match the login transaction", 409, false);
  if (!webview && start.flowId !== undefined && start.flowId !== transaction.flowId) throw new AuthError("oidc_flow_mismatch", "OIDC start flow does not match the login transaction", 409, false);
  if (webview && typeof start.state !== "string") throw new AuthError("invalid_oidc_transaction", "OIDC start response has no state", 409, false);
}

function safeOrigin(value: string): string {
  try {
    return normalizeOrigin(value);
  } catch {
    throw new AuthError("oidc_configuration_missing", "OIDC origin is invalid", 500, false);
  }
}

function originFromRedirect(value: string): string {
  try {
    return normalizeOrigin(new URL(value).origin);
  } catch {
    throw new AuthError("oidc_configuration_missing", "OIDC origin is invalid", 500, false);
  }
}

function opaqueClientKind(value: OpaqueClientKind | undefined): "native" | "mp_weixin" | "webview" | undefined {
  return value === "native" || value === "mp_weixin" || value === "webview" ? value : undefined;
}

function generationMismatch(): AuthError {
  return new AuthError("session_generation_mismatch", "Client session changed while the operation was in progress", 409, false);
}
