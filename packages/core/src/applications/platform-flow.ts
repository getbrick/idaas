import {
  ApplicationPlatformError,
  assertRegisteredPlatformRedirectUri,
  toSafeApplicationPlatformError,
  type PlatformIdentity,
} from "./platforms.js";
import { isRfc8252PrivateUseRedirectUri } from "../oidc/redirect-policy.js";
import {
   normalizePlatformLoginBinding,
   normalizePlatformLoginClient,
   assertPlatformLoginReturnTo,
   PlatformLoginStateManager,
   type PlatformLoginBindingInput,
   type PlatformLoginClient,
   type PlatformLoginClientInput,
   type PlatformLoginStateManagerOptions,
  type PlatformLoginStateStore,
} from "./platform-state.js";
import {
   assertPlatformIdentityLinkHostContext,
   createPlaceholderEmail,
   createPlatformIdentityKey,
  DEFAULT_PLATFORM_IDENTITY_TENANT_ID,
  normalizePlatformIdentityLinkingPolicy,
  normalizePlatformIdentityLinkResult,
  projectPlatformIdentity,
  sanitizePlatformIdentity,
  toPublicPlatformIdentity,
  toPublicPlatformUser,
  type PlatformIdentityLinker,
  type PlatformIdentityLinkingPolicy,
  type PlatformIdentityProjection,
  type PlatformPublicUser,
  type SafePlatformIdentity,
} from "./identity-linker.js";
import {
   assertPlatformSessionResponseSafe,
   assertPlatformSessionResultForClient,
   normalizePlatformSessionIssueResult,
  type PlatformSessionIssueInput,
  type PlatformSessionIssueResult,
  type PlatformSessionIssuerBridge,
} from "./session-bridge.js";

export interface PlatformLoginHostContext {
  userId?: string;
  authenticatedUserId?: string;
  identityLinkingPolicy?: PlatformIdentityLinkingPolicy;
  linkingPolicy?: PlatformIdentityLinkingPolicy;
}

export interface PlatformLoginStartInput {
  tenantId?: string;
  applicationId: string;
  platformId: string;
  redirectUri: string;
  returnTo?: string;
  client?: PlatformLoginClientInput;
  clientKind?: PlatformLoginClientInput;
  browser?: PlatformLoginBindingInput;
  binding?: PlatformLoginBindingInput;
  browserId?: string;
  browserBinding?: string;
  sessionId?: string;
  sessionBinding?: string;
  scope?: string;
  identityLinkingPolicy?: PlatformIdentityLinkingPolicy;
  linkingPolicy?: PlatformIdentityLinkingPolicy;
  requestedUserId?: string;
  hostContext?: PlatformLoginHostContext;
}

export interface PlatformLoginCallbackInput {
  tenantId?: string;
  state: string;
  code?: string;
  authorizationCode?: string;
  error?: string | null;
  errorDescription?: string;
  redirectUri?: string;
  applicationId?: string;
  platformId?: string;
  browser?: PlatformLoginBindingInput;
  binding?: PlatformLoginBindingInput;
  browserId?: string;
  browserBinding?: string;
  sessionId?: string;
  sessionBinding?: string;
  hostContext?: PlatformLoginHostContext;
  leaseOwner?: string;
  context?: unknown;
}

export interface PlatformLoginMiniProgramInput {
  tenantId?: string;
  applicationId: string;
  platformId: string;
  code: string;
  redirectUri?: string;
  identityLinkingPolicy?: PlatformIdentityLinkingPolicy;
  linkingPolicy?: PlatformIdentityLinkingPolicy;
  requestedUserId?: string;
  hostContext?: PlatformLoginHostContext;
  context?: unknown;
}

export interface PlatformLoginStartResult {
  authorizationUrl: string;
  state: string;
  expiresAt: string;
  client?: PlatformLoginClient;
}

export interface PlatformLoginResult {
  user: PlatformPublicUser & { id: string };
  identity: Omit<SafePlatformIdentity, "email"> & { email: string | null };
  account: PlatformIdentityProjection["betterAuthAccount"];
  session: PlatformSessionIssueResult;
  returnTo?: string;
  created: boolean;
  linked: boolean;
  client?: PlatformLoginClient | "mini_program";
}

export interface PlatformLoginAuthorizationInput {
  tenantId?: string;
  applicationId: string;
  platformId: string;
  redirectUri: string;
  state: string;
  scope?: string;
  client?: "web" | "native" | "mini_program";
  clientType?: PlatformLoginClientInput;
  clientKind?: PlatformLoginClientInput;
}

export interface PlatformLoginExchangeInput {
  tenantId?: string;
  applicationId: string;
  platformId: string;
  redirectUri?: string;
  code: string;
  client?: "web" | "native" | "mini_program";
  clientType?: PlatformLoginClientInput;
  clientKind?: PlatformLoginClientInput;
}

export interface PlatformLoginFlowOptions {
  tenantId?: string;
  stateStore?: PlatformLoginStateStore;
  stateManager?: PlatformLoginStateManager;
  state?: PlatformLoginStateManagerOptions;
  registeredRedirectUris:
    | readonly string[]
    | ((applicationId: string, platformId: string) => readonly string[] | Promise<readonly string[]>);
  createAuthorizationUrl: (input: PlatformLoginAuthorizationInput) => string | URL | Promise<string | URL>;
  exchangeCode: (input: PlatformLoginExchangeInput) => PlatformIdentity | Promise<PlatformIdentity>;
  identityLinker: PlatformIdentityLinker;
  sessionIssuer: PlatformSessionIssuerBridge;
  onIdentityAuthenticated?: (input: {
    tenantId: string;
    applicationId: string;
    platformId: string;
    identity: SafePlatformIdentity;
    userId: string;
  }) => void | Promise<void>;
  allowRequestedUserId?: boolean;
}

export class PlatformLoginFlow {
  private readonly stateManager: PlatformLoginStateManager;
  private readonly registeredRedirectUris: PlatformLoginFlowOptions["registeredRedirectUris"];
  private readonly createAuthorizationUrl: PlatformLoginFlowOptions["createAuthorizationUrl"];
  private readonly exchangeCode: PlatformLoginFlowOptions["exchangeCode"];
  private readonly identityLinker: PlatformIdentityLinker;
  private readonly sessionIssuer: PlatformSessionIssuerBridge;
  private readonly onIdentityAuthenticated?: PlatformLoginFlowOptions["onIdentityAuthenticated"];
  private readonly allowRequestedUserId: boolean;
  private readonly tenantId: string | undefined;

  constructor(options: PlatformLoginFlowOptions) {
    if (!options || typeof options.createAuthorizationUrl !== "function" || typeof options.exchangeCode !== "function") {
      throw new ApplicationPlatformError("invalid_platform_login_flow", "Platform login flow is invalid");
    }
    if (!options.identityLinker || typeof options.identityLinker.link !== "function") {
      throw new ApplicationPlatformError("invalid_identity_linker", "Platform identity linker is invalid");
    }
    if (!options.sessionIssuer || typeof options.sessionIssuer.issue !== "function") {
      throw new ApplicationPlatformError("invalid_session_issuer", "Platform session issuer is invalid");
    }
    this.stateManager = options.stateManager ?? new PlatformLoginStateManager(
      options.stateStore as PlatformLoginStateStore,
      options.state,
    );
    this.registeredRedirectUris = options.registeredRedirectUris;
    this.createAuthorizationUrl = options.createAuthorizationUrl;
    this.exchangeCode = options.exchangeCode;
    this.identityLinker = options.identityLinker;
    this.sessionIssuer = options.sessionIssuer;
    this.onIdentityAuthenticated = options.onIdentityAuthenticated;
    this.allowRequestedUserId = options.allowRequestedUserId !== false;
    this.tenantId = options.tenantId === undefined ? undefined : assertFlowTenantId(options.tenantId);
  }

  get states(): PlatformLoginStateManager {
    return this.stateManager;
  }

  async startWeb(input: PlatformLoginStartInput): Promise<PlatformLoginStartResult> {
    return this.startWithClient(input, "web");
  }

  async start(input: PlatformLoginStartInput): Promise<PlatformLoginStartResult> {
    return this.startWithClient(input, resolveFlowClientInput(input, "web"));
  }

  async startNative(input: PlatformLoginStartInput): Promise<PlatformLoginStartResult> {
    return this.startWithClient(input, "native");
  }

  async startNativeLogin(input: PlatformLoginStartInput): Promise<PlatformLoginStartResult> {
    return this.startNative(input);
  }

  async startWebview(input: PlatformLoginStartInput): Promise<PlatformLoginStartResult> {
    return this.startWithClient(input, "webview");
  }

  async startWebView(input: PlatformLoginStartInput): Promise<PlatformLoginStartResult> {
    return this.startWebview(input);
  }

  async startWebviewLogin(input: PlatformLoginStartInput): Promise<PlatformLoginStartResult> {
    return this.startWebview(input);
  }

  async handleWebCallback(input: PlatformLoginCallbackInput): Promise<PlatformLoginResult> {
    return this.handleCallback(input);
  }

  async handleCallback(input: PlatformLoginCallbackInput): Promise<PlatformLoginResult> {
    return this.completeState(input, "web");
  }

  async handleWebviewCallback(input: PlatformLoginCallbackInput): Promise<PlatformLoginResult> {
    return this.completeState(input, "webview");
  }

  async handleWebViewCallback(input: PlatformLoginCallbackInput): Promise<PlatformLoginResult> {
    return this.handleWebviewCallback(input);
  }

  async handleWebviewLogin(input: PlatformLoginCallbackInput): Promise<PlatformLoginResult> {
    return this.handleWebviewCallback(input);
  }

  async exchangeNative(input: PlatformLoginCallbackInput): Promise<PlatformLoginResult> {
    return this.completeState(input, "native");
  }

  async exchangeNativeLogin(input: PlatformLoginCallbackInput): Promise<PlatformLoginResult> {
    return this.exchangeNative(input);
  }

  async exchangeWebview(input: PlatformLoginCallbackInput): Promise<PlatformLoginResult> {
    return this.completeState(input, "webview");
  }

  async exchangeWebviewLogin(input: PlatformLoginCallbackInput): Promise<PlatformLoginResult> {
    return this.exchangeWebview(input);
  }

  async exchangeMiniProgram(input: PlatformLoginMiniProgramInput): Promise<PlatformLoginResult> {
    if (!input || typeof input !== "object") {
      throw new ApplicationPlatformError("invalid_platform_request", "Platform login request is invalid");
    }
    rejectCallbackReturnTo(input);
    const tenantId = resolveFlowTenant(this.tenantId, input.tenantId);
    const applicationId = assertFlowIdentifier(input.applicationId, "application");
    const platformId = assertFlowIdentifier(input.platformId, "platform");
    const code = assertProviderCode(input.code);
    const redirectUri = input.redirectUri === undefined ? undefined : assertFlowRedirect(input.redirectUri);
    if (redirectUri !== undefined) {
      const registered = await this.resolveRegisteredRedirectUris(applicationId, platformId);
      assertPlatformRedirectForClient(redirectUri, registered, "mp_weixin");
    }
    const resolved = this.resolvePolicy(input);
    const identity = await this.exchangeProviderIdentity({
      tenantId,
      applicationId,
      platformId,
      redirectUri,
      code,
      client: "mp_weixin",
      clientType: "mp_weixin",
    });
    return this.linkAndIssue({
      tenantId,
      applicationId,
      platformId,
      identity,
      policy: resolved.policy,
      requestedUserId: resolved.requestedUserId,
      client: "mp_weixin",
      clientType: "mp_weixin",
      hostContext: input.hostContext,
      context: input.context,
    });
  }

  async exchangeMini(input: PlatformLoginMiniProgramInput): Promise<PlatformLoginResult> {
    return this.exchangeMiniProgram(input);
  }

  async exchangeMpWeixin(input: PlatformLoginMiniProgramInput): Promise<PlatformLoginResult> {
    return this.exchangeMiniProgram(input);
  }

  async exchangeMpWeixinLogin(input: PlatformLoginMiniProgramInput): Promise<PlatformLoginResult> {
    return this.exchangeMiniProgram(input);
  }

  async exchangeMiniProgramCode(input: PlatformLoginMiniProgramInput): Promise<PlatformLoginResult> {
    return this.exchangeMiniProgram(input);
  }

  async beginLogin(input: PlatformLoginStartInput): Promise<PlatformLoginStartResult> {
    return this.start(input);
  }

  async createLogin(input: PlatformLoginStartInput): Promise<PlatformLoginStartResult> {
    return this.start(input);
  }

  async completeLogin(input: PlatformLoginCallbackInput): Promise<PlatformLoginResult> {
    return this.handleCallback(input);
  }

  async exchangeCallback(input: PlatformLoginCallbackInput): Promise<PlatformLoginResult> {
    return this.handleCallback(input);
  }

  private async startWithClient(input: PlatformLoginStartInput, client: PlatformLoginClient): Promise<PlatformLoginStartResult> {
    if (!input || typeof input !== "object") {
      throw new ApplicationPlatformError("invalid_platform_login_request", "Platform login request is invalid");
    }
    const requestedClient = readFlowClientInput(input);
    if (requestedClient !== undefined && requestedClient !== client) {
      throw new ApplicationPlatformError("invalid_platform_client", "Platform login client does not match the requested flow");
    }
    const tenantId = resolveFlowTenant(this.tenantId, input.tenantId);
    const applicationId = assertFlowIdentifier(input.applicationId, "application");
    const platformId = assertFlowIdentifier(input.platformId, "platform");
    const hasReturnTo = Object.prototype.hasOwnProperty.call(input, "returnTo");
    const returnTo = input.returnTo === undefined ? undefined : assertPlatformLoginReturnTo(input.returnTo);
    if (hasReturnTo && client !== "web") {
      throw new ApplicationPlatformError("invalid_return_to", "Platform login returnTo is only valid for web clients");
    }
    const redirectUri = assertFlowRedirect(input.redirectUri);
    const registered = await this.resolveRegisteredRedirectUris(applicationId, platformId);
    assertPlatformRedirectForClient(redirectUri, registered, client);
    const binding = normalizePlatformLoginBinding({
      browser: input.browser,
      binding: input.binding,
      browserId: input.browserId,
      browserBinding: input.browserBinding,
      sessionId: input.sessionId,
      sessionBinding: input.sessionBinding,
    }, { allowMissingBrowser: client !== "web" });
    if (client === "web" && binding.browserId === undefined) {
      throw new ApplicationPlatformError("invalid_platform_binding", "Platform login browser binding is required");
    }
    const resolved = this.resolvePolicy(input);
    const issued = await this.stateManager.issue({
      ...(tenantId === undefined ? {} : { tenantId }),
      applicationId,
       platformId,
       redirectUri,
       ...(returnTo === undefined ? {} : { returnTo }),
       binding,
      linkingPolicy: resolved.policy,
      ...(resolved.requestedUserId === undefined ? {} : { requestedUserId: resolved.requestedUserId }),
      ...(input.hostContext === undefined ? {} : { hostContext: input.hostContext }),
      ...(input.scope === undefined ? {} : { scope: input.scope }),
      client,
    });
    try {
      const rawUrl = await this.createAuthorizationUrl({
        ...(tenantId === undefined ? {} : { tenantId }),
        applicationId,
        platformId,
        redirectUri,
        state: issued.state,
        ...(client === "native"
          ? { client: "native" as const }
          : client === "webview"
            ? { client: "web" as const }
            : {}),
        clientType: client,
        ...(input.scope === undefined ? {} : { scope: input.scope }),
      });
      const authorizationUrl = assertAuthorizationUrl(rawUrl, issued.state, redirectUri);
      return {
        authorizationUrl,
        state: issued.state,
        expiresAt: new Date(issued.record.expiresAt).toISOString(),
        client,
      };
    } catch (error) {
      await this.stateManager.revoke(issued.state, issued.record.tenantId, issued.record.applicationId);
      throw toSafeApplicationPlatformError(
        error,
        "authorization_url_failed",
        "Platform authorization URL could not be created",
      );
    }
  }

  private async completeState(
    input: PlatformLoginCallbackInput,
    client: PlatformLoginClient,
  ): Promise<PlatformLoginResult> {
    if (!input || typeof input !== "object") {
      throw new ApplicationPlatformError("invalid_platform_callback", "Platform callback is invalid");
    }
    rejectCallbackReturnTo(input);
    const state = assertCallbackState(input.state);
    const tenantId = resolveFlowTenant(this.tenantId, input.tenantId);
    const binding = normalizePlatformLoginBinding({
      browser: input.browser,
      binding: input.binding,
      browserId: input.browserId,
      browserBinding: input.browserBinding,
      sessionId: input.sessionId,
      sessionBinding: input.sessionBinding,
    }, { allowMissingBrowser: client !== "web" });
    if (client === "web" && binding.browserId === undefined) {
      throw new ApplicationPlatformError("invalid_platform_binding", "Platform login browser binding is required");
    }
    const applicationId = input.applicationId === undefined ? undefined : assertFlowIdentifier(input.applicationId, "application");
    const platformId = input.platformId === undefined ? undefined : assertFlowIdentifier(input.platformId, "platform");
    const expectedRedirectUri = input.redirectUri === undefined ? undefined : assertFlowRedirect(input.redirectUri);
    const providerDenied = input.error !== undefined && input.error !== null;
    if (providerDenied && (typeof input.error !== "string" || input.error.trim().length === 0 || input.error.length > 256)) {
      throw new ApplicationPlatformError("invalid_platform_callback", "Platform callback is invalid");
    }
    const code = input.error !== undefined && input.error !== null
      ? undefined
      : input.code ?? input.authorizationCode;
    if (!providerDenied && typeof code !== "string") {
      throw new ApplicationPlatformError("invalid_platform_code", "Platform callback code is invalid");
    }
    const normalizedCode = providerDenied ? "" : assertProviderCode(code);
    const consumeInput = {
      state,
      ...(tenantId === undefined ? {} : { tenantId }),
      binding,
      client,
      ...(expectedRedirectUri === undefined ? {} : { expectedRedirectUri }),
      ...(applicationId === undefined ? {} : { expectedApplicationId: applicationId }),
      ...(platformId === undefined ? {} : { expectedPlatformId: platformId }),
      ...(input.leaseOwner === undefined ? {} : { leaseOwner: input.leaseOwner }),
    };
    if (this.stateManager.canPeek()) {
      const preview = await this.stateManager.peek(consumeInput);
      assertHostAuthorization(preview, input.hostContext);
    }
    const record = await this.stateManager.consume(consumeInput);
    const effectiveTenantId = tenantId ?? record.tenantId;
    assertHostAuthorization(record, input.hostContext);
    const registered = await this.resolveRegisteredRedirectUris(record.applicationId, record.platformId);
    try {
      assertPlatformRedirectForClient(record.redirectUri, registered, client);
    } catch (error) {
      throw toSafeApplicationPlatformError(error, "invalid_redirect_uri", "Platform callback redirect URI is not registered");
    }
    if (providerDenied) {
      throw new ApplicationPlatformError("platform_provider_denied", "Platform provider did not authorize the login");
    }
    const identity = await this.exchangeProviderIdentity({
      tenantId,
      applicationId: record.applicationId,
      platformId: record.platformId,
      redirectUri: record.redirectUri,
      code: normalizedCode,
      client,
      clientType: client,
    });
    const resolved = this.resolvePolicy({
      hostContext: input.hostContext,
      identityLinkingPolicy: record.linkingPolicy,
    });
    return this.linkAndIssue({
      tenantId: effectiveTenantId,
      applicationId: record.applicationId,
      platformId: record.platformId,
      identity,
      policy: resolved.policy,
       requestedUserId: record.requestedUserId,
       client,
       ...(record.returnTo === undefined ? {} : { returnTo: record.returnTo }),
       hostContext: input.hostContext,
      context: input.context,
    });
  }

  private async exchangeProviderIdentity(input: {
    tenantId?: string;
    applicationId: string;
    platformId: string;
    redirectUri?: string;
    code: string;
    client?: PlatformLoginClient;
    clientType?: PlatformLoginClientInput;
  }): Promise<SafePlatformIdentity> {
    try {
      const adapterClient = input.client === "mp_weixin"
        ? "mini_program" as const
        : input.client === "webview"
          ? "web" as const
          : input.client;
      return sanitizePlatformIdentity(await this.exchangeCode({
        ...(input.tenantId === undefined ? {} : { tenantId: input.tenantId }),
        applicationId: input.applicationId,
        platformId: input.platformId,
        ...(input.redirectUri === undefined ? {} : { redirectUri: input.redirectUri }),
        code: input.code,
        ...(adapterClient === "native" || adapterClient === "mini_program" ? { client: adapterClient } : {}),
        ...(input.client === "webview" || input.client === "mp_weixin" ? { clientType: input.client } : {}),
      }));
    } catch (error) {
      throw toSafeApplicationPlatformError(
        error,
        "platform_exchange_failed",
        "Platform authorization code exchange failed",
      );
    }
  }

  private async linkAndIssue(input: {
    tenantId?: string;
    applicationId: string;
    platformId: string;
    identity: SafePlatformIdentity;
    policy: PlatformIdentityLinkingPolicy;
    requestedUserId?: string;
    client: PlatformLoginClient;
    returnTo?: string;
    clientType?: PlatformLoginClientInput;
    hostContext?: PlatformLoginHostContext;
    context?: unknown;
  }): Promise<PlatformLoginResult> {
    const returnTo = input.returnTo === undefined ? undefined : assertPlatformLoginReturnTo(input.returnTo);
    if (returnTo !== undefined && input.client !== "web") {
      throw new ApplicationPlatformError("invalid_return_to", "Platform login returnTo is only valid for web clients");
    }
    const scope = {
      tenantId: input.tenantId ?? DEFAULT_PLATFORM_IDENTITY_TENANT_ID,
      applicationId: input.applicationId,
    };
    const identityKey = createPlatformIdentityKey(input.identity, scope);
    const projection = projectPlatformIdentity(input.identity, identityKey, scope);
    let linked: ReturnType<typeof normalizePlatformIdentityLinkResult>;
    try {
      linked = normalizePlatformIdentityLinkResult(await this.identityLinker.link({
        ...(input.tenantId === undefined ? {} : { tenantId: input.tenantId }),
        applicationId: input.applicationId,
        platformId: input.platformId,
        identity: input.identity,
        identityKey,
        projection,
        policy: input.policy,
        ...(input.requestedUserId === undefined ? {} : { requestedUserId: input.requestedUserId }),
        ...(input.hostContext === undefined ? {} : { hostContext: input.hostContext }),
      }));
    } catch (error) {
      throw toSafeApplicationPlatformError(error, "identity_linking_failed", "Platform identity linking failed");
    }
    const userId = assertFlowIdentifier(linked.userId, "user");
    const policyTargetUserId = typeof input.policy === "object" ? input.policy.userId : undefined;
    const expectedUserId = input.requestedUserId ?? policyTargetUserId;
    if (expectedUserId !== undefined && userId !== expectedUserId) {
      throw new ApplicationPlatformError("identity_link_target_mismatch", "Platform identity linked to an unexpected user");
    }
    if (linked.user?.id !== undefined && linked.user.id !== userId) {
      throw new ApplicationPlatformError("identity_link_target_mismatch", "Platform identity linker returned an inconsistent user");
    }
    const canonicalUser = linked.user ?? projection.publicUser;
    const publicUser: PlatformPublicUser & { id: string } = {
      ...toPublicPlatformUser(projection, userId),
      ...canonicalUser,
      id: userId,
    };
    const canonicalAccount = linked.account ?? (linked.accountId === undefined
      ? projection.betterAuthAccount
      : { ...projection.betterAuthAccount, accountId: linked.accountId });
    const canonicalBetterAuthUser = {
      name: publicUser.name,
      email: publicUser.email ?? createPlaceholderEmail(projection.identityKey),
      emailVerified: publicUser.emailVerified,
      ...(typeof publicUser.image === "string" ? { image: publicUser.image } : {}),
    };
    const canonicalProjection: PlatformIdentityProjection = {
      ...projection,
      publicUser,
      betterAuthUser: canonicalBetterAuthUser,
      betterAuthAccount: canonicalAccount,
      betterAuth: {
        user: canonicalBetterAuthUser,
        account: canonicalAccount,
      },
    };
    const sessionInput: PlatformSessionIssueInput = {
      ...(input.tenantId === undefined ? {} : { tenantId: input.tenantId }),
      applicationId: input.applicationId,
      platformId: input.platformId,
      userId,
      user: publicUser,
      identity: input.identity,
      projection: canonicalProjection,
      ...(linked.account !== undefined || linked.accountId !== undefined ? { account: canonicalAccount } : {}),
      client: input.client,
      ...(input.context === undefined ? {} : { context: input.context }),
      created: linked.created === true,
      linked: linked.linked === true,
    };
    let session: PlatformSessionIssueResult;
    try {
      session = normalizePlatformSessionIssueResult(await this.sessionIssuer.issue(sessionInput));
    } catch (error) {
      throw toSafeApplicationPlatformError(error, "session_issue_failed", "Platform session could not be issued");
    }
    if (session.response === undefined && session.sessionReference === undefined) {
      throw new ApplicationPlatformError("invalid_session_issuer_result", "Platform session issuer did not return a host session");
    }
    assertPlatformSessionResultForClient(session, input.client);
    if (session.user !== undefined) session = { ...session, user: publicUser };
    if (session.response !== undefined) {
      try {
        await assertPlatformSessionResponseSafe(session.response);
      } catch (error) {
        throw toSafeApplicationPlatformError(error, "session_issue_failed", "Platform session could not be issued");
      }
    }
    if (this.onIdentityAuthenticated !== undefined) {
      try {
        await this.onIdentityAuthenticated({
          tenantId: scope.tenantId,
          applicationId: input.applicationId,
          platformId: input.platformId,
          identity: input.identity,
          userId,
        });
      } catch (error) {
        throw toSafeApplicationPlatformError(error, "identity_persistence_failed", "Platform identity could not be persisted");
      }
    }
    return {
      user: publicUser,
      identity: toPublicPlatformIdentity(input.identity),
      account: canonicalAccount,
      session,
      ...(returnTo === undefined ? {} : { returnTo }),
      created: linked.created === true,
      linked: linked.linked === true,
      client: input.client,
    };
  }

  private resolvePolicy(input: {
    identityLinkingPolicy?: PlatformIdentityLinkingPolicy;
    linkingPolicy?: PlatformIdentityLinkingPolicy;
    requestedUserId?: string;
    hostContext?: PlatformLoginHostContext;
  }): { policy: PlatformIdentityLinkingPolicy; requestedUserId?: string } {
    const inputPolicy = input.identityLinkingPolicy ?? input.linkingPolicy;
    const hostPolicy = input.hostContext?.identityLinkingPolicy ?? input.hostContext?.linkingPolicy;
    if (inputPolicy !== undefined && hostPolicy !== undefined) {
      const inputNormalized = normalizePlatformIdentityLinkingPolicy(inputPolicy);
      const hostNormalized = normalizePlatformIdentityLinkingPolicy(hostPolicy);
      if (inputNormalized.mode !== hostNormalized.mode || inputNormalized.userId !== hostNormalized.userId) {
        throw new ApplicationPlatformError("invalid_host_context", "Platform host context is inconsistent");
      }
    }
    const hostUserId = resolvePlatformLoginHostUserId(input.hostContext);
    const policy = hostPolicy !== undefined
      ? normalizePlatformIdentityLinkingPolicy(hostPolicy)
      : inputPolicy === undefined && hostUserId !== undefined
        ? { mode: "link_existing" as const, userId: hostUserId }
        : normalizePlatformIdentityLinkingPolicy(inputPolicy);
    const inputRequested = input.requestedUserId;
    if (inputRequested !== undefined && hostUserId !== undefined && inputRequested !== hostUserId) {
      throw new ApplicationPlatformError("invalid_host_context", "Platform host context is inconsistent");
    }
    if (inputRequested !== undefined && !this.allowRequestedUserId && hostUserId === undefined) {
      throw new ApplicationPlatformError("identity_link_authorization_required", "Explicit account linking requires host authorization");
    }
    if (inputPolicy !== undefined && !this.allowRequestedUserId && typeof inputPolicy === "object" && inputPolicy.userId !== undefined && hostUserId === undefined) {
      throw new ApplicationPlatformError("identity_link_authorization_required", "Explicit account linking requires host authorization");
    }
    const requestedUserId = inputRequested ?? policy.userId ?? hostUserId;
    if (requestedUserId !== undefined && policy.mode !== "link_existing") {
      throw new ApplicationPlatformError("invalid_identity_linking_policy", "Only explicit account linking accepts a user target");
    }
    assertPlatformIdentityLinkHostContext(policy, requestedUserId, input.hostContext);
    return {
      policy,
      ...(requestedUserId === undefined ? {} : { requestedUserId }),
    };
  }

  private async resolveRegisteredRedirectUris(applicationId: string, platformId: string): Promise<readonly string[]> {
    try {
      const value = typeof this.registeredRedirectUris === "function"
        ? await this.registeredRedirectUris(applicationId, platformId)
        : this.registeredRedirectUris;
      if (!Array.isArray(value) || value.length === 0) {
        throw new ApplicationPlatformError("invalid_redirect_uri", "Platform callback redirect URI is not registered");
      }
      return value;
    } catch (error) {
      throw toSafeApplicationPlatformError(error, "platform_unavailable", "Application platform is unavailable");
    }
  }
}

export function createPlatformLoginFlow(options: PlatformLoginFlowOptions): PlatformLoginFlow {
  return new PlatformLoginFlow(options);
}

function rejectCallbackReturnTo(input: object): void {
  if (Object.prototype.hasOwnProperty.call(input, "returnTo") || Object.prototype.hasOwnProperty.call(input, "return_to")) {
    throw new ApplicationPlatformError("invalid_platform_callback", "Platform callback cannot select returnTo");
  }
}

function assertHostAuthorization(record: { requestedUserId?: string; linkingPolicy: PlatformIdentityLinkingPolicy }, context: PlatformLoginHostContext | undefined): void {
  const policy = normalizePlatformIdentityLinkingPolicy(record.linkingPolicy);
  assertPlatformIdentityLinkHostContext(policy, record.requestedUserId ?? policy.userId, context);
}

function resolvePlatformLoginHostUserId(context: PlatformLoginHostContext | undefined): string | undefined {
  if (context === undefined) return undefined;
  if (context.userId !== undefined && context.authenticatedUserId !== undefined && context.userId !== context.authenticatedUserId) {
    throw new ApplicationPlatformError("invalid_host_context", "Platform host context is inconsistent");
  }
  const value = context.userId ?? context.authenticatedUserId;
  if (value === undefined) return undefined;
  if (typeof value !== "string" || value.trim().length === 0 || value.length > 256 || /[\u0000-\u001f\u007f]/u.test(value)) {
    throw new ApplicationPlatformError("invalid_host_context", "Platform host context is invalid");
  }
  return value.trim();
}

function assertAuthorizationUrl(value: unknown, state: string, redirectUri?: string): string {
  let parsed: URL;
  try {
    parsed = new URL(value instanceof URL ? value.toString() : String(value));
  } catch {
    throw new ApplicationPlatformError("authorization_url_failed", "Platform authorization URL is invalid");
  }
  if (
    value === undefined ||
    value === null ||
    (parsed.protocol !== "https:" && parsed.protocol !== "http:") ||
    (parsed.protocol !== "https:" && !isLoopbackHost(parsed.hostname)) ||
    parsed.username !== "" ||
    parsed.password !== "" ||
    parsed.hostname.length === 0 ||
    parsed.toString().length > 4096 ||
    /[\u0000-\u001f\u007f]/u.test(parsed.toString())
  ) {
    throw new ApplicationPlatformError("authorization_url_failed", "Platform authorization URL is invalid");
  }
  for (const key of parsed.searchParams.keys()) {
    const normalizedKey = key.toLowerCase().replace(/[^a-z0-9]/gu, "");
    if (
      normalizedKey === "accesstoken" ||
      normalizedKey === "refreshtoken" ||
      normalizedKey === "idtoken" ||
      normalizedKey === "sessionkey" ||
      normalizedKey === "secret" ||
      normalizedKey === "clientsecret" ||
      normalizedKey === "password" ||
      normalizedKey === "code"
    ) {
      throw new ApplicationPlatformError("authorization_url_failed", "Platform authorization URL contained a forbidden secret");
    }
  }
  if (parsed.searchParams.getAll("state").length !== 1) {
    throw new ApplicationPlatformError("authorization_url_failed", "Platform authorization URL did not preserve login state");
  }
  if (parsed.searchParams.get("state") !== state) {
    throw new ApplicationPlatformError("authorization_url_failed", "Platform authorization URL did not preserve login state");
  }
  if (redirectUri !== undefined) {
    const redirectValues = parsed.searchParams.getAll("redirect_uri");
    if (redirectValues.length > 1 || (redirectValues.length === 1 && redirectValues[0] !== redirectUri)) {
      throw new ApplicationPlatformError("authorization_url_failed", "Platform authorization URL did not preserve the registered redirect URI");
    }
  }
  return parsed.toString();
}

function assertPlatformRedirectForClient(
  redirectUri: string,
  registered: readonly string[],
  client: PlatformLoginClient,
): string {
  if (client === "web" || client === "webview") return assertRegisteredPlatformRedirectUri(redirectUri, registered);
  if (!Array.isArray(registered) || !registered.includes(redirectUri)) {
    throw new ApplicationPlatformError("invalid_redirect_uri", "Platform callback redirect URI is not registered");
  }
  let parsed: URL;
  try {
    parsed = new URL(redirectUri);
  } catch {
    throw new ApplicationPlatformError("invalid_redirect_uri", "Platform callback redirect URI is invalid");
  }
  if (
    parsed.username !== "" ||
    parsed.password !== "" ||
    parsed.hash !== "" ||
    /[\u0000-\u001f\u007f\s\\]/u.test(redirectUri)
  ) {
    throw new ApplicationPlatformError("invalid_redirect_uri", "Platform callback redirect URI is invalid");
  }
  if (parsed.protocol === "http:") {
    if (parsed.hostname.length === 0 || !isLoopbackHost(parsed.hostname)) {
      throw new ApplicationPlatformError("invalid_redirect_uri", "Platform callback redirect URI is invalid");
    }
    return redirectUri;
  }
  if (parsed.protocol === "https:") {
    if (parsed.hostname.length === 0 || isLoopbackHost(parsed.hostname)) {
      throw new ApplicationPlatformError("invalid_redirect_uri", "Platform callback redirect URI is invalid");
    }
    return redirectUri;
  }
  if (!isRfc8252PrivateUseRedirectUri(redirectUri)) {
    throw new ApplicationPlatformError("invalid_redirect_uri", "Platform callback redirect URI is invalid");
  }
  return redirectUri;
}

function assertProviderCode(value: unknown): string {
  if (typeof value !== "string") {
    throw new ApplicationPlatformError("invalid_platform_code", "Platform callback code is invalid");
  }
  const normalized = value.trim();
  if (normalized.length === 0 || normalized.length > 512 || /[\u0000-\u001f\u007f\s]/u.test(normalized)) {
    throw new ApplicationPlatformError("invalid_platform_code", "Platform callback code is invalid");
  }
  return normalized;
}

function assertCallbackState(value: unknown): string {
  if (typeof value !== "string" || value.length < 32 || value.length > 512 || !/^[A-Za-z0-9_-]+$/u.test(value)) {
    throw new ApplicationPlatformError("invalid_platform_state", "Platform login state is invalid");
  }
  return value;
}

function readFlowClientInput(input: { client?: unknown; clientKind?: unknown }): PlatformLoginClient | undefined {
  const client = input.client;
  const clientKind = input.clientKind;
  if (client === null || clientKind === null) {
    throw new ApplicationPlatformError("invalid_platform_client", "Platform login client is invalid");
  }
  const clientValue = client === undefined ? clientKind : client;
  const normalized = clientValue === undefined ? undefined : normalizePlatformLoginClient(clientValue);
  if (client !== undefined && clientKind !== undefined && normalizePlatformLoginClient(client) !== normalized) {
    throw new ApplicationPlatformError("invalid_platform_client", "Platform login client aliases conflict");
  }
  return normalized;
}

function resolveFlowClientInput(
  input: { client?: unknown; clientKind?: unknown },
  fallback: PlatformLoginClient,
): PlatformLoginClient {
  return readFlowClientInput(input) ?? fallback;
}

function resolveFlowTenant(configured: string | undefined, supplied: string | undefined): string | undefined {
  const value = configured ?? supplied;
  return value === undefined ? undefined : assertFlowTenantId(value);
}

function assertFlowTenantId(value: unknown): string {
  if (typeof value !== "string") {
    throw new ApplicationPlatformError("invalid_platform_identifier", "Platform tenant identifier is invalid");
  }
  const normalized = value.trim();
  if (normalized.length === 0 || normalized.length > 256 || /[:\u0000-\u001f\u007f]/u.test(normalized)) {
    throw new ApplicationPlatformError("invalid_platform_identifier", "Platform tenant identifier is invalid");
  }
  return normalized;
}

function assertFlowIdentifier(value: unknown, field: string): string {
  if (typeof value !== "string") {
    throw new ApplicationPlatformError("invalid_platform_identifier", `Platform ${field} identifier is invalid`);
  }
  const normalized = value.trim();
  if (normalized.length === 0 || normalized.length > 256 || /[\u0000-\u001f\u007f]/u.test(normalized)) {
    throw new ApplicationPlatformError("invalid_platform_identifier", `Platform ${field} identifier is invalid`);
  }
  return normalized;
}

function assertFlowRedirect(value: unknown): string {
  if (typeof value !== "string") {
    throw new ApplicationPlatformError("invalid_redirect_uri", "Platform callback redirect URI is invalid");
  }
  const normalized = value.trim();
  if (normalized.length === 0 || normalized.length > 2048 || /[\u0000-\u001f\u007f\s]/u.test(normalized)) {
    throw new ApplicationPlatformError("invalid_redirect_uri", "Platform callback redirect URI is invalid");
  }
  return normalized;
}

function isLoopbackHost(hostname: string): boolean {
  return hostname === "localhost" || hostname === "127.0.0.1" || hostname === "[::1]";
}
