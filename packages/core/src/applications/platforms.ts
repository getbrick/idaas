import { isRfc8252PrivateUseRedirectUri } from "../oidc/redirect-policy.js";

export type ApplicationPlatformType =
  | "web"
  | "wechat_official_account"
  | "wechat_open_platform"
  | "wechat_mini_program"
  | "alipay_mini_program"
  | "douyin_mini_program"
  | "qq_mini_program"
  | "baidu_mini_program"
  | "feishu_mini_program"
  | "mini_program"
  | (string & {});

export interface PlatformFetchInit {
  method?: string;
  headers?: Record<string, string>;
  body?: string;
  signal?: AbortSignal;
}

export type PlatformFetch = (input: string, init?: PlatformFetchInit) => Promise<Response>;

export interface PlatformIdentity {
  provider: string;
  platform: string;
  appId: string;
  subject: string;
  openid?: string;
  unionid?: string;
  nickname?: string;
  avatarUrl?: string;
  email?: string;
  emailVerified?: boolean;
  scopes: string[];
}

export interface ApplicationPlatformAuthorizationInput {
  appId: string;
  redirectUri: string;
  state: string;
  scope?: string;
  client?: "web" | "native";
}

export interface ApplicationPlatformCodeExchangeInput {
  appId: string;
  appSecret?: string;
  code: string;
  redirectUri?: string;
  client?: "web" | "native" | "mini_program";
  scope?: string;
  componentAppId?: string;
  authorizedAppId?: string;
}

export interface ApplicationPlatformAuthAdapter {
  readonly type: ApplicationPlatformType;
  readonly supportsAuthorization: boolean;
  createAuthorizationUrl(input: ApplicationPlatformAuthorizationInput): string;
  exchangeCode(input: ApplicationPlatformCodeExchangeInput): Promise<PlatformIdentity>;
}

export const WECHAT_OFFICIAL_ACCOUNT_SCOPES = ["snsapi_base", "snsapi_userinfo"] as const;
export const WECHAT_OPEN_PLATFORM_SCOPES = ["snsapi_login"] as const;
export type WechatOfficialAccountScope = (typeof WECHAT_OFFICIAL_ACCOUNT_SCOPES)[number];
export type WechatOpenPlatformScope = (typeof WECHAT_OPEN_PLATFORM_SCOPES)[number];

export interface WechatPlatformEndpoints {
  officialAuthorizationUrl: string;
  openPlatformAuthorizationUrl: string;
  accessTokenUrl: string;
  userInfoUrl: string;
  miniProgramSessionUrl: string;
}

export interface WechatComponentEndpoints {
  componentAccessTokenUrl: string;
  authorizerAccessTokenUrl: string;
  authorizerInfoUrl: string;
  authorizedAccountListUrl: string;
  componentOAuthAccessTokenUrl?: string;
  componentOAuthRefreshTokenUrl?: string;
  componentAuthorizationInfoUrl?: string;
}

type ResolvedWechatComponentEndpoints = WechatComponentEndpoints & {
  componentOAuthAccessTokenUrl: string;
  componentOAuthRefreshTokenUrl: string;
  componentAuthorizationInfoUrl: string;
};

export interface WechatComponentAccessTokenResolverInput {
  componentAppId: string;
  authorizedAppId: string;
  appId?: string;
  authorizerAppId?: string;
}

export interface WechatComponentAccessTokenResolution {
  accessToken?: string;
  componentAccessToken?: string;
  component_access_token?: string;
  token?: string;
  expiresIn?: number;
  expires_in?: number;
}

export type WechatComponentAccessTokenResolverResult = string | WechatComponentAccessTokenResolution;

export type WechatComponentAccessTokenResolver = (
  input: WechatComponentAccessTokenResolverInput,
) => WechatComponentAccessTokenResolverResult | Promise<WechatComponentAccessTokenResolverResult>;

export interface WechatComponentAccessTokenResolverObject {
  resolve?: WechatComponentAccessTokenResolver;
  getComponentAccessToken?: WechatComponentAccessTokenResolver;
}

export interface WechatComponentAppIdResolverInput {
  componentAppId: string;
}

export type WechatComponentAppIdResolver = (
  input: WechatComponentAppIdResolverInput,
) => WechatComponentAccessTokenResolverResult | Promise<WechatComponentAccessTokenResolverResult>;

export type WechatComponentAccessTokenResolverLike =
  | WechatComponentAccessTokenResolver
  | WechatComponentAppIdResolver
  | WechatComponentAccessTokenResolverObject;

export type WechatComponentTokenResolver = WechatComponentAccessTokenResolverLike;

export type WechatComponentSecretSource = string | (() => string | Promise<string>);

export interface WechatComponentAccessTokenResolverOptions {
  componentAppId?: string;
  component_appid?: string;
  componentAppSecret?: WechatComponentSecretSource;
  component_appsecret?: WechatComponentSecretSource;
  component_app_secret?: WechatComponentSecretSource;
  componentVerifyTicket?: WechatComponentSecretSource;
  component_verify_ticket?: WechatComponentSecretSource;
  endpoint?: string;
  fetch?: PlatformFetch;
  allowInsecureEndpoint?: boolean;
}

export interface WechatComponentAccountBinding {
  componentAppId?: string;
  component_appid?: string;
  authorizedAppId?: string;
  authorized_appid?: string;
  authorizerAppId?: string;
  authorizer_appid?: string;
  appId?: string;
  appSecret?: string;
  app_secret?: string;
  authorizerRefreshToken?: string;
  authorizer_refresh_token?: string;
  refreshToken?: string;
  refresh_token?: string;
}

export type WechatComponentAuthorizedAccountBinding = WechatComponentAccountBinding;
export type WechatComponentBinding = WechatComponentAccountBinding;
export type WechatAuthorizedAccountBinding = WechatComponentAccountBinding;

export type WechatComponentAccountBindingInput = WechatComponentAccountBinding;

export type WechatComponentAccountBindingCollection =
  | readonly WechatComponentAccountBindingInput[]
  | Readonly<Record<string, WechatComponentAccountBindingInput>>
  | ReadonlyMap<string, WechatComponentAccountBindingInput>;

export interface WechatComponentBindingResolverInput {
  componentAppId: string;
  authorizedAppId: string;
  appId?: string;
  authorizerAppId?: string;
}

export type WechatComponentBindingResolver = (
  input: WechatComponentBindingResolverInput,
) => WechatComponentAccountBindingInput | undefined | null | Promise<WechatComponentAccountBindingInput | undefined | null>;

export interface WechatComponentBindingResolverObject {
  resolve: WechatComponentBindingResolver;
}

export type WechatComponentBindingResolverLike =
  | WechatComponentBindingResolver
  | WechatComponentBindingResolverObject;

export interface WechatApplicationSecretResolverInput {
  appId: string;
  platform: "wechat_official_account" | "wechat_open_platform" | "wechat_mini_program" | "wechat_component";
  componentAppId?: string;
  authorizedAppId?: string;
}

export type WechatApplicationSecretResolver = (
  input: WechatApplicationSecretResolverInput,
) => string | Promise<string>;

export interface WechatComponentAdapterOptions extends WechatPlatformAdapterOptions {
  componentAppId?: string;
}

export type WechatComponentProviderOptions = WechatComponentAdapterOptions;

export interface WechatPlatformAdapterOptions {
  fetch?: PlatformFetch;
  allowInsecureRedirectUris?: boolean;
  allowInsecureEndpoints?: boolean;
  endpoints?: Partial<WechatPlatformEndpoints>;
  componentEndpoints?: Partial<WechatComponentEndpoints>;
  componentAppId?: string;
  component_appid?: string;
  componentAccessTokenResolver?: WechatComponentAccessTokenResolverLike;
  component_access_token_resolver?: WechatComponentAccessTokenResolverLike;
  resolveComponentAccessToken?: WechatComponentAccessTokenResolverLike;
  componentTokenResolver?: WechatComponentAccessTokenResolverLike;
  componentAccessToken?: string | (() => string | Promise<string>);
  component_access_token?: string | (() => string | Promise<string>);
  bindings?: WechatComponentAccountBindingCollection;
  authorizedAccounts?: WechatComponentAccountBindingCollection;
  authorized_accounts?: WechatComponentAccountBindingCollection;
  authorizedAccountBindings?: WechatComponentAccountBindingCollection;
  account_bindings?: WechatComponentAccountBindingCollection;
  accounts?: WechatComponentAccountBindingCollection;
  resolveBinding?: WechatComponentBindingResolverLike;
  resolveAuthorizedAccount?: WechatComponentBindingResolverLike;
  resolveAuthorizedAccountBinding?: WechatComponentBindingResolverLike;
  resolve_binding?: WechatComponentBindingResolverLike;
  appSecretResolver?: WechatApplicationSecretResolver;
  resolveAppSecret?: WechatApplicationSecretResolver;
  resolveSecret?: WechatApplicationSecretResolver;
  requireAuthorizedAccountBinding?: boolean;
  allowUnboundAuthorizedAccount?: boolean;
  componentPlatformType?: "wechat_official_account" | "wechat_open_platform";
}

export interface GenericMiniProgramAdapterOptions {
  type: ApplicationPlatformType;
  endpoint: string;
  fetch?: PlatformFetch;
  allowInsecureEndpoint?: boolean;
  mapResponse: (payload: unknown, context: { appId: string; code: string }) => GenericMiniProgramIdentityInput;
}

export interface GenericMiniProgramIdentityInput {
  subject: string;
  openid?: string;
  unionid?: string;
  nickname?: string;
  avatarUrl?: string;
  email?: string;
  emailVerified?: boolean;
  scopes?: string[];
}

export class ApplicationPlatformError extends Error {
  readonly code: string;
  readonly statusCode?: number;
  declare readonly providerUrl?: string;

  constructor(code: string, message: string, statusCode?: number, providerUrl?: string) {
    super(message);
    this.name = "ApplicationPlatformError";
    this.code = code;
    this.statusCode = statusCode;
    if (providerUrl !== undefined) {
      Object.defineProperty(this, "providerUrl", { value: providerUrl, enumerable: false });
    }
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

export function assertRegisteredPlatformRedirectUri(
  redirectUri: unknown,
  registeredRedirectUris: readonly unknown[] | undefined,
): string {
  if (typeof redirectUri !== "string" || redirectUri.length === 0 || redirectUri.length > 2048) {
    throw new ApplicationPlatformError("invalid_redirect_uri", "Platform redirect URI is invalid");
  }
  if (!Array.isArray(registeredRedirectUris) || registeredRedirectUris.length === 0) {
    throw new ApplicationPlatformError("invalid_redirect_uri", "Redirect URI is not registered for the application platform");
  }
  let parsed: URL;
  try {
    parsed = new URL(redirectUri);
  } catch {
    throw new ApplicationPlatformError("invalid_redirect_uri", "Platform redirect URI is invalid");
  }
  if (
    (parsed.protocol !== "https:" && parsed.protocol !== "http:") ||
    (parsed.protocol !== "https:" && !isLoopbackHost(parsed.hostname)) ||
     parsed.username !== "" ||
     parsed.password !== "" ||
     parsed.hash !== "" ||
     parsed.hostname.length === 0 ||
     /[\u0000-\u001f\u007f\s]/u.test(redirectUri) ||
     hasUnsafeRedirectText(redirectUri)


  ) {
    throw new ApplicationPlatformError("invalid_redirect_uri", "Platform redirect URI is invalid");
  }
  assertRedirectQueryIsSafe(parsed);
  const match = registeredRedirectUris.find((value) => value === redirectUri);
  if (match === undefined) {
    throw new ApplicationPlatformError("invalid_redirect_uri", "Redirect URI is not registered for the application platform");
  }
  return match;
}

export const isRegisteredPlatformRedirectUri = (
  redirectUri: unknown,
  registeredRedirectUris: readonly unknown[] | undefined,
): boolean => {
  try {
    assertRegisteredPlatformRedirectUri(redirectUri, registeredRedirectUris);
    return true;
  } catch {
    return false;
  }
};

export function toSafeApplicationPlatformError(
  error: unknown,
  fallbackCode = "platform_operation_failed",
  fallbackMessage = "Application platform operation failed",
): ApplicationPlatformError {
  if (error instanceof ApplicationPlatformError) {
    const code = typeof error.code === "string" && /^[a-z][a-z0-9_]{0,63}$/u.test(error.code)
      ? error.code
      : fallbackCode;
    const message = safePlatformErrorMessage(code) ?? fallbackMessage;
    const statusCode = typeof error.statusCode === "number" &&
      Number.isInteger(error.statusCode) &&
      error.statusCode >= 100 &&
      error.statusCode <= 599
      ? error.statusCode
      : undefined;
    return new ApplicationPlatformError(code, message, statusCode);
  }
  return new ApplicationPlatformError(fallbackCode, fallbackMessage);
}

export function normalizeWechatProviderError(error: unknown): ApplicationPlatformError {
  return toSafeApplicationPlatformError(
    error,
    "provider_error",
    "Platform provider request failed",
  );
}

export class ApplicationPlatformAdapterRegistry {
  private readonly adapters = new Map<string, ApplicationPlatformAuthAdapter>();

  register(adapter: ApplicationPlatformAuthAdapter): this {
    if (!adapter || typeof adapter.type !== "string" || adapter.type.length === 0) {
      throw new ApplicationPlatformError("invalid_adapter", "Invalid application platform adapter");
    }
    this.adapters.set(adapter.type, adapter);
    return this;
  }

  get(type: string): ApplicationPlatformAuthAdapter | undefined {
    return this.adapters.get(type);
  }

  has(type: string): boolean {
    return this.adapters.has(type);
  }

  list(): ApplicationPlatformAuthAdapter[] {
    return [...this.adapters.values()];
  }
}

export const WECHAT_ENDPOINTS: WechatPlatformEndpoints = {
  officialAuthorizationUrl: "https://open.weixin.qq.com/connect/oauth2/authorize",
  openPlatformAuthorizationUrl: "https://open.weixin.qq.com/connect/qrconnect",
  accessTokenUrl: "https://api.weixin.qq.com/sns/oauth2/access_token",
  userInfoUrl: "https://api.weixin.qq.com/sns/userinfo",
  miniProgramSessionUrl: "https://api.weixin.qq.com/sns/jscode2session",
};

export const WECHAT_COMPONENT_ENDPOINTS = {
  componentAccessTokenUrl: "https://api.weixin.qq.com/cgi-bin/component/api_component_token",
  authorizerAccessTokenUrl: "https://api.weixin.qq.com/cgi-bin/component/api_authorizer_token",
  authorizerInfoUrl: "https://api.weixin.qq.com/cgi-bin/component/api_get_authorizer_info",
  authorizedAccountListUrl: "https://api.weixin.qq.com/cgi-bin/component/api_get_authorized_appinfo",
  componentOAuthAccessTokenUrl: "https://api.weixin.qq.com/sns/oauth2/component/access_token",
  componentOAuthRefreshTokenUrl: "https://api.weixin.qq.com/sns/oauth2/component/refresh_token",
  componentAuthorizationInfoUrl: "https://api.weixin.qq.com/cgi-bin/component/api_query_auth",
};

export interface WechatComponentTokenMetadata {
  componentAppId: string;
  authorizedAppId: string;
  expiresIn?: number;
}

export interface WechatComponentAccountStatus {
  componentAppId: string;
  authorizedAppId: string;
  bound: boolean;
  hasAppSecret: boolean;
  hasAuthorizerRefreshToken: boolean;
}

export interface WechatComponentProvider extends ApplicationPlatformAuthAdapter {
  readonly type: ApplicationPlatformType;
  readonly supportsAuthorization: true;
  readonly componentAppId: string;
  bindAuthorizedAccount(binding: WechatComponentAccountBindingInput): void;
  unbindAuthorizedAccount(authorizedAppId: string): boolean;
  listAuthorizedAccounts(): string[];
  hasAuthorizedAccount(authorizedAppId: string): boolean;
  getAuthorizedAccount(authorizedAppId: string): Promise<WechatComponentAccountStatus>;
  toJSON(): {
    type: ApplicationPlatformType;
    componentAppId: string;
    authorizedAppIds: string[];
  };
  resolveComponentAccessToken(
    input: string | { authorizedAppId: string },
  ): Promise<string>;
  withComponentAccessToken<T>(
    authorizedAppId: string,
    operation: (accessToken: string) => T | Promise<T>,
  ): Promise<T>;
  getAuthorizerAccessToken(authorizedAppId: string): Promise<WechatComponentTokenMetadata>;
  withAuthorizerAccessToken<T>(
    authorizedAppId: string,
    operation: (accessToken: string) => T | Promise<T>,
  ): Promise<T>;
}

interface NormalizedWechatComponentBinding {
  componentAppId: string;
  authorizedAppId: string;
  appSecret?: string;
  authorizerRefreshToken?: string;
}

export class WechatComponentProviderAdapter implements WechatComponentProvider {
  readonly type: "wechat_official_account" | "wechat_open_platform";
  readonly supportsAuthorization = true as const;
  readonly componentAppId: string;
  private readonly bindings = new Map<string, NormalizedWechatComponentBinding>();
  private readonly bindingResolvers: WechatComponentBindingResolverLike | undefined;
  private readonly componentAccessTokenInFlight = new Map<string, Promise<string>>();
  private readonly authorizerAccessTokenInFlight = new Map<string, Promise<{ token: string; metadata: WechatComponentTokenMetadata }>>();
  private readonly componentAccessTokenResolver: WechatComponentAccessTokenResolverLike | undefined;
  private readonly componentAccessToken: string | (() => string | Promise<string>) | undefined;
  private readonly appSecretResolver: WechatApplicationSecretResolver | undefined;
  private readonly platformEndpoints: WechatPlatformEndpoints;
  private readonly componentEndpoints: ResolvedWechatComponentEndpoints;
  private readonly fetcher: PlatformFetch | undefined;
  private readonly allowInsecureRedirectUris: boolean;
  private readonly requireBinding: boolean;
  private readonly hasConfiguredBindings: boolean;

  constructor(options: WechatComponentAdapterOptions) {
    if (!options || typeof options !== "object") {
      throw new ApplicationPlatformError("invalid_component_configuration", "WeChat component configuration is invalid");
    }
    this.componentAppId = assertCredential(options.componentAppId ?? options.component_appid, "componentAppId");
    this.type = options.componentPlatformType === "wechat_open_platform"
      ? "wechat_open_platform"
      : "wechat_official_account";
    this.platformEndpoints = resolveEndpoints(options.endpoints, options.allowInsecureEndpoints === true);
    this.componentEndpoints = resolveComponentEndpoints(
      options.componentEndpoints,
      options.allowInsecureEndpoints === true,
    );
    this.fetcher = options.fetch ?? globalThis.fetch;
    this.allowInsecureRedirectUris = options.allowInsecureRedirectUris === true;
    this.requireBinding = options.allowUnboundAuthorizedAccount === true
      ? false
      : options.requireAuthorizedAccountBinding !== false;
    this.componentAccessTokenResolver = options.componentAccessTokenResolver ?? options.component_access_token_resolver ?? options.resolveComponentAccessToken ?? options.componentTokenResolver;
    this.componentAccessToken = options.componentAccessToken ?? options.component_access_token;
    this.appSecretResolver = options.appSecretResolver ?? options.resolveAppSecret ?? options.resolveSecret;
    this.bindingResolvers = options.resolveBinding ?? options.resolveAuthorizedAccount ?? options.resolveAuthorizedAccountBinding ?? options.resolve_binding;
    const collection = options.bindings ?? options.authorizedAccounts ?? options.authorized_accounts ?? options.authorizedAccountBindings ?? options.account_bindings ?? options.accounts;
    this.hasConfiguredBindings = collection !== undefined;
    if (collection !== undefined) {
      for (const [key, binding] of componentBindingEntries(collection)) {
        this.bindAuthorizedAccount({
          ...binding,
          authorizedAppId: binding.authorizedAppId ?? binding.authorized_appid ?? binding.authorizerAppId ?? binding.appId ?? key,
        });
      }
    }
  }

  bindAuthorizedAccount(binding: WechatComponentAccountBindingInput): void {
    const normalized = normalizeWechatComponentBinding(binding, this.componentAppId);
    this.bindings.set(normalized.authorizedAppId, normalized);
  }

  unbindAuthorizedAccount(authorizedAppId: string): boolean {
    return this.bindings.delete(assertCredential(authorizedAppId, "authorizedAppId"));
  }

  listAuthorizedAccounts(): string[] {
    return [...this.bindings.keys()];
  }

  hasAuthorizedAccount(authorizedAppId: string): boolean {
    return this.bindings.has(assertCredential(authorizedAppId, "authorizedAppId"));
  }

  toJSON(): {
    type: ApplicationPlatformType;
    componentAppId: string;
    authorizedAppIds: string[];
  } {
    return {
      type: this.type,
      componentAppId: this.componentAppId,
      authorizedAppIds: this.listAuthorizedAccounts(),
    };
  }

  async getAuthorizedAccount(authorizedAppId: string): Promise<WechatComponentAccountStatus> {
    const normalizedId = assertCredential(authorizedAppId, "authorizedAppId");
    let binding: NormalizedWechatComponentBinding | undefined;
    try {
      binding = await this.resolveBinding(normalizedId);
    } catch (error) {
      if (!(error instanceof ApplicationPlatformError) || error.code !== "component_account_not_bound") throw error;
    }
    return {
      componentAppId: this.componentAppId,
      authorizedAppId: normalizedId,
      bound: binding !== undefined,
      hasAppSecret: binding?.appSecret !== undefined,
      hasAuthorizerRefreshToken: binding?.authorizerRefreshToken !== undefined,
    };
  }

  createAuthorizationUrl(input: ApplicationPlatformAuthorizationInput): string {
    const appId = assertCredential(input.appId, "appId");
    this.assertAuthorizationBinding(appId);
    return createWechatAuthorizationUrl(
      this.type,
      appId,
      input.redirectUri,
      input.state,
      input.scope,
      input.client,
      this.allowInsecureRedirectUris,
      this.type === "wechat_open_platform"
        ? this.platformEndpoints.openPlatformAuthorizationUrl
        : this.platformEndpoints.officialAuthorizationUrl,
      this.componentAppId,
    );
  }

  async exchangeCode(input: ApplicationPlatformCodeExchangeInput): Promise<PlatformIdentity> {
    const appId = assertCredential(input.appId, "appId");
    if (input.authorizedAppId !== undefined && assertCredential(input.authorizedAppId, "authorizedAppId") !== appId) {
      throw new ApplicationPlatformError("invalid_component_binding", "WeChat authorized account binding is invalid");
    }
    if (input.componentAppId !== undefined && assertCredential(input.componentAppId, "componentAppId") !== this.componentAppId) {
      throw new ApplicationPlatformError("invalid_component_binding", "WeChat component binding is invalid");
    }
    const binding = await this.resolveBinding(appId);
    if (binding !== undefined && binding.authorizedAppId !== appId) {
      throw new ApplicationPlatformError("invalid_component_binding", "WeChat authorized account binding is invalid");
    }
    const code = assertCode(input.code);
    if (input.redirectUri !== undefined) {
      assertRedirectUri(input.redirectUri, this.allowInsecureRedirectUris, input.client);
    }
    const requestedScope = input.scope === undefined
      ? undefined
      : normalizeWechatScope(input.scope, this.type);
    if (this.type === "wechat_open_platform") {
      const appSecret = await this.resolveAppSecret(appId, binding, input.appSecret);
      return this.exchangeStandardOAuthCode(appId, appSecret, code);
    }
    const componentAccessToken = await this.resolveComponentAccessToken(appId);
    const tokenPayload = await requestJson(
      this.fetcher,
      this.componentEndpoints.componentOAuthAccessTokenUrl,
      {
        appid: appId,
        code,
        grant_type: "authorization_code",
        component_appid: this.componentAppId,
        component_access_token: componentAccessToken,
      },
    );
    const accessToken = assertResponseString(tokenPayload.access_token, "access_token");
    const openid = assertResponseString(tokenPayload.openid ?? tokenPayload.opens, "openid");
    const unionid = optionalResponseString(tokenPayload.unionid ?? tokenPayload.unions, "unionid");
    const responseScope = optionalResponseString(tokenPayload.scope, "scope");
    const scope = responseScope === undefined
      ? requestedScope ?? "snsapi_userinfo"
      : normalizeWechatScopeResponse(responseScope, "wechat_official_account");
    let nickname: string | undefined;
    let avatarUrl: string | undefined;
    if (scope.split(",").includes("snsapi_userinfo")) {
      const userInfo = await requestJson(this.fetcher, this.platformEndpoints.userInfoUrl, {
        access_token: accessToken,
        openid,
        lang: "zh_CN",
      });
      nickname = optionalResponseString(userInfo.nickname, "nickname");
      const rawAvatarUrl = optionalResponseString(userInfo.headimgurl, "headimgurl");
      avatarUrl = rawAvatarUrl === undefined ? undefined : assertProviderImageUrl(rawAvatarUrl);
    }
    return {
      provider: "wechat",
      platform: this.type,
      appId,
      subject: unionid ?? `${appId}:${openid}`,
      openid,
      ...(unionid === undefined ? {} : { unionid }),
      ...(nickname === undefined ? {} : { nickname }),
      ...(avatarUrl === undefined ? {} : { avatarUrl }),
      scopes: [scope],
    };
  }

  private async exchangeStandardOAuthCode(appId: string, appSecret: string, code: string): Promise<PlatformIdentity> {
    const tokenPayload = await requestJson(
      this.fetcher,
      this.platformEndpoints.accessTokenUrl,
      {
        appid: appId,
        secret: appSecret,
        code,
        grant_type: "authorization_code",
      },
    );
    const accessToken = assertResponseString(tokenPayload.access_token, "access_token");
    const openid = assertResponseString(tokenPayload.openid ?? tokenPayload.opens, "openid");
    const unionid = optionalResponseString(tokenPayload.unionid ?? tokenPayload.unions, "unionid");
    return {
      provider: "wechat",
      platform: "wechat_open_platform",
      appId,
      subject: unionid ?? `${appId}:${openid}`,
      openid,
      ...(unionid === undefined ? {} : { unionid }),
      scopes: ["snsapi_login"],
    };
  }

  async resolveComponentAccessToken(
    input: string | { authorizedAppId: string },
  ): Promise<string> {
    const authorizedAppId = assertCredential(
      typeof input === "string" ? input : input?.authorizedAppId,
      "authorizedAppId",
    );
    const existing = this.componentAccessTokenInFlight.get(authorizedAppId);
    if (existing !== undefined) return existing;
    const operation = this.resolveComponentAccessTokenUncached(authorizedAppId);
    this.componentAccessTokenInFlight.set(authorizedAppId, operation);
    try {
      return await operation;
    } finally {
      if (this.componentAccessTokenInFlight.get(authorizedAppId) === operation) this.componentAccessTokenInFlight.delete(authorizedAppId);
    }
  }

  private async resolveComponentAccessTokenUncached(authorizedAppId: string): Promise<string> {
    const resolver = this.componentAccessTokenResolver;
    let result: WechatComponentAccessTokenResolverResult | undefined;
    try {
      if (typeof resolver === "function") {
        result = await resolver(createWechatComponentResolverInput(this.componentAppId, authorizedAppId));
      } else if (resolver !== undefined && typeof resolver.resolve === "function") {
        result = await resolver.resolve(createWechatComponentResolverInput(this.componentAppId, authorizedAppId));
      } else if (resolver !== undefined && typeof resolver.getComponentAccessToken === "function") {
        result = await resolver.getComponentAccessToken(createWechatComponentResolverInput(this.componentAppId, authorizedAppId));
      } else if (typeof this.componentAccessToken === "function") {
        result = await this.componentAccessToken();
      } else if (this.componentAccessToken !== undefined) {
        result = this.componentAccessToken;
      } else {
        throw new ApplicationPlatformError("component_access_token_unavailable", "WeChat component access token is unavailable");
      }
    } catch (error) {
      throw toSafeApplicationPlatformError(
        error,
        "component_access_token_unavailable",
        "WeChat component access token is unavailable",
      );
    }
    return assertComponentAccessToken(result);
  }

  async withComponentAccessToken<T>(
    authorizedAppId: string,
    operation: (accessToken: string) => T | Promise<T>,
  ): Promise<T> {
    if (typeof operation !== "function") {
      throw new ApplicationPlatformError("invalid_component_operation", "WeChat component operation is invalid");
    }
    return operation(await this.resolveComponentAccessToken(authorizedAppId));
  }

  async getAuthorizerAccessToken(authorizedAppId: string): Promise<WechatComponentTokenMetadata> {
    const normalizedId = assertCredential(authorizedAppId, "authorizedAppId");
    const binding = await this.resolveBinding(normalizedId);
    if (binding === undefined || binding.authorizerRefreshToken === undefined) {
      throw new ApplicationPlatformError("component_account_not_bound", "WeChat authorized account is not bound");
    }
    const result = await this.resolveAuthorizerAccessToken(normalizedId, binding);
    return result.metadata;
  }

  async withAuthorizerAccessToken<T>(
    authorizedAppId: string,
    operation: (accessToken: string) => T | Promise<T>,
  ): Promise<T> {
    if (typeof operation !== "function") {
      throw new ApplicationPlatformError("invalid_component_operation", "WeChat component operation is invalid");
    }
    const normalizedId = assertCredential(authorizedAppId, "authorizedAppId");
    const binding = await this.resolveBinding(normalizedId);
    if (binding === undefined || binding.authorizerRefreshToken === undefined) {
      throw new ApplicationPlatformError("component_account_not_bound", "WeChat authorized account is not bound");
    }
    const result = await this.resolveAuthorizerAccessToken(normalizedId, binding);
    return operation(result.token);
  }

  private async resolveAuthorizerAccessToken(
    authorizedAppId: string,
    binding: NormalizedWechatComponentBinding,
  ): Promise<{ token: string; metadata: WechatComponentTokenMetadata }> {
    const existing = this.authorizerAccessTokenInFlight.get(authorizedAppId);
    if (existing !== undefined) return existing;
    const operation = (async () => {
      const componentAccessToken = await this.resolveComponentAccessToken(authorizedAppId);
      const payload = await this.requestAuthorizerAccessToken(authorizedAppId, binding.authorizerRefreshToken as string, componentAccessToken);
      const token = assertResponseString(payload.authorizer_access_token, "authorizer_access_token");
      const expiresIn = optionalResponseNumber(payload.expires_in, "expires_in");
      const refreshToken = optionalResponseString(payload.authorizer_refresh_token, "authorizer_refresh_token");
      const current = this.bindings.get(authorizedAppId);
      if (refreshToken !== undefined && current !== undefined && current.authorizerRefreshToken === binding.authorizerRefreshToken) {
        this.bindings.set(authorizedAppId, { ...current, authorizerRefreshToken: refreshToken });
      }
      return {
        token,
        metadata: {
          componentAppId: this.componentAppId,
          authorizedAppId,
          ...(expiresIn === undefined ? {} : { expiresIn }),
        },
      };
    })();
    this.authorizerAccessTokenInFlight.set(authorizedAppId, operation);
    try {
      return await operation;
    } finally {
      if (this.authorizerAccessTokenInFlight.get(authorizedAppId) === operation) this.authorizerAccessTokenInFlight.delete(authorizedAppId);
    }
  }

  private assertAuthorizationBinding(appId: string): void {
    if (this.bindingResolvers !== undefined && !this.hasConfiguredBindings) return;
    if (!this.requireBinding && !this.hasConfiguredBindings) return;
    if (!this.bindings.has(appId)) {
      throw new ApplicationPlatformError("invalid_component_binding", "WeChat authorized account is not bound");
    }
  }

  private async resolveAppSecret(
    appId: string,
    binding: NormalizedWechatComponentBinding | undefined,
    inputSecret: string | undefined,
  ): Promise<string> {
    if (binding?.appSecret !== undefined) return assertCredential(binding.appSecret, "appSecret");
    if (inputSecret !== undefined) return assertCredential(inputSecret, "appSecret");
    if (this.appSecretResolver !== undefined) {
      try {
        return assertCredential(await this.appSecretResolver({
          appId,
          platform: "wechat_component",
          componentAppId: this.componentAppId,
          authorizedAppId: appId,
        }), "appSecret");
      } catch (error) {
        throw toSafeApplicationPlatformError(
          error,
          "credential_unavailable",
          "WeChat authorized account credentials are unavailable",
        );
      }
    }
    throw new ApplicationPlatformError("credential_unavailable", "WeChat authorized account credentials are unavailable");
  }

  private async resolveBinding(authorizedAppId: string): Promise<NormalizedWechatComponentBinding | undefined> {
    const existing = this.bindings.get(authorizedAppId);
    if (existing !== undefined) return existing;
    if (this.bindingResolvers !== undefined) {
      let resolved: WechatComponentAccountBindingInput | null | undefined;
      try {
        const resolver = typeof this.bindingResolvers === "function"
          ? this.bindingResolvers
          : this.bindingResolvers.resolve;
        resolved = await resolver(createWechatComponentResolverInput(this.componentAppId, authorizedAppId));
      } catch (error) {
        throw toSafeApplicationPlatformError(
          error,
          "component_binding_unavailable",
          "WeChat authorized account binding is unavailable",
        );
      }
      if (resolved !== undefined && resolved !== null) {
        const binding = normalizeWechatComponentBinding(resolved, this.componentAppId, authorizedAppId);
        this.bindings.set(authorizedAppId, binding);
        return binding;
      }
    }
    if (this.requireBinding || this.hasConfiguredBindings) {
      throw new ApplicationPlatformError("component_account_not_bound", "WeChat authorized account is not bound");
    }
    return undefined;
  }

  private async requestAuthorizerAccessToken(
    authorizedAppId: string,
    authorizerRefreshToken: string,
    componentAccessToken: string,
  ): Promise<Record<string, unknown>> {
    return requestJson(
      this.fetcher,
      this.componentEndpoints.authorizerAccessTokenUrl,
      { component_access_token: componentAccessToken },
      {
        method: "POST",
        body: JSON.stringify({
          component_appid: this.componentAppId,
          authorizer_appid: authorizedAppId,
          authorizer_refresh_token: authorizerRefreshToken,
        }),
      },
    );
  }
}

export function createWechatComponentAdapter(options: WechatComponentAdapterOptions): WechatComponentProviderAdapter {
  return new WechatComponentProviderAdapter({
    ...options,
    componentPlatformType: options.componentPlatformType ?? "wechat_official_account",
  });
}

export function createWechatComponentProvider(options: WechatComponentAdapterOptions): WechatComponentProviderAdapter {
  return new WechatComponentProviderAdapter({
    ...options,
    componentPlatformType: options.componentPlatformType ?? "wechat_official_account",
  });
}

export function createWechatOpenPlatformComponentAdapter(
  options: WechatComponentAdapterOptions,
): WechatComponentProviderAdapter {
  return new WechatComponentProviderAdapter({
    ...options,
    componentPlatformType: "wechat_open_platform",
  });
}

export function createWechatComponentProviderAdapter(
  options: WechatComponentAdapterOptions,
): WechatComponentProviderAdapter {
  return new WechatComponentProviderAdapter({
    ...options,
    componentPlatformType: options.componentPlatformType ?? "wechat_official_account",
  });
}

export function createWechatThirdPartyPlatformAdapter(
  options: WechatComponentAdapterOptions,
): WechatComponentProviderAdapter {
  return new WechatComponentProviderAdapter({
    ...options,
    componentPlatformType: options.componentPlatformType ?? "wechat_official_account",
  });
}

export function createWechatComponentAccessTokenResolver(
  options: WechatComponentAccessTokenResolverOptions,
): WechatComponentAccessTokenResolver {
  if (!options || typeof options !== "object") {
    throw new ApplicationPlatformError("invalid_component_configuration", "WeChat component configuration is invalid");
  }
  const componentAppId = assertCredential(options.componentAppId ?? options.component_appid, "componentAppId");
  const endpoint = assertEndpoint(
    options.endpoint ?? WECHAT_COMPONENT_ENDPOINTS.componentAccessTokenUrl,
    options.allowInsecureEndpoint === true,
  );
  const fetcher = options.fetch ?? globalThis.fetch;
  const componentAppSecret = options.componentAppSecret ?? options.component_appsecret ?? options.component_app_secret;
  const componentVerifyTicket = options.componentVerifyTicket ?? options.component_verify_ticket;
  if (componentAppSecret === undefined || componentVerifyTicket === undefined) {
    throw new ApplicationPlatformError("invalid_component_configuration", "WeChat component configuration is invalid");
  }
  return async ({ componentAppId: requestedComponentAppId }) => {
    if (requestedComponentAppId !== componentAppId) {
      throw new ApplicationPlatformError("invalid_component_binding", "WeChat component binding is invalid");
    }
    let appSecret: string;
    let verifyTicket: string;
    try {
      appSecret = assertCredential(
        typeof componentAppSecret === "function" ? await componentAppSecret() : componentAppSecret,
        "appSecret",
      );
      verifyTicket = assertComponentAccessToken(
        typeof componentVerifyTicket === "function" ? await componentVerifyTicket() : componentVerifyTicket,
      );
      const payload = await requestJson(fetcher, endpoint, {}, {
        method: "POST",
        body: JSON.stringify({
          component_appid: componentAppId,
          component_appsecret: appSecret,
          component_verify_ticket: verifyTicket,
        }),
      });
      return assertComponentAccessToken(
        payload.component_access_token ?? payload.componentAccessToken ?? payload.accessToken,
      );
    } catch (error) {
      throw toSafeApplicationPlatformError(
        error,
        "component_access_token_unavailable",
        "WeChat component access token is unavailable",
      );
    }
  };
}

export function createWechatOfficialAccountAdapter(
  options: WechatPlatformAdapterOptions = {},
): ApplicationPlatformAuthAdapter {
  if (hasWechatComponentOptions(options)) {
    const componentAppId = options.componentAppId ?? options.component_appid;
    if (componentAppId === undefined) {
      throw new ApplicationPlatformError("invalid_component_configuration", "WeChat component configuration is invalid");
    }
    return new WechatComponentProviderAdapter({
      ...options,
      componentAppId,
      componentPlatformType: "wechat_official_account",
    });
  }
  return createWechatOAuthAdapter("wechat_official_account", options, false);
}

export function createWechatOpenPlatformAdapter(
  options: WechatPlatformAdapterOptions = {},
): ApplicationPlatformAuthAdapter {
  if (hasWechatComponentOptions(options)) {
    const componentAppId = options.componentAppId ?? options.component_appid;
    if (componentAppId === undefined) {
      throw new ApplicationPlatformError("invalid_component_configuration", "WeChat component configuration is invalid");
    }
    return new WechatComponentProviderAdapter({
      ...options,
      componentAppId,
      componentPlatformType: "wechat_open_platform",
    });
  }
  return createWechatOAuthAdapter("wechat_open_platform", options, true);
}

export function createWechatMiniProgramAdapter(
  options: WechatPlatformAdapterOptions = {},
): ApplicationPlatformAuthAdapter {
  const endpoints = resolveEndpoints(options.endpoints, options.allowInsecureEndpoints === true);
  const fetcher = options.fetch ?? globalThis.fetch;
  return {
    type: "wechat_mini_program",
    supportsAuthorization: false,
    createAuthorizationUrl() {
      throw new ApplicationPlatformError(
        "authorization_not_supported",
        "WeChat mini programs use server-side code exchange",
      );
    },
    async exchangeCode(input) {
      const appId = assertCredential(input.appId, "appId");
      const appSecret = await resolveWechatAppSecret("wechat_mini_program", appId, input.appSecret, options);
      const code = assertCode(input.code);
      const payload = await requestJson(fetcher, endpoints.miniProgramSessionUrl, {
        appid: appId,
        secret: appSecret,
        js_code: code,
        grant_type: "authorization_code",
      });
      const openid = assertResponseString(payload.openid, "openid");
      const unionid = optionalResponseString(payload.unionid, "unionid");
      return {
        provider: "wechat",
        platform: "wechat_mini_program",
        appId,
        subject: unionid ?? `${appId}:${openid}`,
        openid,
        ...(unionid === undefined ? {} : { unionid }),
        scopes: [],
      };
    },
  };
}

export function createGenericMiniProgramAdapter(
  options: GenericMiniProgramAdapterOptions,
): ApplicationPlatformAuthAdapter {
  if (!options || typeof options.type !== "string" || options.type.length === 0) {
    throw new ApplicationPlatformError("invalid_adapter", "Invalid mini program adapter type");
  }
  if (typeof options.mapResponse !== "function") {
    throw new ApplicationPlatformError("invalid_adapter", "Mini program response mapper is required");
  }
  const endpoint = assertEndpoint(options.endpoint, options.allowInsecureEndpoint === true);
  const fetcher = options.fetch ?? globalThis.fetch;
  return {
    type: options.type,
    supportsAuthorization: false,
    createAuthorizationUrl() {
      throw new ApplicationPlatformError(
        "authorization_not_supported",
        "Mini programs use server-side code exchange",
      );
    },
    async exchangeCode(input) {
      const appId = assertCredential(input.appId, "appId");
      const appSecret = assertCredential(input.appSecret, "appSecret");
      const code = assertCode(input.code);
      const payload = await requestJson(fetcher, endpoint, { appId, secret: appSecret, code });
      let mapped: GenericMiniProgramIdentityInput;
      try {
        mapped = options.mapResponse(payload, { appId, code });
      } catch {
        throw new ApplicationPlatformError("invalid_response", "Mini program provider returned an invalid identity");
      }
      if (!mapped || typeof mapped !== "object") {
        throw new ApplicationPlatformError("invalid_response", "Mini program provider returned an invalid identity");
      }
      const subject = assertResponseString(mapped.subject, "subject");
      const openid = optionalResponseString(mapped.openid, "openid");
      const unionid = optionalResponseString(mapped.unionid, "unionid");
      const nickname = optionalResponseString(mapped.nickname, "nickname");
      const avatarUrl = optionalResponseString(mapped.avatarUrl, "avatarUrl");
      const email = optionalResponseString(mapped.email, "email");
      const emailVerified = mapped.emailVerified === true;
      return {
        provider: options.type,
        platform: options.type,
        appId,
        subject,
        ...(openid === undefined ? {} : { openid }),
        ...(unionid === undefined ? {} : { unionid }),
        ...(nickname === undefined ? {} : { nickname }),
        ...(avatarUrl === undefined ? {} : { avatarUrl }),
        ...(email === undefined ? {} : { email }),
        ...(email === undefined ? {} : { emailVerified }),
        scopes: normalizeScopes(mapped.scopes),
      };
    },
  };
}

function createWechatOAuthAdapter(
  type: "wechat_official_account" | "wechat_open_platform",
  options: WechatPlatformAdapterOptions,
  openPlatform: boolean,
): ApplicationPlatformAuthAdapter {
  const endpoints = resolveEndpoints(options.endpoints, options.allowInsecureEndpoints === true);
  const fetcher = options.fetch ?? globalThis.fetch;
  const allowInsecureRedirectUris = options.allowInsecureRedirectUris === true;
  return {
    type,
    supportsAuthorization: true,
    createAuthorizationUrl(input) {
      const appId = assertCredential(input.appId, "appId");
      return createWechatAuthorizationUrl(
        type,
        appId,
        input.redirectUri,
        input.state,
        input.scope,
        input.client,
        allowInsecureRedirectUris,
        type === "wechat_open_platform" ? endpoints.openPlatformAuthorizationUrl : endpoints.officialAuthorizationUrl,
      );
    },
    async exchangeCode(input) {
      if (input.componentAppId !== undefined || input.authorizedAppId !== undefined) {
        throw new ApplicationPlatformError("invalid_component_binding", "WeChat component binding is invalid");
      }
      const appId = assertCredential(input.appId, "appId");
      const appSecret = await resolveWechatAppSecret(type, appId, input.appSecret, options);
      const code = assertCode(input.code);
      if (input.redirectUri !== undefined) {
        assertRedirectUri(input.redirectUri, allowInsecureRedirectUris, input.client);
      }
      const requestedScope = input.scope === undefined
        ? undefined
        : normalizeWechatScope(input.scope, type);
      const tokenPayload = await requestJson(fetcher, endpoints.accessTokenUrl, {
        appid: appId,
        secret: appSecret,
        code,
        grant_type: "authorization_code",
      });
      const accessToken = assertResponseString(tokenPayload.access_token, "access_token");
    const openid = assertResponseString(tokenPayload.openid ?? tokenPayload.opens, "openid");
    const unionid = optionalResponseString(tokenPayload.unionid ?? tokenPayload.unions, "unionid");

      const responseScope = optionalResponseString(tokenPayload.scope, "scope");
      const scope = openPlatform
        ? "snsapi_login"
        : responseScope === undefined
          ? requestedScope ?? "snsapi_userinfo"
          : normalizeWechatScopeResponse(responseScope, type);
      let nickname: string | undefined;
      let avatarUrl: string | undefined;
      if (!openPlatform && scope.split(",").includes("snsapi_userinfo")) {
        const userInfo = await requestJson(fetcher, endpoints.userInfoUrl, {
          access_token: accessToken,
          openid,
          lang: "zh_CN",
        });
        nickname = optionalResponseString(userInfo.nickname, "nickname");
        const rawAvatarUrl = optionalResponseString(userInfo.headimgurl, "headimgurl");
        avatarUrl = rawAvatarUrl === undefined ? undefined : assertProviderImageUrl(rawAvatarUrl);
      }
      return {
        provider: "wechat",
        platform: type,
        appId,
        subject: unionid ?? `${appId}:${openid}`,
        openid,
        ...(unionid === undefined ? {} : { unionid }),
        ...(nickname === undefined ? {} : { nickname }),
        ...(avatarUrl === undefined ? {} : { avatarUrl }),
        scopes: [scope],
      };
    },
  };
}

function providerRequestError(
  code: string,
  message: string,
  statusCode: number | undefined,
  internalUrl: string,
): ApplicationPlatformError {
  return new ApplicationPlatformError(code, message, statusCode, redactWechatProviderUrl(internalUrl));
}

async function requestJson(
  fetcher: PlatformFetch | undefined,
  endpoint: string,
  query: Readonly<Record<string, string>>,
  init?: { method?: string; body?: string },
): Promise<Record<string, unknown>> {
  if (typeof fetcher !== "function") {
    throw new ApplicationPlatformError("fetch_unavailable", "Platform HTTP client is unavailable");
  }
  const internalUrl = buildInternalProviderUrl(endpoint, query);
  const method = init?.method ?? "GET";
  let response: Response;
  try {
    response = await fetcher(internalUrl, {
      method,
      headers: {
        accept: "application/json",
        ...(init?.body === undefined ? {} : { "content-type": "application/json" }),
      },
      ...(init?.body === undefined ? {} : { body: init.body }),
      ...(typeof AbortSignal !== "undefined" && typeof AbortSignal.timeout === "function"
        ? { signal: AbortSignal.timeout(10_000) }
        : {}),
    });
  } catch {
    throw providerRequestError("provider_unavailable", "Platform provider is unavailable", undefined, internalUrl);
  }
  if (!response || typeof response.text !== "function") {
    throw providerRequestError("invalid_response", "Platform provider returned an invalid response", undefined, internalUrl);
  }
  const status = typeof response.status === "number" ? response.status : undefined;
  if (response.ok === false || (status !== undefined && (status < 200 || status >= 300))) {
    throw providerRequestError(
      "provider_error",
      "Platform provider request failed",
      status !== undefined && Number.isInteger(status) ? status : undefined,
      internalUrl,
    );
  }
  let text: string;
  try {
    text = await response.text();
  } catch {
    throw providerRequestError("invalid_response", "Platform provider returned an invalid response", undefined, internalUrl);
  }
  if (typeof text !== "string" || text.length > 1_048_576) {
    throw providerRequestError("invalid_response", "Platform provider response is too large", undefined, internalUrl);
  }
  let payload: unknown;
  try {
    payload = JSON.parse(text);
  } catch {
    throw providerRequestError("invalid_response", "Platform provider returned invalid JSON", undefined, internalUrl);
  }
  if (!isRecord(payload)) {
    throw providerRequestError("invalid_response", "Platform provider returned an invalid response", undefined, internalUrl);
  }
  const errorCode = payload.errcode;
  const providerError = payload.error ?? payload.error_code ?? payload.errorCode;
  if (
    (errorCode !== undefined && errorCode !== 0 && errorCode !== "0") ||
    (providerError !== undefined && providerError !== null && providerError !== "" && providerError !== 0 && providerError !== "0")
  ) {
    throw providerRequestError("provider_error", "Platform provider rejected the request", undefined, internalUrl);
  }
  return payload;
}

function buildInternalProviderUrl(endpoint: string, query: Readonly<Record<string, string>>): string {
  const url = new URL(endpoint);
  for (const [key, value] of Object.entries(query)) url.searchParams.set(key, value);
  return url.toString();
}

function hasWechatComponentOptions(options: WechatPlatformAdapterOptions): boolean {
  return options.componentAppId !== undefined ||
    options.component_appid !== undefined ||
    options.componentAccessTokenResolver !== undefined ||
    options.component_access_token_resolver !== undefined ||
    options.resolveComponentAccessToken !== undefined ||
    options.componentTokenResolver !== undefined ||
    options.componentAccessToken !== undefined ||
    options.component_access_token !== undefined ||
    options.bindings !== undefined ||
    options.authorizedAccounts !== undefined ||
    options.authorized_accounts !== undefined ||
    options.authorizedAccountBindings !== undefined ||
    options.account_bindings !== undefined ||
    options.accounts !== undefined ||
    options.resolveBinding !== undefined ||
    options.resolveAuthorizedAccount !== undefined ||
    options.resolveAuthorizedAccountBinding !== undefined ||
    options.resolve_binding !== undefined;
}

function resolveComponentEndpoints(
  value: Partial<WechatComponentEndpoints> | undefined,
  allowInsecure = false,
): ResolvedWechatComponentEndpoints {
  const defaults: ResolvedWechatComponentEndpoints = {
    componentAccessTokenUrl: WECHAT_COMPONENT_ENDPOINTS.componentAccessTokenUrl,
    authorizerAccessTokenUrl: WECHAT_COMPONENT_ENDPOINTS.authorizerAccessTokenUrl,
    authorizerInfoUrl: WECHAT_COMPONENT_ENDPOINTS.authorizerInfoUrl,
    authorizedAccountListUrl: WECHAT_COMPONENT_ENDPOINTS.authorizedAccountListUrl,
    componentOAuthAccessTokenUrl: WECHAT_COMPONENT_ENDPOINTS.componentOAuthAccessTokenUrl ?? "",
    componentOAuthRefreshTokenUrl: WECHAT_COMPONENT_ENDPOINTS.componentOAuthRefreshTokenUrl ?? "",
    componentAuthorizationInfoUrl: WECHAT_COMPONENT_ENDPOINTS.componentAuthorizationInfoUrl ?? "",
  };
  const endpoints: ResolvedWechatComponentEndpoints = {
    ...defaults,
    ...(value?.componentAccessTokenUrl === undefined ? {} : { componentAccessTokenUrl: value.componentAccessTokenUrl }),
    ...(value?.authorizerAccessTokenUrl === undefined ? {} : { authorizerAccessTokenUrl: value.authorizerAccessTokenUrl }),
    ...(value?.authorizerInfoUrl === undefined ? {} : { authorizerInfoUrl: value.authorizerInfoUrl }),
    ...(value?.authorizedAccountListUrl === undefined ? {} : { authorizedAccountListUrl: value.authorizedAccountListUrl }),
    ...(value?.componentOAuthAccessTokenUrl === undefined ? {} : { componentOAuthAccessTokenUrl: value.componentOAuthAccessTokenUrl }),
    ...(value?.componentOAuthRefreshTokenUrl === undefined ? {} : { componentOAuthRefreshTokenUrl: value.componentOAuthRefreshTokenUrl }),
    ...(value?.componentAuthorizationInfoUrl === undefined ? {} : { componentAuthorizationInfoUrl: value.componentAuthorizationInfoUrl }),
  };
  for (const endpoint of Object.values(endpoints)) assertEndpoint(endpoint, allowInsecure);
  return endpoints;
}

function createWechatComponentResolverInput(
  componentAppId: string,
  authorizedAppId: string,
): WechatComponentAccessTokenResolverInput & WechatComponentBindingResolverInput {
  const input = { componentAppId, authorizedAppId } as WechatComponentAccessTokenResolverInput & WechatComponentBindingResolverInput;
  Object.defineProperty(input, "appId", { value: authorizedAppId, enumerable: false });
  Object.defineProperty(input, "authorizerAppId", { value: authorizedAppId, enumerable: false });
  return input;
}

function componentBindingEntries(
  collection: WechatComponentAccountBindingCollection,
): Array<[string, WechatComponentAccountBindingInput]> {
  if (Array.isArray(collection)) {
    return collection.map((binding, index) => {
      if (!isRecord(binding)) {
        throw new ApplicationPlatformError("invalid_component_binding", "WeChat authorized account binding is invalid");
      }
      const record = binding as WechatComponentAccountBindingInput;
      return [
        record.authorizedAppId ?? record.authorized_appid ?? record.authorizerAppId ?? record.appId ?? String(index),
        record,
      ];
    });
  }
  if (collection instanceof Map) return [...collection.entries()];
  if (isRecord(collection)) return Object.entries(collection);
  throw new ApplicationPlatformError("invalid_component_binding", "WeChat authorized account binding is invalid");
}

function normalizeWechatComponentBinding(
  value: WechatComponentAccountBindingInput,
  expectedComponentAppId: string,
  expectedAuthorizedAppId?: string,
): NormalizedWechatComponentBinding {
  if (!isRecord(value)) {
    throw new ApplicationPlatformError("invalid_component_binding", "WeChat authorized account binding is invalid");
  }
  const componentAppId = firstString(value, ["componentAppId", "component_appid"]);
  const authorizedAppId = firstString(value, ["authorizedAppId", "authorized_appid", "authorizerAppId", "authorizer_appid", "appId"]);
  const normalizedComponentAppId = componentAppId ?? expectedComponentAppId;
  const normalizedAuthorizedAppId = expectedAuthorizedAppId ?? authorizedAppId;
  if (
    normalizedComponentAppId !== expectedComponentAppId ||
    normalizedAuthorizedAppId === undefined ||
    (authorizedAppId !== undefined && authorizedAppId !== normalizedAuthorizedAppId)
  ) {
    throw new ApplicationPlatformError("invalid_component_binding", "WeChat authorized account binding is invalid");
  }
  const appSecret = firstString(value, ["appSecret", "app_secret"]);
  const authorizerRefreshToken = firstString(value, [
    "authorizerRefreshToken",
    "authorizer_refresh_token",
    "refreshToken",
    "refresh_token",
  ]);
  return {
    componentAppId: expectedComponentAppId,
    authorizedAppId: assertCredential(normalizedAuthorizedAppId, "authorizedAppId"),
    ...(appSecret === undefined ? {} : { appSecret: assertCredential(appSecret, "appSecret") }),
    ...(authorizerRefreshToken === undefined
      ? {}
      : { authorizerRefreshToken: assertCredential(authorizerRefreshToken, "authorizerRefreshToken") }),
  };
}

function firstString(value: Record<string, unknown>, keys: readonly string[]): string | undefined {
  for (const key of keys) {
    if (!Object.prototype.hasOwnProperty.call(value, key)) continue;
    const candidate = value[key];
    if (candidate === undefined || candidate === null || candidate === "") continue;
    if (typeof candidate !== "string") {
      throw new ApplicationPlatformError("invalid_component_binding", "WeChat authorized account binding is invalid");
    }
    return candidate;
  }
  return undefined;
}

function createWechatAuthorizationUrl(
  type: "wechat_official_account" | "wechat_open_platform",
  appId: string,
  redirectUriValue: unknown,
  stateValue: unknown,
  scopeValue: string | undefined,
  client: "web" | "native" | undefined,
  allowInsecureRedirectUris: boolean,
  authorizationEndpoint: string,
  componentAppId?: string,
): string {
  const redirectUri = assertRedirectUri(redirectUriValue, allowInsecureRedirectUris, client);
  const state = assertState(stateValue);
  const scope = normalizeWechatScope(
    scopeValue ?? (type === "wechat_open_platform" ? "snsapi_login" : "snsapi_userinfo"),
    type,
  );
  const query = new URLSearchParams({
    appid: appId,
    redirect_uri: redirectUri,
    response_type: "code",
    scope,
    state,
    ...(componentAppId === undefined ? {} : { component_appid: componentAppId }),
  });
  const url = new URL(authorizationEndpoint);
  url.search = query.toString();
  url.hash = "wechat_redirect";
  assertRedirectQueryIsSafe(url);
  return url.toString();
}

function resolveWechatAppSecret(
  type: WechatApplicationSecretResolverInput["platform"],
  appId: string,
  inputSecret: string | undefined,
  options: WechatPlatformAdapterOptions,
): Promise<string> | string {
  if (inputSecret !== undefined) return assertCredential(inputSecret, "appSecret");
  const resolver = options.appSecretResolver ?? options.resolveAppSecret ?? options.resolveSecret;
  if (resolver === undefined) {
    throw new ApplicationPlatformError("credential_unavailable", "WeChat application credentials are unavailable");
  }
  return resolveWechatAppSecretWithResolver(resolver, type, appId);
}

async function resolveWechatAppSecretWithResolver(
  resolver: WechatApplicationSecretResolver,
  type: WechatApplicationSecretResolverInput["platform"],
  appId: string,
): Promise<string> {
  try {
    return assertCredential(await resolver({ appId, platform: type }), "appSecret");
  } catch {
    throw new ApplicationPlatformError("credential_unavailable", "WeChat application credentials are unavailable");
  }
}

function assertComponentAccessToken(value: unknown): string {
  let candidate: unknown = value;
  if (isRecord(value)) {
    candidate = value.accessToken ?? value.componentAccessToken ?? value.component_access_token ?? value.token;
  }
  if (typeof candidate !== "string") {
    throw new ApplicationPlatformError("component_access_token_unavailable", "WeChat component access token is unavailable");
  }
  const normalized = candidate.trim();
  if (normalized.length === 0 || normalized.length > 4096 || /[\u0000-\u001f\u007f\s]/u.test(normalized)) {
    throw new ApplicationPlatformError("component_access_token_unavailable", "WeChat component access token is unavailable");
  }
  return normalized;
}

function assertProviderImageUrl(value: string): string {
  if (value.length === 0 || value.length > 2048 || /[\u0000-\u001f\u007f\s]/u.test(value)) {
    throw new ApplicationPlatformError("invalid_response", "Platform provider returned an invalid avatar URL");
  }
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new ApplicationPlatformError("invalid_response", "Platform provider returned an invalid avatar URL");
  }
  if (
    (parsed.protocol !== "https:" && !(parsed.protocol === "http:" && isWechatImageHost(parsed.hostname))) ||
    parsed.hostname.length === 0 ||
    parsed.username !== "" ||
    parsed.password !== "" ||
    parsed.hash !== ""
  ) {
    throw new ApplicationPlatformError("invalid_response", "Platform provider returned an invalid avatar URL");
  }
  return parsed.toString();
}

function isWechatImageHost(hostname: string): boolean {
  const normalized = hostname.toLowerCase();
  return normalized === "wx.qlogo.cn" || normalized.endsWith(".qlogo.cn");
}

function optionalResponseNumber(value: unknown, field: string): number | undefined {
  if (value === undefined || value === null || value === "") return undefined;
  const normalized = typeof value === "string" && /^\d+$/u.test(value) ? Number(value) : value;
  if (typeof normalized !== "number" || !Number.isSafeInteger(normalized) || normalized < 0) {
    throw new ApplicationPlatformError("invalid_response", `Platform provider returned an invalid ${field}`);
  }
  return normalized;
}

export function normalizeWechatScope(
  value: unknown,
  type: "wechat_official_account" | "wechat_open_platform",
): string {
  if (typeof value !== "string") {
    throw new ApplicationPlatformError("invalid_scope", "WeChat scope is invalid");
  }
  const parts = value.split(/[\s,]+/u).filter((part) => part.length > 0);
  const allowed: readonly string[] = type === "wechat_open_platform"
    ? WECHAT_OPEN_PLATFORM_SCOPES
    : WECHAT_OFFICIAL_ACCOUNT_SCOPES;
  if (parts.length === 0 || parts.some((part) => !allowed.includes(part))) {
    throw new ApplicationPlatformError("invalid_scope", "WeChat scope is invalid");
  }
  if (type === "wechat_open_platform" && (parts.length !== 1 || parts[0] !== "snsapi_login")) {
    throw new ApplicationPlatformError("invalid_scope", "WeChat scope is invalid");
  }
  return [...new Set(parts)].join(",");
}

function normalizeWechatScopeResponse(
  value: string,
  type: "wechat_official_account" | "wechat_open_platform",
): string {
  const parts = value.split(/[\s,]+/u).filter((part) => part.length > 0);
  if (parts.length === 0) throw new ApplicationPlatformError("invalid_scope", "WeChat scope is invalid");
  for (const part of parts) normalizeWechatScope(part, type);
  if (type === "wechat_open_platform") return "snsapi_login";
  return parts.includes("snsapi_userinfo") ? "snsapi_userinfo" : "snsapi_base";
}

function resolveEndpoints(
  value: Partial<WechatPlatformEndpoints> | undefined,
  allowInsecure = false,
): WechatPlatformEndpoints {
  const endpoints = { ...WECHAT_ENDPOINTS, ...(value ?? {}) };
  for (const endpoint of Object.values(endpoints)) assertEndpoint(endpoint, allowInsecure);
  return endpoints;
}

function assertEndpoint(value: unknown, allowInsecure = false): string {
  if (typeof value !== "string" || value.length === 0 || value.length > 2048 || /[\u0000-\u001f\u007f\s]/u.test(value)) {
    throw new ApplicationPlatformError("invalid_endpoint", "Platform endpoint is invalid");
  }
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new ApplicationPlatformError("invalid_endpoint", "Platform endpoint is invalid");
  }
  if (
    (parsed.protocol !== "https:" && parsed.protocol !== "http:") ||
    (!allowInsecure && parsed.protocol !== "https:" && !isLoopbackHost(parsed.hostname)) ||
    parsed.username !== "" ||
    parsed.password !== "" ||
    parsed.search !== "" ||
    parsed.hash !== "" ||
    parsed.hostname.length === 0
  ) {
    throw new ApplicationPlatformError("invalid_endpoint", "Platform endpoint is invalid");
  }
  return parsed.toString();
}

const FORBIDDEN_REDIRECT_QUERY_KEYS = new Set([
  "secret",
  "appsecret",
  "clientsecret",
  "componentappsecret",
  "password",
  "accesstoken",
  "refreshtoken",
  "idtoken",
  "sessionkey",
  "componentaccesstoken",
  "authorizeraccesstoken",
  "authorizerrefreshtoken",
  "verifyticket",
  "componentverifyticket",
  "ticket",
  "preauthcode",
  "authorizersecret",
  "code",
]);

function assertRedirectQueryIsSafe(url: URL, depth = 0): void {
  for (const [key, value] of url.searchParams.entries()) {
    if (FORBIDDEN_REDIRECT_QUERY_KEYS.has(key.toLowerCase().replace(/[^a-z0-9]/gu, ""))) {
      throw new ApplicationPlatformError("invalid_redirect_uri", "Platform redirect URI contains a forbidden secret");
    }
    if (depth >= 2 || !/^[a-z][a-z0-9+.-]*:/iu.test(value) || !/[?&]/u.test(value)) continue;
    try {
      assertRedirectQueryIsSafe(new URL(value), depth + 1);
    } catch (error) {
      if (error instanceof ApplicationPlatformError) throw error;
      throw new ApplicationPlatformError("invalid_redirect_uri", "Platform redirect URI contains a forbidden secret");
    }
  }
}

export function redactWechatProviderUrl(value: string): string {
  if (typeof value !== "string" || value.length === 0 || value.length > 8192) return "[REDACTED]";
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    return "[REDACTED]";
  }
  for (const [key, value] of [...parsed.searchParams.entries()]) {
    if (FORBIDDEN_REDIRECT_QUERY_KEYS.has(key.toLowerCase().replace(/[^a-z0-9]/gu, ""))) {
      parsed.searchParams.set(key, "[REDACTED]");
      continue;
    }
    if (/^[a-z][a-z0-9+.-]*:/iu.test(value) && /[?&]/u.test(value)) {
      const nested = redactWechatProviderUrl(value);
      if (nested !== "[REDACTED]") parsed.searchParams.set(key, nested);
    }
  }
  parsed.username = "";
  parsed.password = "";
  return parsed.toString();
}

function hasUnsafeRedirectText(value: string): boolean {
  if (/%(?![0-9a-f]{2})/iu.test(value)) return true;
  let decoded = value;
  for (let depth = 0; depth <= value.length; depth += 1) {
    if (/[\u0000-\u001f\u007f]/u.test(decoded) || decoded.includes("\\")) return true;
    if (!/%[0-9a-f]{2}/iu.test(decoded)) return false;
    try {
      const next = decodeURIComponent(decoded);
      if (next === decoded) return false;
      decoded = next;
    } catch {
      return true;
    }
  }
  return true;
}

function assertRedirectUri(
  value: unknown,
  allowInsecure: boolean,
  client: "web" | "native" | "mini_program" = "web",
): string {
  if (typeof value !== "string" || value.length === 0 || value.length > 2048 || /[\u0000-\u001f\u007f\s\\]/u.test(value) || hasUnsafeRedirectText(value)) {
    throw new ApplicationPlatformError("invalid_redirect_uri", "Platform redirect URI is invalid");
  }
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new ApplicationPlatformError("invalid_redirect_uri", "Platform redirect URI is invalid");
  }
  if (parsed.username !== "" || parsed.password !== "" || parsed.hash !== "") {
    throw new ApplicationPlatformError("invalid_redirect_uri", "Platform redirect URI is invalid");
  }
  assertRedirectQueryIsSafe(parsed);
  if (client === "native" || client === "mini_program") {
    if (parsed.protocol === "http:") {
      if (!isLoopbackHost(parsed.hostname)) throw new ApplicationPlatformError("invalid_redirect_uri", "Platform redirect URI is invalid");
      return parsed.toString();
    }
    if (parsed.protocol === "https:") {
      if (parsed.hostname.length === 0 || isLoopbackHost(parsed.hostname)) throw new ApplicationPlatformError("invalid_redirect_uri", "Platform redirect URI is invalid");
      return parsed.toString();
    }
    if (!isRfc8252PrivateUseRedirectUri(value)) throw new ApplicationPlatformError("invalid_redirect_uri", "Platform redirect URI is invalid");
    return parsed.toString();
  }
  if (
    (parsed.protocol !== "https:" && parsed.protocol !== "http:") ||
    parsed.hostname.length === 0
  ) {
    throw new ApplicationPlatformError("invalid_redirect_uri", "Platform redirect URI is invalid");
  }
  if (!allowInsecure && parsed.protocol !== "https:" && !isLoopbackHost(parsed.hostname)) {
    throw new ApplicationPlatformError("invalid_redirect_uri", "Platform redirect URI must use HTTPS");
  }
  return parsed.toString();
}

function assertCredential(value: unknown, field: string): string {
  if (typeof value !== "string") {
    throw new ApplicationPlatformError("invalid_credentials", "Platform credentials are invalid");
  }
  const normalized = value.trim();
  if (normalized.length === 0 || normalized.length > 512 || /[\u0000-\u001f\u007f\s]/u.test(normalized)) {
    throw new ApplicationPlatformError("invalid_credentials", "Platform credentials are invalid");
  }
  if (field === "appSecret" && normalized.length < 8) {
    throw new ApplicationPlatformError("invalid_credentials", "Platform credentials are invalid");
  }
  return normalized;
}

function assertCode(value: unknown): string {
  if (typeof value !== "string") {
    throw new ApplicationPlatformError("invalid_code", "Platform code is invalid");
  }
  const normalized = value.trim();
  if (normalized.length === 0 || normalized.length > 512 || /[\u0000-\u001f\u007f\s]/u.test(normalized)) {
    throw new ApplicationPlatformError("invalid_code", "Platform code is invalid");
  }
  return normalized;
}

function assertState(value: unknown): string {
  if (typeof value !== "string") {
    throw new ApplicationPlatformError("invalid_state", "Platform state is invalid");
  }
  const normalized = value.trim();
  if (normalized.length === 0 || normalized.length > 512 || /[\u0000-\u001f\u007f\s]/u.test(normalized)) {
    throw new ApplicationPlatformError("invalid_state", "Platform state is invalid");
  }
  return normalized;
}

function assertResponseString(value: unknown, field: string): string {
  if (typeof value !== "string") {
    throw new ApplicationPlatformError("invalid_response", `Platform provider omitted ${field}`);
  }
  const normalized = value.trim();
  if (normalized.length === 0 || normalized.length > 1024 || /[\u0000-\u001f\u007f]/u.test(normalized)) {
    throw new ApplicationPlatformError("invalid_response", `Platform provider returned an invalid ${field}`);
  }
  return normalized;
}

function optionalResponseString(value: unknown, field: string): string | undefined {
  if (value === undefined || value === null || value === "") return undefined;
  return assertResponseString(value, field);
}

function normalizeScopes(value: unknown): string[] {
  if (value === undefined) return [];
  const source = Array.isArray(value) ? value : typeof value === "string" ? value.split(/[\s,]+/u) : [];
  const output: string[] = [];
  for (const item of source) {
    if (typeof item !== "string") continue;
    const normalized = item.trim();
    if (normalized.length === 0 || normalized.length > 128 || /[\u0000-\u001f\u007f\s]/u.test(normalized)) continue;
    if (!output.includes(normalized)) output.push(normalized);
    if (output.length >= 32) break;
  }
  return output;
}

function safePlatformErrorMessage(code: string): string | undefined {
  switch (code) {
    case "invalid_adapter":
      return "Invalid application platform adapter";
    case "invalid_component_configuration":
      return "WeChat component configuration is invalid";
    case "invalid_component_operation":
      return "WeChat component operation is invalid";
    case "invalid_component_binding":
      return "WeChat authorized account binding is invalid";
    case "component_account_not_bound":
      return "WeChat authorized account is not bound";
    case "component_binding_unavailable":
      return "WeChat authorized account binding is unavailable";
    case "component_access_token_unavailable":
      return "WeChat component access token is unavailable";
    case "invalid_endpoint":
      return "Platform endpoint is invalid";
    case "authorization_not_supported":
      return "Application platform does not support browser authorization";
    case "invalid_redirect_uri":
      return "Platform redirect URI is invalid or not registered";
    case "invalid_credentials":
      return "Application platform credentials are unavailable";
    case "credential_unavailable":
      return "Application platform credentials are unavailable";
    case "application_unavailable":
      return "Application is unavailable";
    case "platform_unavailable":
      return "Application platform is unavailable";
    case "unsupported_platform":
      return "Application platform adapter is not registered";
    case "invalid_state":
      return "Platform state is invalid";
    case "invalid_code":
      return "Platform code is invalid";
    case "invalid_scope":
      return "Platform scope is invalid";
    case "invalid_response":
      return "Platform provider returned an invalid response";
    case "provider_error":
      return "Platform provider request failed";
    case "provider_unavailable":
      return "Platform provider is unavailable";
    case "fetch_unavailable":
      return "Platform HTTP client is unavailable";
    default:
      return undefined;
  }
}

function isLoopbackHost(hostname: string): boolean {
  return hostname === "localhost" || hostname === "127.0.0.1" || hostname === "[::1]";
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export * from "./platform-state.js";
export * from "./identity-linker.js";
export * from "./session-bridge.js";
export * from "./platform-flow.js";
