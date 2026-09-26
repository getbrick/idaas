import { createHash, randomBytes } from "node:crypto";
import {
  Body,
  Controller,
  Get,
  HttpCode,
  Inject,
  Optional,
  Param,
  Post,
  Query,
  Req,
  Res,
  ServiceUnavailableException,
  UseFilters,
} from "@nestjs/common";
import { ApplicationPlatformError, assertNoProviderSecrets, assertPlatformLoginReturnTo, assertPlatformSessionResponseSafe, normalizePlatformSessionIssueResult, toSafeApplicationPlatformError, type PlatformLoginStartResult, type PlatformSessionIssueResult } from "@getbrick/idaas-core";
import {
  CONTROL_PLANE_ERROR_CODES,
  ControlPlaneError,
  type ControlPlaneErrorResponse,
} from "./errors.js";
import {
  type ApplicationPlatformAuthService,
  type ApplicationPlatformCallbackRequest,
  type ApplicationPlatformNativeExchangeRequest,
  type ApplicationPlatformNativeLoginRequest,
  type ApplicationPlatformPublicLoginRequest,
} from "./application-platform-service.js";
import { ApplicationPlatformAuthService as PlatformAuthService } from "./application-platform-service.js";
import { Public, GETBRICK_TRUST_PROXY } from "@getbrick/idaas-nestjs";
import { ControlPlaneExceptionFilter } from "./filter.js";
import { CONTROL_PLANE_BASE_PATH } from "./types.js";

const PLATFORM_BINDING_COOKIE_PREFIX = "gb_platform_binding_";
const PLATFORM_BINDING_COOKIE_MAX_AGE_SECONDS = 600;
const PLATFORM_RATE_LIMIT_MAX = 60;
const PLATFORM_RATE_LIMIT_WINDOW_MS = 60_000;

@Controller(`${CONTROL_PLANE_BASE_PATH}/applications`)
@Public()
@UseFilters(ControlPlaneExceptionFilter)
export class ApplicationPlatformRuntimeController {
  private readonly rateLimiter = new PlatformRateLimiter(PLATFORM_RATE_LIMIT_MAX, PLATFORM_RATE_LIMIT_WINDOW_MS);

  constructor(
    @Optional()
    @Inject(PlatformAuthService)
    private readonly platformAuth?: ApplicationPlatformAuthService,
    @Optional()
    @Inject(GETBRICK_TRUST_PROXY)
    private readonly trustProxy?: boolean,
  ) {}

  @Post(":applicationId/platforms/:platformId/login/start")
  @HttpCode(200)
  async startLogin(
    @Param("applicationId") applicationId: string,
    @Param("platformId") platformId: string,
    @Body() body: unknown,
    @Req() request: RuntimeRequest,
    @Res() response?: unknown,
  ): Promise<PlatformLoginStartResult | undefined> {
    let result: PlatformLoginStartResult | undefined;
    await this.execute(request, response, async () => {
      const input = this.publicStartInput(body, request);
      const cookieName = bindingCookieName(applicationId, platformId);
      const bindingValue = createBindingValue();
      result = await this.requireService().createPublicLogin(
        applicationId,
        platformId,
        input,
        request,
        { browserId: bindingValue },
      );
      const maxAge = Math.max(1, Math.min(PLATFORM_BINDING_COOKIE_MAX_AGE_SECONDS, Math.ceil((Date.parse(result.expiresAt) - Date.now()) / 1000)));
      setCookie(response, serializeBindingCookie(cookieName, bindingValue, Number.isFinite(maxAge) ? maxAge : PLATFORM_BINDING_COOKIE_MAX_AGE_SECONDS));
      writeJson(response, 200, result);
    });
    return result;
  }

  @Get(":applicationId/platforms/:platformId/login/callback")
  @HttpCode(200)
  async getCallback(
    @Param("applicationId") applicationId: string,
    @Param("platformId") platformId: string,
    @Req() request: RuntimeRequest,
    @Res() response: unknown,
  ): Promise<void> {
    await this.completeWeb(applicationId, platformId, request, response, true);
  }

  @Post(":applicationId/platforms/:platformId/login/callback")
  @HttpCode(200)
  async postCallback(
    @Param("applicationId") applicationId: string,
    @Param("platformId") platformId: string,
    @Body() body: unknown,
    @Req() request: RuntimeRequest,
    @Res() response: unknown,
  ): Promise<void> {
    await this.completeWeb(applicationId, platformId, { ...request, body }, response);
  }

  @Post(":applicationId/platforms/:platformId/login/exchange")
  @HttpCode(200)
  async exchange(
    @Param("applicationId") applicationId: string,
    @Param("platformId") platformId: string,
    @Body() body: unknown,
    @Req() request: RuntimeRequest,
    @Res() response: unknown,
  ): Promise<void> {
    await this.completeWeb(applicationId, platformId, { ...request, body }, response);
  }

  @Post(":applicationId/platforms/:platformId/login/webview/start")
  @Post(":applicationId/platforms/:platformId/webview/start")
  @HttpCode(200)
  async startWebviewLogin(
    @Param("applicationId") applicationId: string,
    @Param("platformId") platformId: string,
    @Body() body: unknown,
    @Req() request: RuntimeRequest,
    @Res() response?: unknown,
  ): Promise<PlatformLoginStartResult | undefined> {
    let result: PlatformLoginStartResult | undefined;
    await this.execute(request, response, async () => {
      const input = this.publicStartInput(body, request, ["webview"]);
      const started = await this.requireService().startWebviewLogin(applicationId, platformId, { ...input, client: "webview" }, request);
      result = publicPlatformStartResult(started, input.flowBinding);
      writeJson(response, 200, result);
    });
    return result;
  }

  @Post(":applicationId/platforms/:platformId/login/native/start")
  @Post(":applicationId/platforms/:platformId/login/start/native")
  @HttpCode(200)
  async startNativeLogin(
    @Param("applicationId") applicationId: string,
    @Param("platformId") platformId: string,
    @Body() body: unknown,
    @Req() request: RuntimeRequest,
    @Res() response?: unknown,
  ): Promise<PlatformLoginStartResult | undefined> {
    let result: PlatformLoginStartResult | undefined;
    await this.execute(request, response, async () => {
       const input = this.publicStartInput(body, request, ["native", "mp_weixin"]);
       result = await this.requireService().startNativeLogin(applicationId, platformId, { ...input, client: "native" }, request);

      writeJson(response, 200, result);
    });
    return result;
  }

  @Post(":applicationId/platforms/:platformId/login/native/exchange")
  @Post(":applicationId/platforms/:platformId/login/exchange/native")
  @HttpCode(200)
  async exchangeNativeLogin(
    @Param("applicationId") applicationId: string,
    @Param("platformId") platformId: string,
    @Body() body: unknown,
    @Req() request: RuntimeRequest,
    @Res() response: unknown,
  ): Promise<void> {
    await this.execute(request, response, async () => {
      const input = this.nativeExchangeInput(body, request);
      const result = await this.requireService().exchangeNativeLogin(applicationId, platformId, input, request);
      if (result.session.response !== undefined) await assertPlatformSessionResponseSafe(result.session.response);
      writeJson(response, 200, publicSessionResult(result, true));
    });
  }

  @Post(":applicationId/platforms/:platformId/login/mini-program/exchange")
  @Post(":applicationId/platforms/:platformId/login/mp-weixin/exchange")
  @Post(":applicationId/platforms/:platformId/login/mp_weixin/exchange")
  @Post(":applicationId/platforms/:platformId/login/wechat/mini-program/exchange")
  @HttpCode(200)
  async exchangeMiniProgram(
    @Param("applicationId") applicationId: string,
    @Param("platformId") platformId: string,
    @Body() body: unknown,
    @Req() request: RuntimeRequest,
    @Res() response: unknown,
  ): Promise<void> {
    await this.execute(request, response, async () => {
      const input = this.miniProgramInput(body, request);
      const result = await this.requireService().exchangeMiniProgram(applicationId, platformId, input, request);
      if (result.session.response !== undefined) await assertPlatformSessionResponseSafe(result.session.response);
      writeJson(response, 200, publicSessionResult(result, true));
    });
  }

  @Post(":applicationId/platforms/:platformId/login/mini/exchange")
  @HttpCode(200)
  async exchangeMini(
    @Param("applicationId") applicationId: string,
    @Param("platformId") platformId: string,
    @Body() body: unknown,
    @Req() request: RuntimeRequest,
    @Res() response: unknown,
  ): Promise<void> {
    await this.exchangeMiniProgram(applicationId, platformId, body, request, response);
  }

  @Post(":applicationId/platforms/:platformId/login/session/refresh")
  @Post(":applicationId/platforms/:platformId/login/refresh")
  @Post(":applicationId/platforms/:platformId/session/refresh")
  @Post(":applicationId/platforms/:platformId/client-session/refresh")
  @HttpCode(200)
  async refreshSession(
    @Param("applicationId") applicationId: string,
    @Param("platformId") platformId: string,
    @Body() body: unknown,
    @Req() request: RuntimeRequest,
    @Res() response: unknown,
  ): Promise<void> {
    await this.execute(request, response, async () => {
      const result = await this.requireService().refreshSession(applicationId, platformId, this.sessionInput(body, request), request);
      writeJson(response, 200, publicClientSessionResult(result));
    });
  }

  @Post(":applicationId/platforms/:platformId/login/session/logout")
  @Post(":applicationId/platforms/:platformId/login/logout")
  @Post(":applicationId/platforms/:platformId/session/logout")
  @Post(":applicationId/platforms/:platformId/client-session/logout")
  @HttpCode(200)
  async logoutSession(
    @Param("applicationId") applicationId: string,
    @Param("platformId") platformId: string,
    @Body() body: unknown,
    @Req() request: RuntimeRequest,
    @Res() response: unknown,
  ): Promise<void> {
    await this.execute(request, response, async () => {
      const result = await this.requireService().logoutSession(applicationId, platformId, this.sessionInput(body, request), request);
      writeJson(response, 200, publicClientSessionResult(result));
    });
  }

  @Post(":applicationId/platforms/:platformId/login/session/revoke")
  @Post(":applicationId/platforms/:platformId/login/revoke")
  @Post(":applicationId/platforms/:platformId/session/revoke")
  @Post(":applicationId/platforms/:platformId/client-session/revoke")
  @HttpCode(200)
  async revokeSession(
    @Param("applicationId") applicationId: string,
    @Param("platformId") platformId: string,
    @Body() body: unknown,
    @Req() request: RuntimeRequest,
    @Res() response: unknown,
  ): Promise<void> {
    await this.execute(request, response, async () => {
      const result = await this.requireService().revokeSession(applicationId, platformId, this.sessionInput(body, request), request);
      writeJson(response, 200, publicClientSessionResult(result));
    });
  }

  @Post(":applicationId/platforms/:platformId/login/webview/ticket")
  @Post(":applicationId/platforms/:platformId/webview/ticket")
  @Post(":applicationId/platforms/:platformId/webview/ticket/issue")
  @Post(":applicationId/platforms/:platformId/webview/tickets")
  @Post(":applicationId/platforms/:platformId/webview/tickets/issue")
  @HttpCode(200)
  async issueWebviewTicket(
    @Param("applicationId") applicationId: string,
    @Param("platformId") platformId: string,
    @Body() body: unknown,
    @Req() request: RuntimeRequest,
    @Res() response: unknown,
  ): Promise<void> {
    await this.execute(request, response, async () => {
      const result = await this.requireService().issueWebviewTicket(applicationId, platformId, this.sessionInput(body, request), request);
      writeJson(response, 200, publicWebviewTicket(result));
    });
  }

  @Post(":applicationId/platforms/:platformId/login/webview/exchange")
  @Post(":applicationId/platforms/:platformId/webview/exchange")
  @Post(":applicationId/platforms/:platformId/webview/ticket/exchange")
  @Post(":applicationId/platforms/:platformId/webview/session")
  @HttpCode(200)
  async exchangeWebviewTicket(
    @Param("applicationId") applicationId: string,
    @Param("platformId") platformId: string,
    @Body() body: unknown,
    @Req() request: RuntimeRequest,
    @Res() response: unknown,
  ): Promise<void> {
    await this.execute(request, response, async () => {
      const value = isRecord(body) ? body : {};
      const session = this.sessionInput(value, request);
      assertNoSessionSecrets(value);
      const ticket = stringValue(value.ticket ?? value.ticketReference);
      if (ticket === undefined) throw new ApplicationPlatformError("invalid_webview_ticket", "Webview ticket is required");
      const result = await this.requireService().exchangeWebviewTicket(applicationId, platformId, { ...session, ticket }, request);
      writeJson(response, 200, publicClientSessionResult(result));
    });
  }

  private async completeWeb(
    applicationId: string,
    platformId: string,
    request: RuntimeRequest,
    response: unknown,
    allowReturnRedirect = false,
  ): Promise<void> {
    await this.execute(request, response, async () => {
      const cookieName = bindingCookieName(applicationId, platformId);
      const bindingValue = readBindingCookie(request, cookieName);
      if (bindingValue === undefined) {
        throw new ApplicationPlatformError("invalid_platform_binding", "Platform login browser binding is required");
      }
      const input = this.callbackInput(request);
      const result = await this.requireService().completePublicLogin(applicationId, platformId, input, request, { browserId: bindingValue });
      if (allowReturnRedirect && result.returnTo !== undefined) {
        const returnTo = assertPlatformLoginReturnTo(result.returnTo);
        const sessionResponse = result.session.response;
        if (sessionResponse !== undefined) await assertPlatformSessionResponseSafe(sessionResponse);
        await writeRedirectResponse(response, returnTo, sessionResponse, serializeExpiredCookie(cookieName));
        return;
      }
      clearCookie(response, cookieName);
      const sessionResponse = result.session.response;
      if (sessionResponse !== undefined) {
        await assertPlatformSessionResponseSafe(sessionResponse);
        await writeResponse(response, sessionResponse);
        return;
      }
      writeJson(response, 200, publicSessionResult(result, false));
    });
  }

  @Post(":applicationId/platforms/:platformId/login/webview/callback")
  @Post(":applicationId/platforms/:platformId/webview/callback")
  @HttpCode(200)
  async completeWebviewLogin(
    @Param("applicationId") applicationId: string,
    @Param("platformId") platformId: string,
    @Body() body: unknown,
    @Req() request: RuntimeRequest,
    @Res() response: unknown,
  ): Promise<void> {
    await this.completeWebview(applicationId, platformId, { ...request, body }, response, true);
  }

  @Get(":applicationId/platforms/:platformId/login/webview/callback")
  @Get(":applicationId/platforms/:platformId/webview/callback")
  @HttpCode(200)
  async getWebviewCallback(
    @Param("applicationId") applicationId: string,
    @Param("platformId") platformId: string,
    @Req() request: RuntimeRequest,
    @Res() response: unknown,
  ): Promise<void> {
    await this.completeWebview(applicationId, platformId, request, response, false);
  }

  private async completeWebview(
    applicationId: string,
    platformId: string,
    request: RuntimeRequest,
    response: unknown,
    bridgeCallback: boolean,
  ): Promise<void> {
    await this.execute(request, response, async () => {
      if (!bridgeCallback) {
        throw new ApplicationPlatformError("invalid_platform_binding", "Webview callback requires a bridge token");
      }
      const input = this.callbackInput(request, true);
      const result = await this.requireService().completeWebviewLogin(applicationId, platformId, input, request);
      const sessionResponse = result.session.response;
      if (sessionResponse !== undefined) {
        await assertPlatformSessionResponseSafe(sessionResponse);
        await writeResponse(response, sessionResponse);
        return;
      }
      writeJson(response, 200, publicSessionResult(result, true));
    });
  }

  private publicStartInput(body: unknown, request: RuntimeRequest, allowedClients: readonly string[] = []): ApplicationPlatformPublicLoginRequest {
    const value = isRecord(body) ? body : {};
    assertNoUntrustedLinkingFields(value);
    const webview = allowedClients.includes("webview");
    for (const key of ["client", "clientKind", "clientType"]) {
      if (allowedClients.length === 0 && Object.prototype.hasOwnProperty.call(value, key)) throw new ApplicationPlatformError("invalid_platform_client", "Platform client cannot be selected at this boundary");
    }
    if (allowedClients.length > 0) readRuntimeClientAliases(value, allowedClients);
    if (Object.prototype.hasOwnProperty.call(value, "return_to")) {
      throw new ApplicationPlatformError("invalid_return_to", "Platform login returnTo is invalid");
    }
    const hasReturnTo = Object.prototype.hasOwnProperty.call(value, "returnTo");
    if (hasReturnTo && !allowedClients.includes("web")) {
      throw new ApplicationPlatformError("invalid_return_to", "Platform login returnTo is only valid for web clients");
    }
    const returnTo = value.returnTo === undefined ? undefined : assertPlatformLoginReturnTo(value.returnTo);
    const redirectUri = stringValue(value.redirectUri);
    if (redirectUri === undefined) throw new ApplicationPlatformError("invalid_platform_request", "redirectUri is required");
    assertRedirectOrigin(request ?? {}, redirectUri);
    if (value.scope !== undefined && typeof value.scope !== "string") {
      throw new ApplicationPlatformError("invalid_platform_request", "Platform login request is invalid");
    }
    if (webview) {
      if (Object.prototype.hasOwnProperty.call(value, "flow_binding")) {
        throw new ApplicationPlatformError("invalid_platform_binding", "Webview login accepts only flowBinding");
      }
      const flowBinding = requireFlowBinding(value.flowBinding);
      return {
        redirectUri,
        ...(returnTo === undefined ? {} : { returnTo }),
        ...(typeof value.scope === "string" ? { scope: value.scope } : {}),
        flowBinding,
      };
    }
    if (Object.prototype.hasOwnProperty.call(value, "flowBinding") || Object.prototype.hasOwnProperty.call(value, "flow_binding")) {
      throw new ApplicationPlatformError("invalid_platform_request", "flowBinding is only valid for webview login");
    }
    return {
      redirectUri,
      ...(returnTo === undefined ? {} : { returnTo }),
      ...(typeof value.scope === "string" ? { scope: value.scope } : {}),
    };
  }

  private callbackInput(request: RuntimeRequest, webview = false): ApplicationPlatformCallbackRequest {
    const query = isRecord(request.query) ? request.query : {};
    const body = isRecord(request.body) ? request.body : {};
    const value = { ...query, ...body };
    if (Object.prototype.hasOwnProperty.call(value, "returnTo") || Object.prototype.hasOwnProperty.call(value, "return_to")) {
      throw new ApplicationPlatformError("invalid_platform_callback", "Platform callback cannot select returnTo");
    }
    assertNoUntrustedLinkingFields(value);
    for (const key of ["client", "clientKind", "clientType"]) {
      if (Object.prototype.hasOwnProperty.call(value, key)) throw new ApplicationPlatformError("invalid_platform_client", "Platform client cannot be selected at this boundary");
    }
    if (Object.prototype.hasOwnProperty.call(query, "flowBinding") || Object.prototype.hasOwnProperty.call(query, "flow_binding")) {
      throw new ApplicationPlatformError("invalid_platform_binding", "Webview callback flowBinding must be sent in the POST body");
    }
    if (!webview && (Object.prototype.hasOwnProperty.call(value, "flowBinding") || Object.prototype.hasOwnProperty.call(value, "flow_binding"))) {
      throw new ApplicationPlatformError("invalid_platform_request", "flowBinding is only valid for webview callback");
    }
    const state = stringValue(value.state);
    if (state === undefined) throw new ApplicationPlatformError("invalid_platform_request", "state is required");
    const flowBinding = webview ? requireFlowBinding(body.flowBinding) : undefined;
    return {
      state,
      ...(typeof value.code === "string" ? { code: value.code } : {}),
      ...(typeof value.authorization_code === "string" ? { authorizationCode: value.authorization_code } : {}),
      ...(typeof value.error === "string" ? { error: value.error } : {}),
      ...(typeof value.error_description === "string" ? { errorDescription: value.error_description } : {}),
      ...(typeof value.redirectUri === "string" ? { redirectUri: value.redirectUri } : {}),
      ...(flowBinding === undefined ? {} : { flowBinding }),
    };
  }


  private nativeExchangeInput(body: unknown, request: RuntimeRequest): ApplicationPlatformNativeExchangeRequest {
    const query = isRecord(request.query) ? request.query : {};
    const bodyValue = isRecord(body) ? body : {};
    const value = { ...query, ...bodyValue };
    assertNoUntrustedLinkingFields(value);
     for (const key of ["browser", "binding", "browserId", "browserBinding", "sessionId", "sessionBinding", "flowBinding", "flow_binding", "returnTo", "return_to"]) {
      if (Object.prototype.hasOwnProperty.call(value, key)) {
        throw new ApplicationPlatformError("invalid_platform_request", "Native exchange does not accept browser binding");
      }
    }
      const state = stringValue(value.state);
      if (state === undefined) throw new ApplicationPlatformError("invalid_platform_request", "state is required");
      const client = readRuntimeClientAliases(value, ["native", "mp_weixin", "mini_program"]);
      return {
        state,
        ...(typeof value.code === "string" ? { code: value.code } : {}),
        ...(typeof value.authorization_code === "string" ? { authorizationCode: value.authorization_code } : {}),
        ...(typeof value.error === "string" ? { error: value.error } : {}),
        ...(typeof value.error_description === "string" ? { errorDescription: value.error_description } : {}),
        ...(typeof value.redirectUri === "string" ? { redirectUri: value.redirectUri } : {}),
        ...(client === undefined ? {} : { client: client as "native" | "mp_weixin" | "mini_program" }),
      };
   }

   private miniProgramInput(body: unknown, request: RuntimeRequest): { code: string; redirectUri?: string; client?: "mp_weixin" | "mini_program"; clientKind?: "mp_weixin" | "mini_program" } {

    const value = isRecord(body) ? body : isRecord(request.body) ? request.body : {};
    assertNoUntrustedLinkingFields(value);
     for (const key of ["state", "authorizationCode", "error", "error_description", "browser", "binding", "browserId", "browserBinding", "sessionId", "sessionBinding", "flowBinding", "flow_binding", "returnTo", "return_to"]) {
      if (Object.prototype.hasOwnProperty.call(value, key)) {
        throw new ApplicationPlatformError("invalid_platform_request", "Mini-program exchange does not accept state or browser binding");
      }
    }
      const code = stringValue(value.code);
      if (code === undefined) throw new ApplicationPlatformError("invalid_platform_request", "code is required");
      const redirectUri = stringValue(value.redirectUri) ?? stringValue(value.redirect_uri);
      const client = readRuntimeClientAliases(value, ["mp_weixin", "mini_program"]);
      return {
        code,
        ...(redirectUri === undefined ? {} : { redirectUri }),
        ...(client === undefined ? {} : { client: client as "mp_weixin" | "mini_program" }),
      };

  }

  @Get(":applicationId/platforms/:platformId/webview/ticket")
  @Get(":applicationId/platforms/:platformId/login/webview/ticket")
  @HttpCode(200)
  async exchangeWebviewTicketGet(
    @Param("applicationId") applicationId: string,
    @Param("platformId") platformId: string,
    @Query() query: unknown,
    @Req() request: RuntimeRequest,
    @Res() response: unknown,
  ): Promise<void> {
    await this.execute(request, response, async () => {
      const value = isRecord(query) ? query : {};
      assertNoSessionSecrets(value);
      const ticket = stringValue(value.ticket);
      if (ticket === undefined) throw new ApplicationPlatformError("invalid_webview_ticket", "Webview ticket is required");
      const result = await this.requireService().exchangeWebviewTicket(applicationId, platformId, { ticket }, request);
      writeJson(response, 200, publicClientSessionResult(result));
    });
  }

  private sessionInput(body: unknown, request: RuntimeRequest): Record<string, unknown> {
    const value = isRecord(body) ? body : {};
    assertNoSessionSecrets(value);
    const headerReference = headerValue(request.headers ?? {}, "x-session-reference");
    if (value.sessionReference === undefined && value.session_reference === undefined && value.reference === undefined && headerReference !== undefined) {
      return { sessionReference: headerReference };
    }
    return value;
  }

  private requireService(): ApplicationPlatformAuthService {
    if (!this.platformAuth) throw new ServiceUnavailableException("Platform login is not configured");
    return this.platformAuth;
  }

  private async execute(request: RuntimeRequest, response: unknown, operation: () => Promise<void>): Promise<void> {
    setNoStore(response);
    const key = responseKey(request, this.trustProxy === true);
    try {
      this.rateLimiter.assertAllowed(key);
      await operation();
    } catch (error) {
      setNoStore(response);
      if (error instanceof ApplicationPlatformError) {
        const safe = toSafeApplicationPlatformError(error, "platform_operation_failed", "Platform operation failed");
        const normalized = normalizePlatformError(safe);
        if (normalized.code === CONTROL_PLANE_ERROR_CODES.RATE_LIMITED) {
          (response as { setHeader?: (name: string, value: string) => unknown } | undefined)?.setHeader?.("Retry-After", "60");
        }
        if (isWritableResponse(response)) {
          const body: ControlPlaneErrorResponse = normalized.toJSON();
          const requestId = requestIdFromRuntimeRequest(request);
          if (requestId !== undefined) body.requestId = requestId;
          writeJson(response, normalized.statusCode, body);
          return;
        }
        throw normalized;
      }
      throw error;
    }
  }
}

export interface RuntimeRequest {
  headers?: Record<string, unknown>;
  query?: unknown;
  body?: unknown;
  ip?: string;
}

class PlatformRateLimiter {
  private readonly entries = new Map<string, { count: number; resetAt: number }>();

  constructor(
    private readonly max: number,
    private readonly windowMs: number,
  ) {}

  assertAllowed(key: string): void {
    const now = Date.now();
    for (const [entryKey, entry] of this.entries) {
      if (entry.resetAt <= now) this.entries.delete(entryKey);
    }
    const current = this.entries.get(key);
    if (current === undefined || current.resetAt <= now) {
      if (this.entries.size >= 10_000) throw new ApplicationPlatformError("platform_rate_limited", "Platform login rate limit exceeded", 429);
      this.entries.set(key, { count: 1, resetAt: now + this.windowMs });
      return;
    }
    if (current.count >= this.max) {
      throw new ApplicationPlatformError("platform_rate_limited", "Platform login rate limit exceeded", 429);
    }
    current.count += 1;
  }
}

function assertNoUntrustedLinkingFields(value: Record<string, unknown>): void {
  for (const key of [
    "requestedUserId",
    "requested_user_id",
    "userId",
    "identityLinkingPolicy",
    "identity_linking_policy",
    "linkingPolicy",
    "linking_policy",
    "policy",
    "mode",
    "hostContext",
    "context",
    "authenticatedUserId",
    "tenantId",
    "tenant_id",
    "applicationId",
    "application_id",
    "platformId",
    "platform_id",
    "browser",
    "binding",
    "browserId",
    "browser_id",
    "browserBinding",
    "browser_binding",
    "sessionId",
    "session_id",
    "sessionBinding",
    "session_binding",
    "flow_binding",
  ]) {
    if (Object.prototype.hasOwnProperty.call(value, key)) {
      throw new ApplicationPlatformError("invalid_platform_request", "Platform request cannot select an identity linking policy");
    }
  }
}

function bindingCookieName(applicationId: string, platformId: string): string {
  const digest = createHash("sha256").update(`${applicationId}:${platformId}`, "utf8").digest("hex").slice(0, 24);
  return `${PLATFORM_BINDING_COOKIE_PREFIX}${digest}`;
}

function createBindingValue(): string {
  return randomBytes(32).toString("base64url");
}

function serializeBindingCookie(name: string, value: string, maxAge: number): string {
  return `${name}=${encodeURIComponent(value)}; Max-Age=${maxAge}; Path=/; HttpOnly; Secure; SameSite=Lax`;
}

function serializeExpiredCookie(name: string): string {
  return `${name}=; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=Lax`;
}

function readBindingCookie(request: RuntimeRequest, name: string): string | undefined {
  const header = headerValue(request.headers ?? {}, "cookie");
  if (header === undefined) return undefined;
  let found: string | undefined;
  for (const part of header.split(";")) {
    const separator = part.indexOf("=");
    if (separator < 0) continue;
    const key = part.slice(0, separator).trim();
    if (key !== name) continue;
    if (found !== undefined) return undefined;
    const value = part.slice(separator + 1).trim();
    try {
      const normalized = decodeURIComponent(value);
      if (/^[A-Za-z0-9_-]{32,512}$/u.test(normalized)) found = normalized;
      else return undefined;
    } catch {
      return undefined;
    }
  }
  return found;
}

function setCookie(response: unknown, value: string): void {
  const target = response as { setHeader?: (name: string, value: string | string[]) => unknown } | undefined;
  target?.setHeader?.("Set-Cookie", value);
}

function clearCookie(response: unknown, name: string): void {
  setCookie(response, serializeExpiredCookie(name));
}

function setNoStore(response: unknown): void {
  const target = response as { setHeader?: (name: string, value: string) => unknown } | undefined;
  target?.setHeader?.("Cache-Control", "no-store");
  target?.setHeader?.("Pragma", "no-cache");
  target?.setHeader?.("Referrer-Policy", "no-referrer");
}

function responseKey(request: RuntimeRequest, trustProxy: boolean): string {
  if (trustProxy) {
    const forwarded = headerValue(request.headers ?? {}, "x-forwarded-for");
    if (forwarded !== undefined) return forwarded.split(",")[0]?.trim() || "unknown";
  }
  return stringValue(request.ip) ?? "unknown";
}

function assertNoSessionSecrets(value: Record<string, unknown>): void {
  for (const key of [
    "token",
    "sessionToken",
    "session_token",
    "accessToken",
    "access_token",
    "refreshToken",
    "refresh_token",
    "idToken",
    "id_token",
    "hostSessionToken",
    "host_session_token",
    "clientSecret",
    "client_secret",
    "providerToken",
    "provider_token",
    "cookie",
    "authorization",
  ]) {
    if (Object.prototype.hasOwnProperty.call(value, key)) {
      throw new ApplicationPlatformError("invalid_session_reference", "Client session request cannot contain a host credential");
    }
  }
}

function publicClientSessionResult(value: {
  sessionReference: string;
  expiresAt: string;
  userId: string;
  applicationId: string;
  platformId: string;
  client: string;
  clientKind?: string;
  refreshed?: boolean;
  revoked?: boolean;
}): Record<string, unknown> {
  assertNoProviderSecrets(value);
  const clientKind = normalizePublicClientKind(value.clientKind ?? value.client);
  if (value.clientKind !== undefined && value.client !== undefined && normalizePublicClientKind(value.clientKind) !== normalizePublicClientKind(value.client)) {
    throw new ApplicationPlatformError("invalid_platform_client", "Platform client kind is inconsistent");
  }
  const sessionReference = safePublicSessionReference(value.sessionReference);
  return {
    sessionReference,
    expiresAt: value.expiresAt,
    clientKind,
    ...(value.refreshed === true ? { refreshed: true } : {}),
    ...(value.revoked === true ? { revoked: true } : {}),
  };
}

function publicPlatformStartResult(value: PlatformLoginStartResult, flowBinding?: string): PlatformLoginStartResult {
  const authorizationUrl = stringValue(value.authorizationUrl);
  const state = stringValue(value.state);
  const expiresAt = stringValue(value.expiresAt);
  if (authorizationUrl === undefined || state === undefined || expiresAt === undefined) {
    throw new ApplicationPlatformError("authorization_url_failed", "Platform login start response is invalid");
  }
  if (flowBinding !== undefined && (state.includes(flowBinding) || expiresAt.includes(flowBinding) || authorizationUrl.includes(flowBinding) || authorizationUrl.includes(encodeURIComponent(flowBinding)))) {
    throw new ApplicationPlatformError("authorization_url_failed", "Platform login start response exposed flowBinding");
  }
  const client = value.client === undefined ? "webview" : normalizePublicClientKind(value.client);
  if (client !== "webview") {
    throw new ApplicationPlatformError("invalid_platform_client", "Platform login start client is inconsistent");
  }
  return {
    authorizationUrl,
    state,
    expiresAt,
    client,
  };
}

function publicWebviewTicket(value: {
  ticket: string;
  ticketReference?: string;
  expiresAt: string;
  sessionReference?: string;
  applicationId?: string;
  platformId?: string;
  client?: string;
  clientKind?: string;
  redirectUri?: string;
}): Record<string, unknown> {
  assertNoProviderSecrets(value);
  return {
    ticket: value.ticket,
    ...(value.ticketReference === undefined ? {} : { ticketReference: value.ticketReference }),
    expiresAt: value.expiresAt,
    ...(value.applicationId === undefined ? {} : { applicationId: value.applicationId }),
    ...(value.platformId === undefined ? {} : { platformId: value.platformId }),
    ...(value.client === undefined ? {} : { client: value.client }),
    clientKind: "webview",
    ...(value.redirectUri === undefined ? {} : { redirectUri: value.redirectUri }),
  };
}

function publicSessionResult(result: {
  user: unknown;
  identity: unknown;
  account: unknown;
  session: PlatformSessionIssueResult;
  created: boolean;
  linked: boolean;
  client?: string;
}, includeSessionReference: boolean): Record<string, unknown> {
  const user = publicUserResult(result.user);
  const session = normalizePlatformSessionIssueResult(result.session);
  const sessionReference = session.sessionReference ?? session.sessionId;
  const clientKind = normalizePublicClientKind(session.clientKind ?? result.client);
  if (session.clientKind !== undefined && result.client !== undefined && normalizePublicClientKind(session.clientKind) !== normalizePublicClientKind(result.client)) {
    throw new ApplicationPlatformError("invalid_session_issuer_result", "Platform session client kind is inconsistent");
  }
  if (includeSessionReference && (sessionReference === undefined || session.response !== undefined)) {
    throw new ApplicationPlatformError("invalid_session_issuer_result", "Platform session issuer did not return an opaque client session");
  }
  const publicSession: Record<string, unknown> = { clientKind };
  if (includeSessionReference && sessionReference !== undefined) publicSession.sessionReference = safePublicSessionReference(sessionReference);
  if (session.expiresAt !== undefined) publicSession.expiresAt = session.expiresAt;
  return {
    user,
    created: result.created === true,
    linked: result.linked === true,
    clientKind,
    session: publicSession,
  };
}

function responseCookies(response: Response | undefined): string[] {
  if (response === undefined) return [];
  const getSetCookie = (response.headers as Headers & { getSetCookie?: () => string[] }).getSetCookie;
  if (typeof getSetCookie === "function") {
    const values = getSetCookie.call(response.headers);
    if (values.length > 0) return values;
  }
  const value = response.headers.get("set-cookie");
  return value === null ? [] : [value];
}

function assertSafeSessionResponse(response: Response | undefined): void {
  for (const cookie of responseCookies(response)) {
    const parts = cookie.split(";").map((part) => part.trim()).filter((part) => part.length > 0);
    if (parts.length < 2) throw new ApplicationPlatformError("invalid_session_issuer_result", "Platform session cookie is invalid");
    const separator = parts[0]?.indexOf("=") ?? -1;
    if (separator <= 0 || parts[0]?.slice(separator + 1).length === 0) throw new ApplicationPlatformError("invalid_session_issuer_result", "Platform session cookie is invalid");
    const attributes = new Map<string, string>();
    for (const part of parts.slice(1)) {
      const equals = part.indexOf("=");
      const key = (equals === -1 ? part : part.slice(0, equals)).trim().toLowerCase();
      const attributeValue = equals === -1 ? "" : part.slice(equals + 1).trim();
      if (key.length === 0 || attributes.has(key)) throw new ApplicationPlatformError("invalid_session_issuer_result", "Platform session cookie is invalid");
      attributes.set(key, attributeValue);
    }
    const sameSite = attributes.get("samesite")?.toLowerCase();
    if (attributes.get("httponly") !== "" || attributes.get("secure") !== "" || attributes.has("domain") || attributes.get("path") !== "/" || (sameSite !== "lax" && sameSite !== "strict" && sameSite !== "none")) {
      throw new ApplicationPlatformError("invalid_session_issuer_result", "Platform session cookie is invalid");
    }
  }
}

async function writeRedirectResponse(target: unknown, location: string, response?: Response, clearedCookie?: string): Promise<void> {
  assertSafeSessionResponse(response);
  const res = target as {
    status?: (code: number) => unknown;
    setHeader?: (name: string, value: string | string[]) => unknown;
    getHeader?: (name: string) => unknown;
    end?: (body?: Buffer) => unknown;
  };
  setNoStore(target);
  if (response !== undefined) {
    response.headers.forEach((value, key) => {
      const normalized = key.toLowerCase();
      if (normalized === "location" || normalized === "set-cookie" || normalized === "content-length" || normalized === "content-type") return;
      res.setHeader?.(key, value);
    });
  }
  const cookies = responseCookies(response);
  if (cookies.length > 0 || clearedCookie !== undefined) {
    const existing = res.getHeader?.("Set-Cookie");
    const existingCookies = Array.isArray(existing)
      ? existing.map(String)
      : existing === undefined
        ? []
        : [String(existing)];
    const mergedCookies = [...existingCookies, ...cookies];
    if (clearedCookie !== undefined && !mergedCookies.includes(clearedCookie)) mergedCookies.push(clearedCookie);
    res.setHeader?.("Set-Cookie", mergedCookies);
  }
  setNoStore(target);
  if (typeof res.status === "function") res.status(303);
  else (res as { statusCode?: number }).statusCode = 303;
  res.setHeader?.("Location", assertPlatformLoginReturnTo(location));
  res.end?.();
}

async function writeResponse(target: unknown, response: Response): Promise<void> {
  assertSafeSessionResponse(response);
  const res = target as {
    status?: (code: number) => unknown;
    setHeader?: (name: string, value: string | string[]) => unknown;
    end?: (body?: Buffer) => unknown;
  };
  setNoStore(target);
  res.status?.(response.status);
  response.headers.forEach((value, key) => {
    const normalized = key.toLowerCase();
    if (normalized === "location" || normalized === "set-cookie" || normalized === "content-length" || normalized === "content-type") return;
    res.setHeader?.(key, value);
  });
  const cookies = responseCookies(response);
  if (cookies.length > 0) {
    const existing = typeof (res as { getHeader?: (name: string) => unknown }).getHeader === "function"
      ? (res as { getHeader: (name: string) => unknown }).getHeader("Set-Cookie")
      : undefined;
    const existingCookies = Array.isArray(existing) ? existing.map(String) : existing === undefined ? [] : [String(existing)];
    res.setHeader?.("Set-Cookie", [...existingCookies, ...cookies]);
  }
  setNoStore(target);
  res.end?.();
}

function writeJson(target: unknown, status: number, body: unknown): void {
  const res = target as {
    status?: (code: number) => unknown;
    json?: (value: unknown) => unknown;
    setHeader?: (name: string, value: string) => unknown;
    end?: (value?: string) => unknown;
  };
  setNoStore(target);
  res.status?.(status);
  if (typeof res.json === "function") {
    res.json(body);
    return;
  }
  res.setHeader?.("Content-Type", "application/json");
  res.end?.(JSON.stringify(body));
}

function assertRedirectOrigin(request: RuntimeRequest, redirectUri: string): void {
  const origin = headerValue(request.headers ?? {}, "origin") ?? headerValue(request.headers ?? {}, "referer");
  if (origin === undefined) return;
  let originUrl: URL;
  let redirectUrl: URL;
  try {
    originUrl = new URL(origin);
    redirectUrl = new URL(redirectUri);
  } catch {
    throw new ApplicationPlatformError("invalid_redirect_uri", "redirectUri origin is invalid");
  }
  if (redirectUrl.protocol !== "http:" && redirectUrl.protocol !== "https:") return;
  if (originUrl.origin !== redirectUrl.origin) {
    throw new ApplicationPlatformError("invalid_redirect_uri", "redirectUri origin is not allowed");
  }
}

function headerValue(headers: Record<string, unknown>, name: string): string | undefined {
  const entry = Object.entries(headers).find(([key]) => key.toLowerCase() === name);
  const value = Array.isArray(entry?.[1]) ? entry?.[1][0] : entry?.[1];
  return stringValue(value);
}

function requireFlowBinding(value: unknown): string {
  if (
    typeof value !== "string" ||
    value.length < 22 ||
    value.length > 128 ||
    !/^[A-Za-z0-9_-]+$/u.test(value)
  ) {
    throw new ApplicationPlatformError("invalid_platform_binding", "Webview flowBinding is invalid");
  }
  return value;
}

function stringValue(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  const normalized = value.trim();
  return normalized.length > 0 && normalized.length <= 2048 && !/[\u0000-\u001f\u007f]/u.test(normalized) ? normalized : undefined;
}

function readRuntimeClientAliases(value: Record<string, unknown>, allowed: readonly string[]): "web" | "webview" | "mp_weixin" | "native" | undefined {
  const present = ["client", "clientKind", "clientType"].filter((key) => Object.prototype.hasOwnProperty.call(value, key));
  if (present.length === 0) return undefined;
  const normalized: Array<"web" | "webview" | "mp_weixin" | "native"> = [];
  for (const key of present) {
    const raw = value[key];
    if (typeof raw !== "string" || raw.trim().length === 0) {
      throw new ApplicationPlatformError("invalid_platform_client", "Platform client is invalid");
    }
    const clientKind = normalizePublicClientKind(raw.trim());
    if (!allowed.includes(clientKind)) {
      throw new ApplicationPlatformError("invalid_platform_client", "Platform client is invalid");
    }
    normalized.push(clientKind);
  }
  if (new Set(normalized).size > 1) {
    throw new ApplicationPlatformError("invalid_platform_client", "Platform client aliases conflict");
  }
  return normalized[0];
}

function normalizePublicClientKind(value: unknown): "web" | "webview" | "mp_weixin" | "native" {
  if (value === undefined || value === "web") return "web";
  if (value === "mini_program") return "mp_weixin";
  if (value === "webview" || value === "mp_weixin" || value === "native") return value;
  throw new ApplicationPlatformError("invalid_platform_client", "Platform client is invalid");
}

function safePublicSessionReference(value: unknown): string {
  if (typeof value !== "string") throw new ApplicationPlatformError("invalid_session_issuer_result", "Platform session issuer did not return an opaque client session");
  const normalized = value.trim();
  if (normalized.length < 8 || normalized.length > 512 || /[\u0000-\u001f\u007f\s]/u.test(normalized) || /(?:provider|access[_-]?token|refresh[_-]?token|id[_-]?token|session[_-]?key|authorization[_-]?code|(?:^|[^a-z])code(?:$|[^a-z])|(?:^|[^a-z])state(?:$|[^a-z]))/iu.test(normalized)) {
    throw new ApplicationPlatformError("session_issuer_secret_exposed", "Platform session issuer returned a forbidden session reference");
  }
  return normalized;
}

function publicUserResult(value: unknown): Record<string, unknown> {
  if (!isRecord(value)) throw new ApplicationPlatformError("invalid_session_issuer_result", "Platform session issuer returned an invalid public user");
  const name = typeof value.name === "string" ? value.name.trim() : "Platform user";
  if (name.length === 0 || name.length > 1024 || /[\u0000-\u001f\u007f]/u.test(name)) throw new ApplicationPlatformError("invalid_session_issuer_result", "Platform session issuer returned an invalid public user");
  const email = value.email === null || value.email === undefined ? null : typeof value.email === "string" ? value.email.trim().toLowerCase() : null;
  if (value.email !== undefined && value.email !== null && (email === null || email.length === 0 || email.length > 320 || !email.includes("@") || email.endsWith("@placeholder.invalid"))) {
    throw new ApplicationPlatformError("invalid_session_issuer_result", "Platform session issuer returned an invalid public user");
  }
  const user: Record<string, unknown> = {
    name,
    email,
    emailVerified: value.emailVerified === true && email !== null,
  };
  if (typeof value.id === "string") {
    const id = value.id.trim();
    if (id.length === 0 || id.length > 512 || /[\u0000-\u001f\u007f]/u.test(id)) throw new ApplicationPlatformError("invalid_session_issuer_result", "Platform session issuer returned an invalid public user");
    user.id = id;
  }
  if (typeof value.image === "string" && value.image.trim().length > 0) user.image = value.image.trim();
  return user;
}

function normalizePlatformError(error: { code: string; message: string }): ControlPlaneError {
  const statusCode = platformStatusForCode(error.code);
  const code = platformCodeForStatus(error.code, statusCode);
  return new ControlPlaneError(code, error.message, {
    statusCode,
    details: { reason: error.code },
  });
}

function platformCodeForStatus(code: string, statusCode: number): (typeof CONTROL_PLANE_ERROR_CODES)[keyof typeof CONTROL_PLANE_ERROR_CODES] {
  if (statusCode === 429) return CONTROL_PLANE_ERROR_CODES.RATE_LIMITED;
  if (statusCode === 403) return CONTROL_PLANE_ERROR_CODES.FORBIDDEN;
  if (statusCode === 409) return CONTROL_PLANE_ERROR_CODES.CONFLICT;
  if (statusCode === 502) return CONTROL_PLANE_ERROR_CODES.DEPENDENCY_UNAVAILABLE;
  if (statusCode === 503) return CONTROL_PLANE_ERROR_CODES.SERVICE_UNAVAILABLE;
  if (statusCode === 404) return CONTROL_PLANE_ERROR_CODES.NOT_FOUND;
  return CONTROL_PLANE_ERROR_CODES.INVALID_REQUEST;
}

function platformStatusForCode(code: string): number {
  if (code === "platform_rate_limited") return 429;
  if (code === "host_context_unavailable" || code === "platform_state_store_unavailable" || code === "platform_unavailable" || code === "credential_unavailable" || code === "component_credentials_unavailable" || code === "component_adapter_not_configured" || code === "invalid_platform_state_store") return 503;
  if (code === "session_issue_failed" || code === "session_issuer_secret_exposed" || code === "authorization_url_failed" || code === "platform_exchange_failed") return 502;
  if (code === "invalid_session_issuer_result") return 400;
  if (code === "session_not_configured" || code === "webview_ticket_not_configured" || code === "platform_session_not_configured") return 503;
  if (code === "session_not_found" || code === "invalid_webview_ticket") return 404;
  if (code === "session_scope_mismatch" || code === "webview_ticket_scope_mismatch") return 409;
  if (code === "session_refresh_failed" || code === "session_revoke_failed" || code === "session_issuer_invalid") return 502;
  if (code === "identity_link_authorization_required" || code === "explicit_identity_link_required" || code === "identity_linking_rejected" || code === "verified_email_required") return 403;
  if (code === "identity_link_target_mismatch" || code === "identity_email_conflict" || code === "identity_link_scope_mismatch" || code === "platform_state_tenant_mismatch") return 409;
  if (code === "platform_not_found" || code === "application_not_found") return 404;
  return 400;
}

function requestIdFromRuntimeRequest(request: RuntimeRequest): string | undefined {
  const header = Object.entries(request.headers ?? {}).find(([key]) => key.toLowerCase() === "x-request-id" || key.toLowerCase() === "x-correlation-id")?.[1];
  const value = Array.isArray(header) ? header[0] : header;
  if (typeof value !== "string") return undefined;
  const normalized = value.trim();
  return normalized.length > 0 && normalized.length <= 128 && !/[\u0000-\u001f\u007f]/u.test(normalized) && !/(?:secret|token|password|private[-_]?key|credential|authorization|cookie|vault:\/\/)/iu.test(normalized)
    ? normalized
    : undefined;
}

function isWritableResponse(value: unknown): boolean {
  const target = value as { status?: unknown; json?: unknown; end?: unknown } | undefined;
  return typeof target?.status === "function" && (typeof target?.json === "function" || typeof target?.end === "function");
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
