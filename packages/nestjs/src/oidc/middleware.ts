import { createHash } from "node:crypto";
import { Inject, Injectable, Optional, type NestMiddleware } from "@nestjs/common";
import { getSessionFromRequest } from "../request.js";
import {
  GETBRICK_OIDC_AUTH,
  GETBRICK_OIDC_LOGIN_URL,
  GETBRICK_OIDC_PLATFORM_LOGIN_HANDLER,
  GETBRICK_OIDC_RUNTIME,
  type GetbrickAuthLike,
} from "../tokens.js";
import {
  createOidcConsentContext,
  isExactOidcRedirectUri,
  isOidcProtocolReservedClaim,
  isValidOidcClaimName,
  isValidOidcScope,
  isValidPlatformLoginReturnTo,
  normalizeOidcConsentPolicy,
  OIDC_REQUIRED_CONSENT_SCOPES,
  readOidcConsentClaims,
  readOidcConsentScopes,
  requiresExplicitOidcConsent,
  resolveOidcConsentDecision,
  validateOidcConsentDecision,
  type OidcConsentContext,
  type OidcConsentDecision,
  type OidcLogoutOperation,
  type OidcLogoutRequest,
  type OidcLogoutResult,
  type OidcProviderRuntime,
} from "@getbrick/idaas-core";
import {
  createOidcLogoutIdempotencyKey,
  DEFAULT_OIDC_LOGOUT_MAX_OPERATIONS,
  DEFAULT_OIDC_LOGOUT_STATE_TTL_MS,
  DEFAULT_OIDC_LOGOUT_TENANT_ID,
  GETBRICK_OIDC_LOGOUT_COORDINATOR,
  type OidcLogoutCoordinatorLike,
  type OidcLogoutRequestContext,
} from "./logout-coordinator.js";

export { GETBRICK_OIDC_LOGOUT_COORDINATOR } from "./logout-coordinator.js";

export interface OidcAdapterRequest {
  originalUrl?: string;
  url?: string;
  method: string;
  headers: Record<string, unknown>;
  body?: unknown;
}

export interface OidcPlatformLoginRequest {
  returnTo: string;
  reauthenticate?: boolean;
  request: OidcAdapterRequest;
  response: unknown;
}

export interface OidcPlatformLoginResult {
  redirectUrl: string;
}

export type OidcPlatformLoginHandler = (
  input: OidcPlatformLoginRequest,
) => OidcPlatformLoginResult | Promise<OidcPlatformLoginResult>;

interface PendingLogoutRequest {
  clientId?: string;
  redirectUri?: string;
  userId?: string;
  operation?: OidcLogoutOperation;
}

@Injectable()
export class GetbrickOidcMiddleware implements NestMiddleware {
  private readonly pendingLogoutRequests = new Map<string, PendingLogoutRequest>();
  private readonly pendingLogoutExpiresAt = new Map<string, number>();
  private readonly pendingLogoutTtlMs = DEFAULT_OIDC_LOGOUT_STATE_TTL_MS;
  private readonly maxPendingLogoutRequests = DEFAULT_OIDC_LOGOUT_MAX_OPERATIONS;

  constructor(
    @Inject(GETBRICK_OIDC_RUNTIME) private readonly runtime: OidcProviderRuntime,
    @Inject(GETBRICK_OIDC_AUTH) private readonly auth: GetbrickAuthLike,
    @Optional() @Inject(GETBRICK_OIDC_LOGIN_URL) private readonly loginURL?: string,
    @Optional() @Inject(GETBRICK_OIDC_PLATFORM_LOGIN_HANDLER)
    private readonly platformLoginHandler?: OidcPlatformLoginHandler,
    @Optional() @Inject(GETBRICK_OIDC_LOGOUT_COORDINATOR)
    private readonly logoutCoordinator?: OidcLogoutCoordinatorLike,
  ) {}

  async use(req: OidcAdapterRequest, res: any, next: () => void): Promise<void> {
    const originalUrl = req.originalUrl ?? req.url ?? "/";
    const pathname = getPathname(originalUrl);
    if (!isOidcRequestPath(pathname, this.runtime)) {
      next();
      return;
    }
    this.prunePendingLogoutRequests();

    try {
      canonicalizeProviderRequest(req, this.runtime.issuer);
      if (isInteractionPath(pathname, this.runtime)) {
        await this.handleInteraction(req, res, originalUrl);
        return;
      }
      const logout = isEndSessionPath(pathname, this.runtime);
      if (!logout && isAuthorizationPath(pathname, this.runtime)) {
        await assertExactProviderRedirect(req, this.runtime);
      }
      const provider = this.runtime.provider as unknown as {
        on?: (event: string, listener: (context: unknown) => void) => unknown;
        off?: (event: string, listener: (context: unknown) => void) => unknown;
      };
      let logoutPromise: Promise<void> | undefined;
      let onEndSessionSuccess: ((context: unknown) => void) | undefined;
      let pendingLogout: PendingLogoutRequest | undefined;
      let responseGuard: DeferredResponse | undefined;
      if (logout) {
        if (this.logoutCoordinator === undefined) throw new Error("OIDC logout coordinator is unavailable");
        if (isEndSessionStartPath(pathname, this.runtime)) {
          pendingLogout = await this.preflightLogout(req, originalUrl);
        }
        if (typeof provider.on !== "function") {
          throw new Error("OIDC logout completion hook is unavailable");
        }
        onEndSessionSuccess = (context: unknown): void => {
          if (logoutPromise !== undefined) return;
          const completion = this.completeLogout(context, req, pendingLogout).then((result) => {
            if (!result.completed) throw new Error("OIDC logout did not complete");
          });
          logoutPromise = completion;
          void completion.catch(() => undefined);
        };
        provider.on("end_session.success", onEndSessionSuccess);
        responseGuard = deferResponse(res);
      }
      try {
        rewriteProviderRequest(req, originalUrl, this.runtime.basePath);
        const callback = (
          this.runtime.provider.callback as unknown as () => (
            request: OidcAdapterRequest,
            response: any,
          ) => void | Promise<void>
        )();
        await Promise.resolve(callback(req, res));
        if (logout) {
          if (logoutPromise !== undefined) {
            await logoutPromise;
          } else if (!isEndSessionStartPath(pathname, this.runtime)) {
            throw new Error("OIDC logout did not reach its completion hook");
          } else {
            const session = await getSessionFromRequest(this.auth, req);
            if (session?.user?.id === undefined) this.deletePendingLogoutRequest(req);
          }
        }
        responseGuard?.release();
        responseGuard = undefined;
      } finally {
        try {
          if (logout && onEndSessionSuccess !== undefined) provider.off?.("end_session.success", onEndSessionSuccess);
        } finally {
          responseGuard?.abort();
        }
      }
    } catch (error) {
      this.deletePendingLogoutRequest(req);
      if (res.headersSent) {
        res.end();
        return;
      }
      if (isInvalidOidcRequestError(error)) {
        writeJsonError(res, 400, "invalid_request");
        return;
      }
      if (typeof res.status === "function") {
        res.status(500);
      } else {
        res.statusCode = 500;
      }
      if (typeof res.json === "function") {
        res.json({ error: "server_error" });
        return;
      }
      res.setHeader?.("Content-Type", "application/json");
      res.end?.(JSON.stringify({ error: "server_error" }));
    }
  }

  private async preflightLogout(req: OidcAdapterRequest, originalUrl: string): Promise<PendingLogoutRequest> {
    if (this.logoutCoordinator === undefined) throw new Error("OIDC logout coordinator is unavailable");
    const url = new URL(originalUrl, this.runtime.issuer);
    const clientId = readSingleQueryValue(url, "client_id");
    const redirectUri = readSingleQueryValue(url, "post_logout_redirect_uri");
    const idTokenHint = readSingleQueryValue(url, "id_token_hint");
    const session = await getSessionFromRequest(this.auth, req);
    const userId = readString(session?.user?.id);
    const pending: PendingLogoutRequest = {
      ...(clientId === undefined ? {} : { clientId }),
      ...(redirectUri === undefined ? {} : { redirectUri }),
      ...(userId === undefined ? {} : { userId }),
    };
    this.setPendingLogoutRequest(req, pending);
    if (clientId === undefined) return pending;
    const request: OidcLogoutRequest = {
      tenantId: readCoordinatorText(this.logoutCoordinator, "tenantId") ?? DEFAULT_OIDC_LOGOUT_TENANT_ID,
      ...(readCoordinatorText(this.logoutCoordinator, "applicationId") === undefined
        ? {}
        : { applicationId: readCoordinatorText(this.logoutCoordinator, "applicationId") }),
      clientId,
      ...(userId === undefined ? {} : { userId }),
      ...(redirectUri === undefined ? {} : { postLogoutRedirectUri: redirectUri }),
      ...(idTokenHint === undefined ? {} : { idTokenHint }),
      idempotencyKey: createOidcLogoutIdempotencyKey({
        tenantId: readCoordinatorText(this.logoutCoordinator, "tenantId") ?? DEFAULT_OIDC_LOGOUT_TENANT_ID,
        ...(readCoordinatorText(this.logoutCoordinator, "applicationId") === undefined
          ? {}
          : { applicationId: readCoordinatorText(this.logoutCoordinator, "applicationId") }),
        clientId,
        ...(userId === undefined ? {} : { userId }),
        ...(redirectUri === undefined ? {} : { postLogoutRedirectUri: redirectUri }),
      }),
    };
    try {
      pending.operation = await this.logoutCoordinator.prepare(request);
      this.setPendingLogoutRequest(req, pending);
    } catch (error) {
      this.deletePendingLogoutRequest(req);
      throw error;
    }
    return pending;
  }

  private async completeLogout(
    context: unknown,
    req: OidcAdapterRequest,
    pending?: PendingLogoutRequest,
  ): Promise<OidcLogoutResult> {
    if (this.logoutCoordinator === undefined) throw new Error("OIDC logout coordinator is unavailable");
    const details = readProviderLogoutContext(context);
    const clientId = details.clientId;
    if (clientId === undefined) throw new Error("OIDC logout client was not verified");
    const stored = pending ?? this.pendingLogoutRequests.get(logoutRequestKey(req));
    if (stored?.clientId !== undefined && stored.clientId !== clientId) {
      throw new Error("OIDC logout client verification failed");
    }
    if (
      stored?.redirectUri !== undefined &&
      details.postLogoutRedirectUri !== undefined &&
      stored.redirectUri !== details.postLogoutRedirectUri
    ) {
      throw new Error("OIDC logout redirect verification failed");
    }
    const hostSession = await getSessionFromRequest(this.auth, req);
    const hostUserId = readString(hostSession?.user?.id);
    if (details.userId !== undefined && hostUserId !== undefined && details.userId !== hostUserId) {
      throw new Error("OIDC logout session binding failed");
    }
    const userId = details.userId ?? stored?.userId ?? hostUserId;
    const redirectUri = stored?.redirectUri ?? details.postLogoutRedirectUri;
    const request: OidcLogoutRequest = {
      tenantId: readCoordinatorText(this.logoutCoordinator, "tenantId") ?? DEFAULT_OIDC_LOGOUT_TENANT_ID,
      ...(readCoordinatorText(this.logoutCoordinator, "applicationId") === undefined
        ? {}
        : { applicationId: readCoordinatorText(this.logoutCoordinator, "applicationId") }),
      clientId,
      ...(userId === undefined ? {} : { userId }),
      ...(details.providerSessionId === undefined ? {} : { providerSessionId: details.providerSessionId }),
      ...(redirectUri === undefined ? {} : { postLogoutRedirectUri: redirectUri }),
      idempotencyKey: createOidcLogoutIdempotencyKey({
        tenantId: readCoordinatorText(this.logoutCoordinator, "tenantId") ?? DEFAULT_OIDC_LOGOUT_TENANT_ID,
        ...(readCoordinatorText(this.logoutCoordinator, "applicationId") === undefined
          ? {}
          : { applicationId: readCoordinatorText(this.logoutCoordinator, "applicationId") }),
        clientId,
        ...(userId === undefined ? {} : { userId }),
        ...(details.providerSessionId === undefined ? {} : { providerSessionId: details.providerSessionId }),
        ...(redirectUri === undefined ? {} : { postLogoutRedirectUri: redirectUri }),
      }),
    };
    const operation = stored?.operation ?? await this.logoutCoordinator.prepare(request);
    if (operation.clientId !== clientId) throw new Error("OIDC logout client verification failed");
    const requestContext: OidcLogoutRequestContext = {
      headers: contextHeadersRecord(context, req),
      response: contextResponse(context),
      clientId,
      ...(details.userId === undefined ? {} : { userId: details.userId }),
      ...(details.providerSessionId === undefined ? {} : { providerSessionId: details.providerSessionId }),
      ...(details.postLogoutRedirectUri === undefined ? {} : { postLogoutRedirectUri: details.postLogoutRedirectUri }),
      providerSessionRevoked: true,
      grantIds: details.grantIds,
    };
    try {
      return await this.logoutCoordinator.complete(operation, requestContext);
    } finally {
      this.deletePendingLogoutRequest(req);
    }
  }

  private async handleInteraction(
    req: OidcAdapterRequest,
    res: any,
    originalUrl: string,
  ): Promise<void> {
    const details = await this.runtime.provider.interactionDetails(req as any, res) as unknown as {
      uid?: string;
      grantId?: string;
      params: Record<string, unknown>;
      prompt: {
        name: string;
        reasons?: string[];
        details?: Record<string, unknown>;
      };
      session?: {
        accountId?: string;
        clientId?: string;
      };
    };

    const routeUid = readInteractionUid(originalUrl, this.runtime);
    if (routeUid === undefined) {
      writeJsonError(res, 400, "invalid_request");
      return;
    }
    if (typeof details.uid !== "string" || details.uid !== routeUid) {
      await this.denyInteraction(req, res);
      return;
    }
    const session = await getSessionFromRequest(this.auth, req);
    const userId = session?.user?.id;
    if (details.prompt.name === "consent") {
      if (typeof userId !== "string" || userId.length === 0) {
        await this.redirectToLogin(req, res, originalUrl);
        return;
      }
      const interactionAccountId = details.session?.accountId;
      const interactionClientId = details.session?.clientId;
      const requestedClientId = details.params.client_id;
      if (
        (typeof interactionAccountId === "string" && interactionAccountId !== userId) ||
        (typeof interactionClientId === "string" &&
          typeof requestedClientId === "string" &&
          interactionClientId !== requestedClientId)
      ) {
        await this.denyInteraction(req, res);
        return;
      }
      await this.finishConsent(req, res, details, userId);
      return;
    }
    if (hasPrompt(details.params, "none")) {
      await this.denyInteraction(req, res, "login_required");
      return;
    }
    if (typeof userId !== "string" || userId.length === 0 || hasPrompt(details.params, "login") || details.params.max_age !== undefined) {
      await this.redirectToLogin(req, res, originalUrl, hasPrompt(details.params, "login") || details.params.max_age !== undefined);
      return;
    }
    if (details.prompt.name !== "login") {
      await this.denyInteraction(req, res);
      return;
    }
    const interactionAccountId = details.session?.accountId;
    const interactionClientId = details.session?.clientId;
    const requestedClientId = details.params.client_id;
    if (
      (typeof interactionAccountId === "string" && interactionAccountId !== userId) ||
      (typeof interactionClientId === "string" &&
        typeof requestedClientId === "string" &&
        interactionClientId !== requestedClientId)
    ) {
      await this.denyInteraction(req, res);
      return;
    }
    await this.runtime.provider.interactionFinished(req as any, res, {
      login: {
        accountId: userId,
        remember: true,
      },
    });
  }

  private async denyInteraction(req: OidcAdapterRequest, res: any, error = "access_denied"): Promise<void> {
    await this.runtime.provider.interactionFinished(
      req as any,
      res,
      { error },
      { mergeWithLastSubmission: false },
    );
  }

  private async finishConsent(
    req: OidcAdapterRequest,
    res: any,
    details: {
      uid?: string;
      grantId?: string;
      params: Record<string, unknown>;
      prompt: {
        name: string;
        reasons?: string[];
        details?: Record<string, unknown>;
      };
      session?: {
        accountId?: string;
        clientId?: string;
      };
    },
    userId: string,
  ): Promise<void> {
    if (hasPrompt(details.params, "none")) {
      await this.denyInteraction(req, res, "consent_required");
      return;
    }
    const mode = consentResolverMode(this.runtime);
    const paramsClientId = readStringProperty(details.params, "client_id");
    const sessionAccountId = readStringProperty(details.session, "accountId");
    const sessionClientId = readStringProperty(details.session, "clientId");
    const client = await findOidcClient(this.runtime, sessionClientId ?? paramsClientId ?? "");
    const metadata = readOidcClientMetadata(client);
    const verifiedClientId = readVerifiedOidcClientId(client) ?? (
      mode === "legacy" ? sessionClientId ?? paramsClientId : undefined
    );
    if (verifiedClientId === undefined) {
      await this.denyInteraction(req, res);
      return;
    }
    if (
      mode === "v2" &&
      (sessionAccountId !== userId ||
        (sessionClientId !== undefined && sessionClientId !== verifiedClientId) ||
        paramsClientId !== verifiedClientId)
    ) {
      await this.denyInteraction(req, res);
      return;
    }
    const clientId = verifiedClientId;
    const promptDetails = isRecord(details.prompt.details) ? details.prompt.details : {};
    const missingScopes = readMissingConsentValues(promptDetails, "missingOIDCScope", isValidOidcScope);
    const missingClaims = readMissingConsentValues(promptDetails, "missingOIDCClaims", isValidOidcClaimName);
    if (missingScopes === undefined || missingClaims === undefined) {
      await this.denyInteraction(req, res);
      return;
    }
    const requestedScopes = [...new Set([
      ...readOidcConsentScopes(details.params),
      ...missingScopes,
    ])];
    const requestedClaims = [...new Set([
      ...readOidcConsentClaims(details.params),
      ...missingClaims,
    ])];
    const requestedScopeSet = new Set(requestedScopes);
    const requestedClaimSet = new Set(requestedClaims);
    if (!requestedScopes.includes("openid")) {
      await this.denyInteraction(req, res);
      return;
    }
    const policy = this.runtime.consentPolicy ?? normalizeOidcConsentPolicy();
    let nativeInteraction = details.prompt.reasons?.includes("native_client_prompt") === true ||
      details.prompt.reasons?.includes("webview_client_prompt") === true;
    if (!nativeInteraction) {
      nativeInteraction = metadata.application_type === "native" ||
        metadata.applicationType === "native" ||
        metadata["getbrick:client_kind"] === "webview";
    }
    const requiresConsent = details.prompt.name === "consent" ||
      requiresExplicitOidcConsent(requestedScopes, policy, nativeInteraction) ||
      missingScopes.length > 0 ||
      missingClaims.length > 0;
    let grant: any = mode === "v2"
      ? typeof details.grantId === "string"
        ? await this.runtime.provider.Grant.find(details.grantId)
        : new this.runtime.provider.Grant({ accountId: userId, clientId })
      : undefined;
    let verifiedGrantId: string | undefined;
    let grantPersisted = false;
    if (mode === "v2") {
      if (!grant) {
        await this.denyInteraction(req, res);
        return;
      }
      const grantAccountId = readStringProperty(grant, "accountId");
      const grantClientId = readStringProperty(grant, "clientId");
      if (grantAccountId !== userId || grantClientId !== clientId) {
        await this.denyInteraction(req, res);
        return;
      }
      verifiedGrantId = readStringProperty(grant, "jti") ?? readStringProperty(grant, "id") ?? details.grantId;
      if (verifiedGrantId === undefined) {
        const savedGrantId = await grant.save();
        if (typeof savedGrantId !== "string" || savedGrantId.length === 0) {
          await this.denyInteraction(req, res);
          return;
        }
        verifiedGrantId = savedGrantId;
        grantPersisted = true;
      }
    }
    const denyV2Consent = async (error = "access_denied"): Promise<void> => {
      if (grantPersisted && typeof grant?.destroy === "function") {
        try {
          await grant.destroy();
        } catch {
          await this.denyInteraction(req, res, error);
          return;
        }
      }
      await this.denyInteraction(req, res, error);
    };
    let approvedScopes: string[] = [];
    let approvedClaims: string[] = [];
    if (requiresConsent) {
      if (mode === "v2") {
        const tenantId = this.runtime.consentTenantId;
        const applicationId = this.runtime.consentApplicationId;
        const policyVersion = this.runtime.claimPolicy?.policyVersion ?? this.runtime.consentPolicy?.policyVersion;
        if (
          typeof details.uid !== "string" ||
          verifiedGrantId === undefined ||
          tenantId === undefined ||
          applicationId === undefined ||
          policyVersion === undefined ||
          !requestedScopes.includes("openid")
        ) {
          await denyV2Consent();
          return;
        }
        const context: OidcConsentContext = createOidcConsentContext({
          consentId: details.uid,
          tenantId,
          applicationId,
          clientId,
          userId,
          grantId: verifiedGrantId,
          interactionId: details.uid,
          requestedScopes,
          requestedClaims,
          policyVersion,
          origin: this.runtime.issuer,
        });
        let decision: OidcConsentDecision;
        try {
          if (typeof this.runtime.resolveConsentV2 === "function") {
            decision = await this.runtime.resolveConsentV2(context);
          } else if (typeof this.runtime.consentResolverV2 === "function") {
            decision = validateOidcConsentDecision(
              context,
              await this.runtime.consentResolverV2(context),
              this.runtime.claimPolicy,
            );
          } else {
            decision = { decision: "denied", reason: "policy_denied" };
          }
        } catch {
          decision = { decision: "denied", reason: "policy_denied" };
        }
        try {
          decision = validateOidcConsentDecision(context, decision, this.runtime.claimPolicy);
        } catch {
          decision = { decision: "denied", reason: "policy_denied" };
        }
        if (
          decision.decision !== "approved" ||
          decision.approvedScopes.some((scope) => !requestedScopeSet.has(scope)) ||
          decision.approvedClaims.some((claim) => !requestedClaimSet.has(claim))
        ) {
          await denyV2Consent();
          return;
        }
        const missingScopeSet = new Set(missingScopes);
        const missingClaimSet = new Set(missingClaims);
        approvedScopes = decision.approvedScopes.filter((scope) => missingScopeSet.has(scope));
        approvedClaims = decision.approvedClaims.filter((claim) => missingClaimSet.has(claim));
        if (OIDC_REQUIRED_CONSENT_SCOPES.some((scope) => missingScopeSet.has(scope) && !approvedScopes.includes(scope))) {
          await denyV2Consent();
          return;
        }
      } else if (typeof this.runtime.consentResolver === "function") {
        let approved = false;
        try {
          approved = resolveOidcConsentDecision(await this.runtime.consentResolver({
            clientId,
            userId,
            scopes: requestedScopes,
            requestedScopes,
            missingScopes,
            requestedClaims,
            nativeInteraction,
            consentId: details.uid,
            policyVersion: this.runtime.consentPolicy?.policyVersion,
          }));
        } catch {
          approved = false;
        }
        if (!approved) {
          await this.denyInteraction(req, res, "access_denied");
          return;
        }
        approvedScopes = missingScopes.filter((scope) => !isOidcProtocolReservedClaim(scope));
        approvedClaims = missingClaims.filter((claim) => !isOidcProtocolReservedClaim(claim));
      } else {
        await this.denyInteraction(req, res, "consent_required");
        return;
      }
    }
    if (grant === undefined) {
      grant = details.grantId
        ? await this.runtime.provider.Grant.find(details.grantId)
        : new this.runtime.provider.Grant({ accountId: userId, clientId });
    }
    if (!grant) {
      await this.denyInteraction(req, res);
      return;
    }
    if (readStringProperty(grant, "accountId") !== userId || readStringProperty(grant, "clientId") !== clientId) {
      await this.denyInteraction(req, res);
      return;
    }
    applyApprovedConsentToGrant(
      grant,
      requestedScopes,
      requestedClaims,
      missingScopes,
      missingClaims,
      approvedScopes,
      approvedClaims,
      mode === "v2",
    );
    const grantId = await grant.save();
    await this.runtime.provider.interactionFinished(
      req as any,
      res,
      { consent: { grantId } },
      { mergeWithLastSubmission: true },
    );
  }

  private async redirectToLogin(
    req: OidcAdapterRequest,
    res: any,
    originalUrl: string,
    reauthenticate = false,
  ): Promise<void> {
    if (!isSafeReturnPath(originalUrl)) {
      writeJsonError(res, 400, "invalid_request");
      return;
    }
    if (this.platformLoginHandler !== undefined) {
      const result = await this.platformLoginHandler({
        returnTo: originalUrl,
        ...(reauthenticate ? { reauthenticate: true } : {}),
        request: req,
        response: res,
      });
      if (!isSafePlatformLoginRedirect(result.redirectUrl)) {
        throw new Error("[getbrick-idaas] OIDC platform login redirect is invalid");
      }
      setNoStore(res);
      res.setHeader?.("Referrer-Policy", "no-referrer");
      res.statusCode = 303;
      res.setHeader?.("Location", result.redirectUrl);
      res.end?.();
      return;
    }
    if (!this.loginURL || !isSafeLoginURL(this.loginURL)) {
      writeJsonError(res, 401, "login_required");
      return;
    }
    const target = new URL(this.loginURL);
    target.searchParams.set("returnTo", originalUrl);
    if (reauthenticate) target.searchParams.set("reauthenticate", "1");
    setNoStore(res);
    res.setHeader?.("Referrer-Policy", "no-referrer");
    res.statusCode = 303;
    res.setHeader?.("Location", target.toString());
    res.end?.();
  }

  private prunePendingLogoutRequests(): void {
    const now = Date.now();
    for (const [key, expiresAt] of this.pendingLogoutExpiresAt) {
      if (expiresAt > now) continue;
      this.pendingLogoutExpiresAt.delete(key);
      this.pendingLogoutRequests.delete(key);
    }
  }

  private setPendingLogoutRequest(req: OidcAdapterRequest, pending: PendingLogoutRequest): void {
    this.prunePendingLogoutRequests();
    const key = logoutRequestKey(req);
    this.pendingLogoutRequests.delete(key);
    while (this.pendingLogoutRequests.size >= this.maxPendingLogoutRequests) {
      const oldest = this.pendingLogoutRequests.keys().next().value as string | undefined;
      if (oldest === undefined) break;
      this.pendingLogoutRequests.delete(oldest);
      this.pendingLogoutExpiresAt.delete(oldest);
    }
    this.pendingLogoutRequests.set(key, pending);
    this.pendingLogoutExpiresAt.set(key, Date.now() + this.pendingLogoutTtlMs);
  }

  private deletePendingLogoutRequest(req: OidcAdapterRequest): void {
    const key = logoutRequestKey(req);
    this.pendingLogoutRequests.delete(key);
    this.pendingLogoutExpiresAt.delete(key);
  }
}

function consentResolverMode(runtime: OidcProviderRuntime): "v2" | "legacy" {
  if (runtime.consentResolverMode === "v2" || runtime.consentResolverMode === "legacy") {
    return runtime.consentResolverMode;
  }
  if (
    runtime.consentResolverV2 !== undefined ||
    runtime.hostGrantPort !== undefined ||
    runtime.consentGrantPort !== undefined ||
    runtime.consentGrantStore !== undefined
  ) {
    return "v2";
  }
  return "legacy";
}

function readVerifiedOidcClientId(client: unknown): string | undefined {
  const metadata = readOidcClientMetadata(client);
  return readStringProperty(metadata, "client_id")
    ?? readStringProperty(metadata, "clientId")
    ?? readStringProperty(client, "client_id")
    ?? readStringProperty(client, "clientId");
}

function readMissingConsentValues(
  details: Record<string, unknown>,
  key: string,
  validator: (value: unknown) => value is string,
): string[] | undefined {
  const raw = details[key];
  if (raw === undefined) return [];
  if (!Array.isArray(raw) || raw.some((value) => !validator(value))) return undefined;
  return [...new Set(raw as string[])];
}

function applyApprovedConsentToGrant(
  grant: unknown,
  requestedScopes: readonly string[],
  requestedClaims: readonly string[],
  missingScopes: readonly string[],
  missingClaims: readonly string[],
  approvedScopes: readonly string[],
  approvedClaims: readonly string[],
  exact: boolean,
): void {
  const target = isRecord(grant) ? grant : {};
  const currentScopes = readGrantScopes(target);
  const currentClaims = readGrantClaims(target);
  const missingScopeSet = new Set(missingScopes);
  const missingClaimSet = new Set(missingClaims);
  const approvedScopeSet = new Set(approvedScopes);
  const approvedClaimSet = new Set(approvedClaims);
  const scopesToAdd = approvedScopes.filter((scope) => missingScopeSet.has(scope));
  if (scopesToAdd.length > 0 && typeof target.addOIDCScope === "function") {
    target.addOIDCScope(scopesToAdd.join(" "));
  }
  if (exact && typeof target.rejectOIDCScope === "function") {
    for (const scope of requestedScopes) {
      if (!approvedScopeSet.has(scope) && (missingScopeSet.has(scope) || currentScopes.has(scope))) {
        target.rejectOIDCScope(scope);
      }
    }
  }
  const claimsToAdd = approvedClaims.filter((claim) => missingClaimSet.has(claim) && !isOidcProtocolReservedClaim(claim));
  if (claimsToAdd.length > 0 && typeof target.addOIDCClaims === "function") {
    target.addOIDCClaims(claimsToAdd);
  }
  if (exact && typeof target.rejectOIDCClaims === "function") {
    for (const claim of requestedClaims) {
      if (
        !isOidcProtocolReservedClaim(claim) &&
        !approvedClaimSet.has(claim) &&
        (missingClaimSet.has(claim) || currentClaims.has(claim))
      ) {
        target.rejectOIDCClaims([claim]);
      }
    }
  }
}

function readGrantScopes(grant: Record<string, unknown>): Set<string> {
  if (typeof grant.getOIDCScope === "function") {
    try {
      const value = grant.getOIDCScope();
      if (typeof value === "string") return new Set(value.split(/\s+/u).filter((scope) => scope.length > 0));
    } catch {
      return new Set();
    }
  }
  const openid = isRecord(grant.openid) ? grant.openid : undefined;
  return new Set(typeof openid?.scope === "string" ? openid.scope.split(/\s+/u).filter((scope) => scope.length > 0) : []);
}

function readGrantClaims(grant: Record<string, unknown>): Set<string> {
  if (typeof grant.getOIDCClaims === "function") {
    try {
      const value = grant.getOIDCClaims();
      if (Array.isArray(value)) return new Set(value.filter((claim): claim is string => typeof claim === "string"));
    } catch {
      return new Set();
    }
  }
  const openid = isRecord(grant.openid) ? grant.openid : undefined;
  return new Set(Array.isArray(openid?.claims) ? openid.claims.filter((claim): claim is string => typeof claim === "string") : []);
}

export function isOidcRequestPath(pathname: string, runtime: Pick<OidcProviderRuntime, "basePath">): boolean {
  const path = normalizePath(pathname);
  const mountPath = normalizePath(runtime.basePath);
  const wellKnownPaths = [
    "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server",
  ];
  if (wellKnownPaths.includes(path)) return true;
  if (mountPath === "/") {
    const rootPaths = new Set([
      "/auth",
      "/token",
      "/token/introspection",
      "/token/revocation",
      "/userinfo",
      "/me",
      "/jwks",
      "/session/end",
    ]);
    return rootPaths.has(path) || path === "/session/end/confirm" || path.startsWith("/interaction/");
  }
  return path === mountPath || path.startsWith(`${mountPath}/`);
}

async function assertExactProviderRedirect(
  req: OidcAdapterRequest,
  runtime: OidcProviderRuntime,
): Promise<void> {
  const originalUrl = new URL(req.originalUrl ?? req.url ?? "/", runtime.issuer);
  const requestedValues = originalUrl.searchParams.getAll("redirect_uri");
  if (requestedValues.length > 1) throw new Error("OIDC redirect URI is invalid");
  const requested = requestedValues[0];
  if (requested === undefined) return;
  if (!isExactOidcRedirectUri(requested, requested)) throw new Error("OIDC redirect URI is invalid");
  const clientId = readSingleQueryValue(originalUrl, "client_id");
  if (clientId === undefined) throw new Error("OIDC client identifier is required");
  const provider = runtime.provider as unknown as {
    Client?: { find?: (id: string) => Promise<unknown> };
  };
  if (typeof provider.Client?.find !== "function") throw new Error("OIDC client lookup is unavailable");
  const client = await provider.Client.find(clientId);
  if (client === undefined || client === null) throw new Error("OIDC client is unavailable");
  const metadata = readOidcClientMetadata(client);
  const registered = readRegisteredRedirectUris(metadata, false);
  if (registered.length === 0 || !registered.some((value) => isExactOidcRedirectUri(value, requested))) {
    throw new Error("OIDC redirect URI is not registered");
  }
}

function readRegisteredRedirectUris(metadata: unknown, logout: boolean): string[] {
  if (!isRecord(metadata)) return [];
  const values = logout
    ? metadata.post_logout_redirect_uris ?? metadata.postLogoutRedirectUris
    : metadata.redirect_uris ?? metadata.redirectUris;
  return Array.isArray(values) ? values.filter((value): value is string => typeof value === "string") : [];
}

function isAuthorizationPath(pathname: string, runtime: OidcProviderRuntime): boolean {
  const path = normalizePath(pathname);
  const basePath = normalizePath(runtime.basePath);
  const authorizationPath = basePath === "/" ? "/auth" : `${basePath}/auth`;
  return path === authorizationPath;
}

function isInteractionPath(pathname: string, runtime: OidcProviderRuntime): boolean {
  const path = normalizePath(pathname);
  const interactionPath = normalizePath(runtime.interactionPath);
  return path === interactionPath || path.startsWith(`${interactionPath}/`);
}

function isEndSessionPath(pathname: string, runtime: OidcProviderRuntime): boolean {
  const path = normalizePath(pathname);
  const endSessionPath = endSessionRoot(pathname, runtime);
  return path === endSessionPath || path.startsWith(`${endSessionPath}/confirm`);
}

function isEndSessionStartPath(pathname: string, runtime: OidcProviderRuntime): boolean {
  return normalizePath(pathname) === endSessionRoot(pathname, runtime);
}

function endSessionRoot(_pathname: string, runtime: OidcProviderRuntime): string {
  const basePath = normalizePath(runtime.basePath);
  return basePath === "/" ? "/session/end" : `${basePath}/session/end`;
}

function canonicalizeProviderRequest(req: OidcAdapterRequest, issuer: string): void {
  const canonical = new URL(issuer);
  req.headers.host = canonical.host;
  req.headers["x-forwarded-host"] = canonical.host;
  req.headers["x-forwarded-proto"] = canonical.protocol.slice(0, -1);
}

function rewriteProviderRequest(
  req: OidcAdapterRequest,
  originalUrl: string,
  mountPath: string,
): { url: string; originalUrl: string } {
  const parsed = new URL(originalUrl, "http://localhost");
  const path = normalizePath(parsed.pathname);
  const normalizedMountPath = normalizePath(mountPath);
  const relativePath = normalizedMountPath === "/"
    ? path
    : path === normalizedMountPath
      ? "/"
      : path.startsWith(`${normalizedMountPath}/`)
        ? path.slice(normalizedMountPath.length) || "/"
        : path;
  const providerPath = relativePath === "/.well-known/oauth-authorization-server"
    ? "/.well-known/openid-configuration"
    : relativePath;
  const relativeUrl = `${providerPath}${parsed.search}`;
  const rewrittenOriginalUrl = `${normalizedMountPath === "/" ? "" : normalizedMountPath}${relativeUrl}`;
  req.url = relativeUrl;
  req.originalUrl = rewrittenOriginalUrl;
  return { url: relativeUrl, originalUrl: rewrittenOriginalUrl };
}

function getPathname(value: string): string {
  try {
    return new URL(value, "http://localhost").pathname;
  } catch {
    return value.split(/[?#]/u)[0] ?? "/";
  }
}

function normalizePath(value: string): string {
  const path = value.trim().replace(/\/+$/u, "");
  return path || "/";
}

interface ProviderLogoutDetails {
  clientId?: string;
  userId?: string;
  providerSessionId?: string;
  postLogoutRedirectUri?: string;
  grantIds: string[];
}

function readProviderLogoutContext(context: unknown): ProviderLogoutDetails {
  const root = isRecord(context) ? context : {};
  const oidc = isRecord(root.oidc) ? root.oidc : {};
  const client = isRecord(oidc.client) ? oidc.client : {};
  const session = isRecord(oidc.session) ? oidc.session : {};
  const state = isRecord(session.state) ? session.state : {};
  const params = isRecord(oidc.params) ? oidc.params : {};
  const authorizationClients = isRecord(session.authorizations)
    ? Object.keys(session.authorizations).filter((value) => value.length > 0)
    : [];
  const clientId = readString(client.clientId)
    ?? readString(client.client_id)
    ?? readString(state.clientId)
    ?? readString(session.clientId)
    ?? readString(params.client_id)
    ?? (authorizationClients.length === 1 ? authorizationClients[0] : undefined);
  if (clientId === undefined) return { grantIds: [] };
  const providerSessionId = readString(session.uid)
    ?? readString(session.jti)
    ?? readString(session.sessionUid)
    ?? readString(session.id)
    ?? readSessionSid(session, clientId);
  const postLogoutRedirectUri = readString(state.postLogoutRedirectUri)
    ?? readString(params.post_logout_redirect_uri);
  const userId = readString(session.accountId) ?? readString(session.userId);
  const grantIds = readGrantIds(session, clientId);
  return {
    clientId,
    ...(userId === undefined ? {} : { userId }),
    ...(providerSessionId === undefined ? {} : { providerSessionId }),
    ...(postLogoutRedirectUri === undefined ? {} : { postLogoutRedirectUri }),
    grantIds,
  };
}

function readSessionSid(session: Record<string, unknown>, clientId: string): string | undefined {
  const sidFor = session.sidFor;
  if (typeof sidFor !== "function") return undefined;
  try {
    return readString(sidFor.call(session, clientId));
  } catch {
    return undefined;
  }
}

function readGrantIds(session: Record<string, unknown>, clientId: string): string[] {
  const ids = new Set<string>();
  const authorizations = session.authorizations;
  if (isRecord(authorizations)) {
    for (const value of Object.values(authorizations)) {
      if (isRecord(value)) {
        const grantId = readString(value.grantId);
        if (grantId !== undefined) ids.add(grantId);
      }
    }
  }
  const grantIdFor = session.grantIdFor;
  if (typeof grantIdFor === "function") {
    try {
      const grantId = readString(grantIdFor.call(session, clientId));
      if (grantId !== undefined) ids.add(grantId);
    } catch {
      return [...ids];
    }
  }
  return [...ids];
}

function readSingleQueryValue(url: URL, name: string): string | undefined {
  const values = url.searchParams.getAll(name);
  if (values.length > 1) throw new Error(`OIDC ${name} is invalid`);
  return values[0];
}

function logoutRequestKey(req: OidcAdapterRequest): string {
  const cookie = req.headers.cookie;
  const source = typeof cookie === "string"
    ? cookie
    : Array.isArray(cookie)
      ? cookie.join(";")
      : JSON.stringify(req.headers);
  return createHash("sha256").update(source).digest("base64url");
}

function contextHeadersRecord(context: unknown, req: OidcAdapterRequest): Record<string, unknown> {
  const root = isRecord(context) ? context : {};
  const headers = isRecord(root.headers) ? root.headers : req.headers;
  return headers;
}

function contextResponse(context: unknown): unknown {
  const root = isRecord(context) ? context : {};
  if (root.res !== undefined) return root.res;
  if (isRecord(root.response) && root.response.res !== undefined) return root.response.res;
  return undefined;
}

function isInvalidOidcRequestError(error: unknown): boolean {
  if (!(error instanceof Error)) return false;
  return /^OIDC (?:redirect URI|client identifier|client_id|post_logout_redirect_uri|client is unavailable|client verification failed|redirect URI is not registered|logout client|logout redirect|id_token_hint|logout request|logout tenant|logout application|logout user|logout provider session|logout idempotency|logout request is invalid)/u.test(error.message);
}

function readCoordinatorText(coordinator: OidcLogoutCoordinatorLike, key: "tenantId" | "applicationId"): string | undefined {
  const value = (coordinator as unknown as Record<string, unknown>)[key];
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

interface DeferredResponse {
  release(): void;
  abort(): void;
}

function deferResponse(response: any): DeferredResponse {
  if (response === null || typeof response !== "object" || typeof response.end !== "function") {
    return { release: () => undefined, abort: () => undefined };
  }
  const originalEnd = response.end;
  const originalWrite = typeof response.write === "function" ? response.write : undefined;
  const originalWriteHead = typeof response.writeHead === "function" ? response.writeHead : undefined;
  const originalFlushHeaders = typeof response.flushHeaders === "function" ? response.flushHeaders : undefined;
  const queuedEnds: unknown[][] = [];
  const queuedWrites: unknown[][] = [];
  let queuedWriteHead: unknown[] | undefined;
  let flushHeaders = false;
  let finished = false;
  response.end = function deferredEnd(...args: unknown[]) {
    if (!finished) {
      queuedEnds.push(args);
      return response;
    }
    return originalEnd.apply(response, args);
  };
  if (originalWrite !== undefined) {
    response.write = function deferredWrite(...args: unknown[]) {
      if (!finished) {
        queuedWrites.push(args);
        return true;
      }
      return originalWrite.apply(response, args);
    };
  }
  if (originalWriteHead !== undefined) {
    response.writeHead = function deferredWriteHead(...args: unknown[]) {
      if (!finished) {
        queuedWriteHead = args;
        return response;
      }
      return originalWriteHead.apply(response, args);
    };
  }
  if (originalFlushHeaders !== undefined) {
    response.flushHeaders = function deferredFlushHeaders() {
      if (!finished) {
        flushHeaders = true;
        return response;
      }
      return originalFlushHeaders.call(response);
    };
  }
  const restore = (): void => {
    response.end = originalEnd;
    if (originalWrite !== undefined) response.write = originalWrite;
    if (originalWriteHead !== undefined) response.writeHead = originalWriteHead;
    if (originalFlushHeaders !== undefined) response.flushHeaders = originalFlushHeaders;
  };
  return {
    release: () => {
      if (finished) return;
      finished = true;
      restore();
      if (queuedWriteHead !== undefined && originalWriteHead !== undefined) originalWriteHead.apply(response, queuedWriteHead);
      if (originalWrite !== undefined) {
        for (const args of queuedWrites) originalWrite.apply(response, args);
      }
      if (flushHeaders && originalFlushHeaders !== undefined) originalFlushHeaders.call(response);
      const end = queuedEnds.pop();
      if (end !== undefined) originalEnd.apply(response, end);
      else originalEnd.call(response);
    },
    abort: () => {
      if (finished) return;
      finished = true;
      restore();
      response.statusCode = 500;
      response.removeHeader?.("Location");
      response.removeHeader?.("Content-Length");
    },
  };
}

function readString(value: unknown): string | undefined {
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

async function findOidcClient(runtime: OidcProviderRuntime, clientId: string): Promise<unknown> {
  const provider = runtime.provider as unknown as { Client?: { find?: (id: string) => Promise<unknown> } };
  if (typeof provider.Client?.find !== "function") return undefined;
  try {
    return await provider.Client.find(clientId);
  } catch {
    return undefined;
  }
}

function readOidcClientMetadata(value: unknown): Record<string, unknown> {
  if (!isRecord(value)) return {};
  const metadata = typeof value.metadata === "function" ? value.metadata() : value.metadata ?? value;
  return isRecord(metadata) ? metadata : {};
}

function readStringProperty(value: unknown, key: string): string | undefined {
  if (typeof value !== "object" || value === null) return undefined;
  const result = (value as Record<string, unknown>)[key];
  return typeof result === "string" && result.length > 0 ? result : undefined;
}

function setNoStore(response: any): void {
  response.setHeader?.("Cache-Control", "no-store");
  response.setHeader?.("Pragma", "no-cache");
}

function writeJsonError(response: any, status: number, error: string): void {
  if (typeof response.status === "function") response.status(status);
  else response.statusCode = status;
  if (typeof response.json === "function") {
    response.json({ error });
    return;
  }
  response.setHeader?.("Content-Type", "application/json");
  response.end?.(JSON.stringify({ error }));
}

function readInteractionUid(value: string, runtime: Pick<OidcProviderRuntime, "interactionPath">): string | undefined {
  const path = getPathname(value);
  const root = normalizePath(runtime.interactionPath);
  if (!path.startsWith(`${root}/`)) return undefined;
  const encoded = path.slice(root.length + 1);
  if (encoded.length === 0 || encoded.includes("/")) return undefined;
  let uid: string;
  try {
    uid = decodeURIComponent(encoded);
  } catch {
    return undefined;
  }
  return /^[A-Za-z0-9._~-]{8,512}$/u.test(uid) ? uid : undefined;
}

function hasPrompt(params: Record<string, unknown>, name: string): boolean {
  const value = params.prompt;
  return typeof value === "string" && value.split(/\s+/u).filter(Boolean).includes(name);
}

function isSafePlatformLoginRedirect(value: unknown): value is string {
  if (typeof value !== "string" || value.length === 0 || value.length > 4096 || /[\u0000-\u001f\u007f\s\\]/u.test(value)) return false;
  if (isSafeReturnPath(value)) return true;
  try {
    const parsed = new URL(value);
    if (parsed.protocol === "https:") {
      return parsed.username === "" && parsed.password === "" && parsed.hash === "" && parsed.origin !== "null";
    }
    return parsed.protocol === "http:" && isLoopbackHostname(parsed.hostname) && parsed.username === "" && parsed.password === "" && parsed.hash === "" && parsed.origin !== "null";
  } catch {
    return false;
  }
}

function isLoopbackHostname(hostname: string): boolean {
  return hostname === "localhost" || hostname === "127.0.0.1" || hostname === "[::1]";
}

function isSafeLoginURL(value: string): boolean {
  try {
    const parsed = new URL(value);
    return (
      (parsed.protocol === "http:" || parsed.protocol === "https:") &&
      parsed.username === "" &&
      parsed.password === "" &&
      parsed.origin !== "null" &&
      parsed.hash === "" &&
      !/[\x00-\x1f\x7f]/u.test(value) &&
      !value.includes("\\")
    );
  } catch {
    return false;
  }
}

function isSafeReturnPath(value: string): boolean {
  const queryIndex = value.indexOf("?");
  const path = queryIndex === -1 ? value : value.slice(0, queryIndex);
  if (!isValidPlatformLoginReturnTo(path)) return false;
  if (queryIndex === -1) return true;
  const query = value.slice(queryIndex + 1);
  if (/%(?![0-9a-f]{2})/iu.test(query)) return false;
  try {
    const decoded = decodeURIComponent(query);
    return !/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f\\]/u.test(decoded);
  } catch {
    return false;
  }
}
