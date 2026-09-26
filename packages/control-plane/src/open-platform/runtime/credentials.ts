import type {
  CredentialDto,
  OpenPlatformRuntimeMode,
} from "../types.js";
import {
  normalizeIdentifier,
  normalizeResourceId,
  normalizeScopes,
  normalizeTenantKey,
} from "../validation.js";
import {
  isOpenPlatformApiRequestContext,
  normalizeAudience,
  normalizeCredentialVersion,
  normalizeRuntimeInstant,
} from "./context.js";
import {
  OPEN_PLATFORM_RUNTIME_ERROR_CODES,
  isOpenPlatformRuntimeError,
  runtimeError,
  toOpenPlatformRuntimeContractError,
  type OpenPlatformRuntimeErrorCode,
} from "./errors.js";
import { normalizeOpenPlatformApiRoutePolicy } from "./policy.js";
import type {
  OpenPlatformAdapterCredentialIdentity,
  OpenPlatformApiAuthentication,
  OpenPlatformApiKeyAuthentication,
  OpenPlatformApiPrincipal,
  OpenPlatformApiRequestContext,
  OpenPlatformApiRoutePolicy,
  OpenPlatformCredentialDomain,
  OpenPlatformCredentialVerifier,
  OpenPlatformOidcBearerAuthentication,
  OpenPlatformOidcBearerVerifierPort,
  OpenPlatformServiceClientAuthentication,
  OpenPlatformServiceClientVerifierPort,
} from "./types.js";

interface ValidatedCredentialState {
  readonly credential: CredentialDto;
  readonly effectiveScopes: readonly string[];
}

export interface OpenPlatformCredentialVerificationServiceOptions {
  readonly domain: OpenPlatformCredentialDomain;
  readonly mode?: OpenPlatformRuntimeMode;
  readonly clock?: () => Date;
  readonly oidcBearerVerifier?: OpenPlatformOidcBearerVerifierPort;
  readonly serviceClientVerifier?: OpenPlatformServiceClientVerifierPort;
}

export class OpenPlatformCredentialVerificationService
implements OpenPlatformCredentialVerifier {
  private readonly domain: OpenPlatformCredentialDomain;
  private readonly mode: OpenPlatformRuntimeMode;
  private readonly clock: () => Date;
  private readonly oidcBearerVerifier:
    | OpenPlatformOidcBearerVerifierPort
    | undefined;
  private readonly serviceClientVerifier:
    | OpenPlatformServiceClientVerifierPort
    | undefined;

  constructor(options: OpenPlatformCredentialVerificationServiceOptions) {
    if (
      options === null ||
      typeof options !== "object" ||
      !isCredentialDomain(options.domain)
    ) {
      throw runtimeError(
        OPEN_PLATFORM_RUNTIME_ERROR_CODES.CONFIGURATION_ERROR,
      );
    }
    const mode = options.mode ?? "test";
    if (
      mode !== "development" &&
      mode !== "test" &&
      mode !== "production"
    ) {
      throw runtimeError(
        OPEN_PLATFORM_RUNTIME_ERROR_CODES.CONFIGURATION_ERROR,
      );
    }
    if (typeof options.clock !== "undefined" && typeof options.clock !== "function") {
      throw runtimeError(
        OPEN_PLATFORM_RUNTIME_ERROR_CODES.CONFIGURATION_ERROR,
      );
    }
    this.domain = options.domain;
    this.mode = mode;
    this.clock = options.clock ?? (() => new Date());
    this.oidcBearerVerifier = validateOptionalVerifier(
      options.oidcBearerVerifier,
      mode,
    );
    this.serviceClientVerifier = validateOptionalVerifier(
      options.serviceClientVerifier,
      mode,
    );
  }

  async verify(
    context: OpenPlatformApiRequestContext,
    route: OpenPlatformApiRoutePolicy,
    authentication: OpenPlatformApiAuthentication,
  ): Promise<OpenPlatformApiPrincipal> {
    return this.execute(context, async () => {
      if (authentication === null || typeof authentication !== "object") {
        throw runtimeError(OPEN_PLATFORM_RUNTIME_ERROR_CODES.INVALID_REQUEST);
      }
      switch (authentication.type) {
        case "apiKey":
          return this.verifyApiKeyInternal(context, route, authentication);
        case "oidcBearer":
          return this.verifyOidcBearerInternal(context, route, authentication);
        case "serviceClient":
          return this.verifyServiceClientInternal(
            context,
            route,
            authentication,
          );
        default:
          throw runtimeError(
            OPEN_PLATFORM_RUNTIME_ERROR_CODES.INVALID_REQUEST,
          );
      }
    });
  }

  async verifyApiKey(
    context: OpenPlatformApiRequestContext,
    route: OpenPlatformApiRoutePolicy,
    authentication: OpenPlatformApiKeyAuthentication,
  ): Promise<OpenPlatformApiPrincipal> {
    return this.execute(context, () =>
      this.verifyApiKeyInternal(context, route, authentication)
    );
  }

  async verifyOidcBearer(
    context: OpenPlatformApiRequestContext,
    route: OpenPlatformApiRoutePolicy,
    authentication: OpenPlatformOidcBearerAuthentication,
  ): Promise<OpenPlatformApiPrincipal> {
    return this.execute(context, () =>
      this.verifyOidcBearerInternal(context, route, authentication)
    );
  }

  async verifyServiceClient(
    context: OpenPlatformApiRequestContext,
    route: OpenPlatformApiRoutePolicy,
    authentication: OpenPlatformServiceClientAuthentication,
  ): Promise<OpenPlatformApiPrincipal> {
    return this.execute(context, () =>
      this.verifyServiceClientInternal(context, route, authentication)
    );
  }

  private async verifyApiKeyInternal(
    context: OpenPlatformApiRequestContext,
    routeValue: OpenPlatformApiRoutePolicy,
    authentication: OpenPlatformApiKeyAuthentication,
  ): Promise<OpenPlatformApiPrincipal> {
    const route = normalizeOpenPlatformApiRoutePolicy(routeValue);
    assertRouteMatchesContext(context, route);
    const credentialId = normalizeResourceId(
      authentication?.credentialId,
      "credential",
    );
    const credentialVersion = normalizeCredentialVersion(
      authentication?.credentialVersion,
    );
    const secret = normalizeSecretMaterial(authentication?.secret);
    const state = await this.validateCredentialState(
      context,
      route,
      credentialId,
      credentialVersion,
    );
    let verified = false;
    try {
      verified = await this.domain.verifyCredentialSecret(
        context.trustedContext,
        {
          tenantId: context.tenantId,
          credentialId,
          secret,
        },
      );
    } catch (error) {
      return this.throwNormalized(error, context.requestId);
    }
    if (verified !== true) {
      throw runtimeError(
        OPEN_PLATFORM_RUNTIME_ERROR_CODES.CREDENTIAL_INVALID,
        { requestId: context.requestId },
      );
    }
    return this.principal(
      context,
      "apiKey",
      state.credential,
      state.effectiveScopes,
      state.credential.createdAt,
    );
  }

  private async verifyOidcBearerInternal(
    context: OpenPlatformApiRequestContext,
    routeValue: OpenPlatformApiRoutePolicy,
    authentication: OpenPlatformOidcBearerAuthentication,
  ): Promise<OpenPlatformApiPrincipal> {
    const route = normalizeOpenPlatformApiRoutePolicy(routeValue);
    assertRouteMatchesContext(context, route);
    if (
      authentication?.type !== "oidcBearer" ||
      this.oidcBearerVerifier === undefined
    ) {
      throw runtimeError(
        OPEN_PLATFORM_RUNTIME_ERROR_CODES.CREDENTIAL_VERIFIER_UNAVAILABLE,
        { requestId: context.requestId },
      );
    }
    const token = normalizeSecretMaterial(authentication.token);
    let identity: OpenPlatformAdapterCredentialIdentity | undefined;
    try {
      identity = await this.oidcBearerVerifier.verify({
        token,
        audience: route.audience,
        requestId: context.requestId,
      });
    } catch {
      throw runtimeError(
        OPEN_PLATFORM_RUNTIME_ERROR_CODES.CREDENTIAL_VERIFIER_UNAVAILABLE,
        { requestId: context.requestId },
      );
    }
    return this.verifyAdapterIdentity(
      context,
      route,
      "oidcBearer",
      identity,
    );
  }

  private async verifyServiceClientInternal(
    context: OpenPlatformApiRequestContext,
    routeValue: OpenPlatformApiRoutePolicy,
    authentication: OpenPlatformServiceClientAuthentication,
  ): Promise<OpenPlatformApiPrincipal> {
    const route = normalizeOpenPlatformApiRoutePolicy(routeValue);
    assertRouteMatchesContext(context, route);
    if (
      authentication?.type !== "serviceClient" ||
      this.serviceClientVerifier === undefined
    ) {
      throw runtimeError(
        OPEN_PLATFORM_RUNTIME_ERROR_CODES.CREDENTIAL_VERIFIER_UNAVAILABLE,
        { requestId: context.requestId },
      );
    }
    const clientId = normalizeIdentifier(
      authentication.clientId,
      "clientId",
    );
    if (clientId !== context.clientId) {
      throw runtimeError(OPEN_PLATFORM_RUNTIME_ERROR_CODES.CLIENT_NOT_ALLOWED, {
        requestId: context.requestId,
      });
    }
    const assertion = normalizeSecretMaterial(authentication.assertion);
    let identity: OpenPlatformAdapterCredentialIdentity | undefined;
    try {
      identity = await this.serviceClientVerifier.verify({
        assertion,
        clientId,
        audience: route.audience,
        requestId: context.requestId,
      });
    } catch {
      throw runtimeError(
        OPEN_PLATFORM_RUNTIME_ERROR_CODES.CREDENTIAL_VERIFIER_UNAVAILABLE,
        { requestId: context.requestId },
      );
    }
    return this.verifyAdapterIdentity(
      context,
      route,
      "serviceClient",
      identity,
    );
  }

  private async verifyAdapterIdentity(
    context: OpenPlatformApiRequestContext,
    route: OpenPlatformApiRoutePolicy,
    authenticationType: "oidcBearer" | "serviceClient",
    value: OpenPlatformAdapterCredentialIdentity | undefined,
  ): Promise<OpenPlatformApiPrincipal> {
    if (value === undefined) {
      throw runtimeError(
        OPEN_PLATFORM_RUNTIME_ERROR_CODES.CREDENTIAL_INVALID,
        { requestId: context.requestId },
      );
    }
    const identity = normalizeAdapterIdentity(value);
    if (
      identity.tenantId !== context.tenantId ||
      identity.applicationId !== context.applicationId ||
      identity.clientId !== context.clientId
    ) {
      if (identity.tenantId !== context.tenantId) {
        throw runtimeError(OPEN_PLATFORM_RUNTIME_ERROR_CODES.TENANT_MISMATCH, {
          requestId: context.requestId,
        });
      }
      if (identity.applicationId !== context.applicationId) {
        throw runtimeError(
          OPEN_PLATFORM_RUNTIME_ERROR_CODES.APPLICATION_MISMATCH,
          { requestId: context.requestId },
        );
      }
      throw runtimeError(OPEN_PLATFORM_RUNTIME_ERROR_CODES.CLIENT_NOT_ALLOWED, {
        requestId: context.requestId,
      });
    }
    if (
      !identity.audiences.includes(context.audience) ||
      !identity.audiences.includes(route.audience)
    ) {
      throw runtimeError(OPEN_PLATFORM_RUNTIME_ERROR_CODES.INVALID_AUDIENCE, {
        requestId: context.requestId,
      });
    }
    if (
      route.requiredScopes.some(
        (scope) => !identity.scopes.includes(scope),
      )
    ) {
      throw runtimeError(OPEN_PLATFORM_RUNTIME_ERROR_CODES.INVALID_SCOPE, {
        requestId: context.requestId,
      });
    }
    const now = this.now();
    if (
      Date.parse(identity.issuedAt) > Date.parse(now) ||
      Date.parse(identity.expiresAt) <= Date.parse(now)
    ) {
      throw runtimeError(
        OPEN_PLATFORM_RUNTIME_ERROR_CODES.CREDENTIAL_EXPIRED,
        { requestId: context.requestId },
      );
    }
    const state = await this.validateCredentialState(
      context,
      route,
      identity.credentialId,
      identity.credentialVersion,
    );
    const scopes = state.effectiveScopes.filter((scope) =>
      identity.scopes.includes(scope)
    );
    return this.principal(
      context,
      authenticationType,
      state.credential,
      scopes,
      identity.issuedAt,
      identity.expiresAt,
    );
  }

  private async validateCredentialState(
    context: OpenPlatformApiRequestContext,
    route: OpenPlatformApiRoutePolicy,
    credentialId: string,
    expectedVersion: number,
  ): Promise<ValidatedCredentialState> {
    const credential = await this.domain.getCredential(
      context.trustedContext,
      {
        tenantId: context.tenantId,
        id: credentialId,
      },
    );
    if (credential.applicationId !== context.applicationId) {
      throw runtimeError(
        OPEN_PLATFORM_RUNTIME_ERROR_CODES.APPLICATION_MISMATCH,
        { requestId: context.requestId },
      );
    }
    if (credential.status === "revoked") {
      throw runtimeError(OPEN_PLATFORM_RUNTIME_ERROR_CODES.CREDENTIAL_REVOKED, {
        requestId: context.requestId,
      });
    }
    if (credential.status !== "active") {
      throw runtimeError(OPEN_PLATFORM_RUNTIME_ERROR_CODES.CREDENTIAL_INACTIVE, {
        requestId: context.requestId,
      });
    }
    if (credential.version !== expectedVersion) {
      throw runtimeError(
        OPEN_PLATFORM_RUNTIME_ERROR_CODES.CREDENTIAL_VERSION_MISMATCH,
        {
          requestId: context.requestId,
          details: {
            expectedVersion,
            actualVersion: credential.version,
          },
        },
      );
    }
    const now = this.now();
    if (credential.expiresAt !== undefined) {
      const expiresAt = Date.parse(credential.expiresAt);
      if (!Number.isFinite(expiresAt)) {
        throw runtimeError(
          OPEN_PLATFORM_RUNTIME_ERROR_CODES.CREDENTIAL_INVALID,
          { requestId: context.requestId },
        );
      }
      if (expiresAt <= Date.parse(now)) {
        throw runtimeError(
          OPEN_PLATFORM_RUNTIME_ERROR_CODES.CREDENTIAL_EXPIRED,
          { requestId: context.requestId },
        );
      }
    }
    const tenant = await this.domain.getTenant(context.trustedContext, {
      tenantId: context.tenantId,
    });
    if (tenant.status !== "published") {
      throw parentDisabled(context, "tenant");
    }
    const application = await this.domain.getApplication(
      context.trustedContext,
      {
        tenantId: context.tenantId,
        id: credential.applicationId,
      },
    );
    if (application.status !== "published") {
      throw parentDisabled(context, "application");
    }
    if (credential.environmentId !== undefined) {
      const environment = await this.domain.getApplicationEnvironment(
        context.trustedContext,
        {
          tenantId: context.tenantId,
          applicationId: application.id,
          id: credential.environmentId,
        },
      );
      if (environment.status !== "published") {
        throw parentDisabled(context, "applicationEnvironment");
      }
    }
    const product = await this.domain.getApiProduct(
      context.trustedContext,
      {
        tenantId: context.tenantId,
        id: route.productId,
      },
    );
    if (product.status !== "published") {
      throw parentDisabled(context, "apiProduct");
    }
    let catalogScopes = [...product.scopes];
    if (route.apiVersionId !== undefined) {
      const version = await this.domain.getApiVersion(
        context.trustedContext,
        {
          tenantId: context.tenantId,
          productId: product.id,
          id: route.apiVersionId,
        },
      );
      if (
        version.status !== "published" ||
        version.productId !== product.id
      ) {
        throw parentDisabled(context, "apiVersion");
      }
      catalogScopes = catalogScopes.filter((scope) =>
        version.scopes.includes(scope)
      );
    }
    await this.domain.authorizeScopes(context.trustedContext, {
      tenantId: context.tenantId,
      credentialId,
      productId: route.productId,
      ...(route.apiVersionId === undefined
        ? {}
        : { apiVersionId: route.apiVersionId }),
      scopes: [...route.requiredScopes],
    });
    const grants = await this.domain.listScopeGrants(
      context.trustedContext,
      {
        tenantId: context.tenantId,
        credentialId,
        productId: route.productId,
        ...(route.apiVersionId === undefined
          ? {}
          : { apiVersionId: route.apiVersionId }),
      },
    );
    const effectiveScopes = [...new Set(grants
      .filter((grant) =>
        grant.status === "active" &&
        grant.revokedAt === undefined &&
        grant.applicationId === credential.applicationId &&
        grant.apiVersionId === route.apiVersionId
      )
      .flatMap((grant) => grant.scopes)
      .filter((scope) =>
        credential.scopes.includes(scope) &&
        catalogScopes.includes(scope)
      )
      .sort((left, right) => left.localeCompare(right)))];
    if (
      route.requiredScopes.some(
        (scope) => !effectiveScopes.includes(scope),
      )
    ) {
      throw runtimeError(
        OPEN_PLATFORM_RUNTIME_ERROR_CODES.SCOPE_GRANT_INVALID,
        { requestId: context.requestId },
      );
    }
    return Object.freeze({
      credential,
      effectiveScopes: Object.freeze(effectiveScopes),
    });
  }

  private principal(
    context: OpenPlatformApiRequestContext,
    authenticationType: OpenPlatformApiAuthentication["type"],
    credential: CredentialDto,
    scopes: readonly string[],
    issuedAt: string,
    expiresAt?: string,
  ): OpenPlatformApiPrincipal {
    return Object.freeze({
      authenticationType,
      tenantId: context.tenantId,
      applicationId: context.applicationId,
      clientId: context.clientId,
      credentialId: credential.id,
      credentialVersion: credential.version,
      scopes: Object.freeze([...scopes]),
      audience: context.audience,
      issuedAt,
      ...(expiresAt === undefined ? {} : { expiresAt }),
    });
  }

  private now(): string {
    const value = this.clock();
    if (!(value instanceof Date) || !Number.isFinite(value.getTime())) {
      throw runtimeError(
        OPEN_PLATFORM_RUNTIME_ERROR_CODES.CONFIGURATION_ERROR,
      );
    }
    return value.toISOString();
  }

  private async execute<T>(
    context: OpenPlatformApiRequestContext,
    operation: () => Promise<T>,
  ): Promise<T> {
    if (!isOpenPlatformApiRequestContext(context)) {
      throw runtimeError(
        OPEN_PLATFORM_RUNTIME_ERROR_CODES.AUTHENTICATION_REQUIRED,
      );
    }
    if (
      this.mode === "production" &&
      context.trustedContext.assurance !== "authenticated"
    ) {
      throw runtimeError(
        OPEN_PLATFORM_RUNTIME_ERROR_CODES.AUTHENTICATION_REQUIRED,
        { requestId: context.requestId },
      );
    }
    try {
      return await operation();
    } catch (error) {
      if (isOpenPlatformRuntimeError(error)) {
        if (error.requestId === undefined) {
          throw runtimeError(error.code, {
            requestId: context.requestId,
            ...(error.retryAfterSeconds === undefined
              ? {}
              : { retryAfterSeconds: error.retryAfterSeconds }),
            ...(error.details === undefined ? {} : { details: error.details }),
          });
        }
        throw error;
      }
      return this.throwNormalized(error, context.requestId);
    }
  }

  private throwNormalized(error: unknown, requestId: string): never {
    const contract = toOpenPlatformRuntimeContractError(error, requestId);
    throw runtimeError(contract.body.error.code as OpenPlatformRuntimeErrorCode, {
      requestId,
    });
  }
}

export function createOpenPlatformCredentialVerificationService(
  options: OpenPlatformCredentialVerificationServiceOptions,
): OpenPlatformCredentialVerificationService {
  return new OpenPlatformCredentialVerificationService(options);
}

function isCredentialDomain(value: unknown): value is OpenPlatformCredentialDomain {
  if (value === null || typeof value !== "object") return false;
  const domain = value as OpenPlatformCredentialDomain;
  return typeof domain.authorizeScopes === "function" &&
    typeof domain.getApiProduct === "function" &&
    typeof domain.getApiVersion === "function" &&
    typeof domain.getApplication === "function" &&
    typeof domain.getApplicationEnvironment === "function" &&
    typeof domain.getCredential === "function" &&
    typeof domain.getTenant === "function" &&
    typeof domain.listScopeGrants === "function" &&
    typeof domain.verifyCredentialSecret === "function";
}

function validateOptionalVerifier<T extends { productionReady: boolean }>(
  value: T | undefined,
  mode: OpenPlatformRuntimeMode,
): T | undefined {
  if (value === undefined) return undefined;
  const candidate = value as T & { readonly verify?: unknown };
  if (
    candidate === null ||
    typeof candidate !== "object" ||
    typeof candidate.verify !== "function" ||
    typeof candidate.productionReady !== "boolean" ||
    (mode === "production" && candidate.productionReady !== true)
  ) {
    throw runtimeError(
      OPEN_PLATFORM_RUNTIME_ERROR_CODES.CONFIGURATION_ERROR,
    );
  }
  return value;
}

function normalizeAdapterIdentity(
  value: unknown,
): OpenPlatformAdapterCredentialIdentity {
  try {
    if (value === null || typeof value !== "object") {
      throw new Error("invalid adapter identity");
    }
    const identity = value as OpenPlatformAdapterCredentialIdentity;
    if (identity.active !== true) {
      throw new Error("inactive adapter identity");
    }
    const issuedAt = normalizeRuntimeInstant(
      identity.issuedAt,
      OPEN_PLATFORM_RUNTIME_ERROR_CODES.CREDENTIAL_VERIFIER_UNAVAILABLE,
    );
    const expiresAt = normalizeRuntimeInstant(
      identity.expiresAt,
      OPEN_PLATFORM_RUNTIME_ERROR_CODES.CREDENTIAL_VERIFIER_UNAVAILABLE,
    );
    if (Date.parse(expiresAt) <= Date.parse(issuedAt)) {
      throw new Error("invalid adapter lifetime");
    }
    const audiences = [...new Set(
      (normalizeStringArray(identity.audiences) as string[]).map(
        (audience) => normalizeAudience(audience),
      ),
    )].sort((left, right) => left.localeCompare(right));
    const scopes = normalizeScopes(identity.scopes, "scopes", true);
    if (audiences.length === 0) throw new Error("adapter audience missing");
    return Object.freeze({
      active: true,
      tenantId: normalizeTenantKey(identity.tenantId),
      applicationId: normalizeResourceId(
        identity.applicationId,
        "application",
      ),
      clientId: normalizeIdentifier(identity.clientId, "clientId"),
      credentialId: normalizeResourceId(identity.credentialId, "credential"),
      credentialVersion: normalizeCredentialVersion(
        identity.credentialVersion,
      ),
      scopes: Object.freeze(scopes),
      audiences: Object.freeze(audiences),
      issuedAt,
      expiresAt,
    });
  } catch {
    throw runtimeError(
      OPEN_PLATFORM_RUNTIME_ERROR_CODES.CREDENTIAL_VERIFIER_UNAVAILABLE,
    );
  }
}

function normalizeStringArray(value: unknown): string[] {
  if (!Array.isArray(value) || value.length > 128) throw new Error("invalid");
  return value.map((item) => {
    if (typeof item !== "string") throw new Error("invalid");
    return item;
  });
}

function normalizeSecretMaterial(value: unknown): string {
  if (
    typeof value !== "string" ||
    value.length < 1 ||
    value.length > 4096 ||
    /[\u0000-\u001f\u007f]/u.test(value)
  ) {
    throw runtimeError(
      OPEN_PLATFORM_RUNTIME_ERROR_CODES.CREDENTIAL_INVALID,
    );
  }
  return value;
}

function assertRouteMatchesContext(
  context: OpenPlatformApiRequestContext,
  route: OpenPlatformApiRoutePolicy,
): void {
  if (
    !route.enabled ||
    route.method !== context.method ||
    route.path !== context.path
  ) {
    throw runtimeError(OPEN_PLATFORM_RUNTIME_ERROR_CODES.ROUTE_NOT_ALLOWED, {
      requestId: context.requestId,
    });
  }
  if (route.audience !== context.audience) {
    throw runtimeError(OPEN_PLATFORM_RUNTIME_ERROR_CODES.INVALID_AUDIENCE, {
      requestId: context.requestId,
    });
  }
  if (!route.clientIds.includes(context.clientId)) {
    throw runtimeError(OPEN_PLATFORM_RUNTIME_ERROR_CODES.CLIENT_NOT_ALLOWED, {
      requestId: context.requestId,
    });
  }
}

function parentDisabled(
  context: OpenPlatformApiRequestContext,
  resource: string,
) {
  return runtimeError(
    OPEN_PLATFORM_RUNTIME_ERROR_CODES.PARENT_RESOURCE_DISABLED,
    {
      requestId: context.requestId,
      details: { resource },
    },
  );
}
