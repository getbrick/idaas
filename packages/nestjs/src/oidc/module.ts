import {
  Inject,
  Module,
  Optional,
  RequestMethod,
  type DynamicModule,
  type MiddlewareConsumer,
  type OnModuleInit,
} from "@nestjs/common";
import {
  assertOidcRemoteJwksPolicy,
  createDynamicOidcClientAdapter,
  createOidcProvider,
  defineIdaasConfig,
  normalizeOidcJwksUri,
  validateIdaasConfig,
  type AdapterFactory,
  type IdaasConfigInput,
  type IdaasProfile,
  type JWKS,
  type OidcClientJwksInput,
   type OidcClientJwksResolver,
   type OidcClaimPolicyInput,
   type OidcConsentGrantStore,
   type OidcConsentPolicy,
   type OidcConsentResolver,
   type OidcConsentResolverV2,
   type OidcHostGrantBoundary,
   type OidcOpClient,
   type OidcDynamicClient,
   type OidcDynamicClientAdapterFactory,
   type OidcDynamicClientStore,
   type OidcRemoteJwksPolicy,
  type OidcProviderRuntime,
  type OidcUserResolver,
  validateOidcCookieKeys,
} from "@getbrick/idaas-core";
import { GetbrickOidcMiddleware, type OidcPlatformLoginHandler } from "./middleware.js";
import {
  GETBRICK_OIDC_AUTH,
  GETBRICK_OIDC_LOGIN_URL,
  GETBRICK_OIDC_PLATFORM_LOGIN_HANDLER,
  GETBRICK_OIDC_READINESS,
  GETBRICK_OIDC_RUNTIME,
  type GetbrickAuthLike,
} from "../tokens.js";
import {
  createBetterAuthOidcSessionRevocationPort,
  createOidcLogoutCoordinator,
  createProviderOidcGrantRevocationPort,
  GETBRICK_OIDC_LOGOUT_COORDINATOR,
  type OidcLogoutCoordinatorLike,
  type OidcLogoutCoordinatorOptions,
  type OidcLogoutPersistenceLike,
  type OidcLogoutStateOptions,
  type OidcGrantRevocationPortLike,
  type OidcSessionRevocationPortLike,
} from "./logout-coordinator.js";

export {
  createBetterAuthOidcSessionRevocationPort,
  createOidcLogoutCoordinator,
  createProviderOidcGrantRevocationPort,
  createOidcLogoutIdempotencyKey,
  DEFAULT_OIDC_LOGOUT_MAX_IN_FLIGHT,
  DEFAULT_OIDC_LOGOUT_MAX_OPERATIONS,
  DEFAULT_OIDC_LOGOUT_STATE_TTL_MS,
  GETBRICK_OIDC_LOGOUT_COORDINATOR,
  OidcLogoutCoordinator,
} from "./logout-coordinator.js";
export type {
  OidcGrantRevocationPortLike,
  OidcLogoutClientResolver,
  OidcLogoutCoordinatorLike,
  OidcLogoutCoordinatorOptions,
  OidcLogoutPersistenceLike,
  OidcLogoutPersistencePort,
  OidcLogoutStateOptions,
  OidcLogoutGrantPort,
  OidcLogoutGrantRevocationPort,
  OidcLogoutRequestContext,
  OidcLogoutRevocationPort,
  OidcLogoutSessionPort,
  OidcLogoutSessionRevocationPort,
  OidcSessionRevocationInput,
  OidcSessionRevocationPort,
  OidcSessionRevocationPortLike,
} from "./logout-coordinator.js";

type OidcRevocationReadiness = {
  ready?: () => boolean | Promise<boolean>;
};

type OidcSessionRevocationPortOption = OidcSessionRevocationPortLike & OidcRevocationReadiness;
type OidcGrantRevocationPortOption = OidcGrantRevocationPortLike & OidcRevocationReadiness;

export interface GetbrickOidcLogoutModuleOptions {
  coordinator?: OidcLogoutCoordinatorLike;
  sessionRevocationPort?: OidcSessionRevocationPortOption;
  grantRevocationPort?: OidcGrantRevocationPortOption;
  sessionRevocation?: OidcSessionRevocationPortOption;
  grantRevocation?: OidcGrantRevocationPortOption;
  logoutSessionPort?: OidcSessionRevocationPortOption;
  logoutGrantPort?: OidcGrantRevocationPortOption;
  sessionPort?: OidcSessionRevocationPortOption;
  grantPort?: OidcGrantRevocationPortOption;
  tenantId?: string;
  applicationId?: string;
  namespace?: string;
  persistence?: OidcLogoutPersistenceLike;
  operationStore?: OidcLogoutPersistenceLike;
  state?: OidcLogoutStateOptions;
}


export interface GetbrickOidcModuleOptions {
  auth: GetbrickAuthLike;
  config: IdaasConfigInput;
  findUser: OidcUserResolver;
  clientSecrets?: Record<string, string>;
  clientJwks?: Record<string, JWKS>;
  resolveClientJwks?: OidcClientJwksResolver;
  allowRemoteJwksUri?: boolean;
  trustedJwksOrigins?: readonly string[];
  trustedJwksHosts?: readonly string[];
  adapter?: AdapterFactory;
  clientStore?: OidcDynamicClientStore;
  jwks?: JWKS;
  cookieKeys?: string[];
  trustProxy?: boolean;
  readiness?: () => boolean | Promise<boolean>;
  profile?: IdaasProfile;
   consentPolicy?: Partial<OidcConsentPolicy>;
   consentResolver?: OidcConsentResolver;
   consentResolverV2?: OidcConsentResolverV2;
   hostConsentGrantStore?: OidcConsentGrantStore;
   consentGrantStore?: OidcConsentGrantStore;
   hostConsentGrantPort?: OidcHostGrantBoundary;
   consentGrantPort?: OidcHostGrantBoundary;
   claimPolicy?: OidcClaimPolicyInput;
   consentTenantId?: string;
   consentApplicationId?: string;
   tenantId?: string;
   applicationId?: string;
   platformLoginHandler?: OidcPlatformLoginHandler;
  logoutCoordinator?: OidcLogoutCoordinatorLike;
  logoutSessionRevocationPort?: OidcSessionRevocationPortLike;
  logoutGrantRevocationPort?: OidcGrantRevocationPortLike;
  sessionRevocationPort?: OidcSessionRevocationPortOption;
  grantRevocationPort?: OidcGrantRevocationPortOption;
  sessionRevocation?: OidcSessionRevocationPortOption;
  grantRevocation?: OidcGrantRevocationPortOption;
  logoutSessionPort?: OidcSessionRevocationPortOption;
  logoutGrantPort?: OidcGrantRevocationPortOption;
  sessionPort?: OidcSessionRevocationPortOption;
  grantPort?: OidcGrantRevocationPortOption;
  logout?: GetbrickOidcLogoutModuleOptions;
  logoutTenantId?: string;
  logoutApplicationId?: string;
  logoutNamespace?: string;
  logoutPersistence?: OidcLogoutPersistenceLike;
  logoutOperationStore?: OidcLogoutPersistenceLike;
  logoutState?: OidcLogoutStateOptions;
}

@Module({})
export class GetbrickOidcModule implements OnModuleInit {
  constructor(
    @Optional()
    @Inject(GETBRICK_OIDC_RUNTIME)
    private readonly runtime?: OidcProviderRuntime,
    @Optional()
    @Inject(GETBRICK_OIDC_AUTH)
    private readonly auth?: GetbrickAuthLike,
    @Optional()
    @Inject(GETBRICK_OIDC_LOGIN_URL)
    private readonly loginURL?: string,
    @Optional()
    @Inject(GETBRICK_OIDC_READINESS)
    private readonly readiness?: () => Promise<boolean>,
  ) {}

  async onModuleInit(): Promise<void> {
    if (typeof this.readiness !== "function") return;
    if ((await this.readiness()) !== true) {
      throw new Error("[getbrick-idaas] OIDC provider storage is not ready");
    }
  }

  static forRoot(options: GetbrickOidcModuleOptions): DynamicModule {
    const config = defineIdaasConfig(options.config);
    if (options.profile !== undefined) config.profile = options.profile;
    if (options.clientStore) config.oidc.op.dynamicClients = true;
    const configuredClientJwks = {
      ...(config.oidc.op.clientJwks ?? {}),
      ...(options.clientJwks ?? {}),
    } as unknown as Record<string, OidcClientJwksInput>;
    if (options.clientJwks) {
      config.oidc.op.clientJwks = configuredClientJwks as unknown as Record<string, Record<string, unknown>>;
    }
    if (config.oidc.op.enabled && config.oidc.op.dynamicClients && !options.clientStore) {
      throw new Error("[getbrick-idaas] dynamic OIDC clients require a clientStore");
    }
    validateIdaasConfig(config);
    if (!config.oidc.op.enabled) {
      return {
        module: GetbrickOidcModule,
        exports: [],
      };
    }
    const remoteJwksPolicy: OidcRemoteJwksPolicy = {
      profile: config.profile,
      allowRemoteJwksUri: options.allowRemoteJwksUri,
      trustedJwksOrigins: options.trustedJwksOrigins,
      trustedJwksHosts: options.trustedJwksHosts,
    };
    assertOidcRemoteJwksPolicy(remoteJwksPolicy);
    const strictRemoteJwks = config.profile === "production" || options.allowRemoteJwksUri === true;
    const remoteStaticClients: OidcDynamicClient[] = [];
    for (const client of config.oidc.op.clients) {
      if (!strictRemoteJwks || client.jwksUri === undefined) continue;
      if (client.jwks !== undefined || client.clientJwks !== undefined || Object.prototype.hasOwnProperty.call(configuredClientJwks, client.clientId)) {
        throw new Error(`[getbrick-idaas] OIDC OP client ${client.clientId} cannot configure both JWKS and jwks_uri`);
      }
      if (client.tokenEndpointAuthMethod !== "private_key_jwt") {
        throw new Error(`[getbrick-idaas] OIDC OP client ${client.clientId} asymmetric fields require private_key_jwt`);
      }
      const jwksUri = normalizeOidcJwksUri(client.jwksUri, false, remoteJwksPolicy);
      remoteStaticClients.push(toRemoteRegistryClient(
        client,
        options.clientSecrets?.[client.clientId] ?? client.clientSecret,
        jwksUri,
      ));
    }
    const remoteStaticClientIds = new Set(remoteStaticClients.map((client) => client.client_id));
    const providerConfig = remoteStaticClientIds.size === 0
      ? config.oidc.op
      : {
          ...config.oidc.op,
          clients: config.oidc.op.clients.filter((client) => !remoteStaticClientIds.has(client.clientId)),
          dynamicClients: true,
          scopes: uniqueStrings([
            ...config.oidc.op.scopes,
            ...config.oidc.op.clients.flatMap((client) => client.scopes),
          ]),
        };
    const authSecret = options.auth.options?.secret;
    const cookieKeys = options.cookieKeys ??
      (typeof authSecret === "string" && authSecret.length >= 32 ? [authSecret] : undefined);
    if (typeof options.findUser !== "function") {
      throw new Error("[getbrick-idaas] OIDC provider requires a findUser resolver");
    }
    if (options.clientStore && !options.adapter) {
      throw new Error("[getbrick-idaas] dynamic OIDC clients require a base adapter");
    }
    if (config.profile === "production") {
      if (!config.session.storeInDatabase) {
        throw new Error("[getbrick-idaas] production OIDC provider requires database-backed sessions");
      }
      if (!options.adapter) {
        throw new Error("[getbrick-idaas] production OIDC provider requires a persistent adapter");
      }
      if (!options.jwks && !config.oidc.op.jwks) {
        throw new Error("[getbrick-idaas] production OIDC provider requires a configured JWKS");
      }
      if (!cookieKeys?.length) {
        throw new Error("[getbrick-idaas] production OIDC provider requires cookieKeys or an auth secret");
      }
      validateOidcCookieKeys(cookieKeys, 32);
      if (!readinessCheck(options)) {
        throw new Error("[getbrick-idaas] production OIDC provider requires a storage readiness check");
      }
      const logout = readLogoutModuleOptions(options);
      if (!hasProductionLogoutCapabilities(logout)) {
        throw new Error("[getbrick-idaas] production OIDC provider requires a ready persistent logout coordinator, ready revocation and persistence readiness for logout session and grant revocation ports");
      }
    }
    const logout = readLogoutModuleOptions(options);
    if (
      logout.coordinator === undefined &&
      config.profile !== "development" &&
      config.profile !== "test" &&
      (!hasSessionRevocationPort(logout.sessionRevocationPort) || !hasGrantRevocationPort(logout.grantRevocationPort))
    ) {
      throw new Error("[getbrick-idaas] OIDC logout requires session and grant revocation ports");
    }
     const clientJwks = configuredClientJwks;
     const consentGrantStore = options.hostConsentGrantStore ?? options.consentGrantStore;
     const consentGrantPort = options.hostConsentGrantPort ?? options.consentGrantPort;
     const consentTenantId = options.consentTenantId ?? options.tenantId ?? options.logoutTenantId;
     const consentApplicationId = options.consentApplicationId ?? options.applicationId ?? options.logoutApplicationId;
     if (
       (options.consentResolverV2 !== undefined || consentGrantStore !== undefined || consentGrantPort !== undefined) &&
       (consentTenantId === undefined || consentApplicationId === undefined)
     ) {
       throw new Error("[getbrick-idaas] V2 OIDC consent requires trusted tenant and application identifiers");
     }
     const baseAdapter = options.adapter ?? (remoteStaticClients.length > 0 ? createEmptyOidcAdapter() : undefined);
     const registryAdapter = baseAdapter !== undefined && (options.clientStore !== undefined || remoteStaticClients.length > 0)
       ? createDynamicOidcClientAdapter(
           baseAdapter,
           options.clientStore ?? { find: async () => undefined },
           {
             clientJwks,
             resolveClientJwks: options.resolveClientJwks,
             allowInsecureHttp: strictRemoteJwks ? false : config.profile !== "production",
             idTokenSignedResponseAlg: config.oidc.op.signingAlgorithm,
             requireApplicationType: true,
             staticClients: remoteStaticClients,
             ...remoteJwksPolicy,
           },
         )
       : undefined;
     const adapter = registryAdapter ?? baseAdapter;
     const readiness = readinessCheck(options, remoteStaticClientIds, registryAdapter);
     const runtime = createOidcProvider({
      config: providerConfig,
      profile: config.profile,
      dynamicClients: providerConfig.dynamicClients,
      findUser: options.findUser,
      clientSecrets: options.clientSecrets,
      clientJwks,
      adapter,
      jwks: options.jwks,
      cookieKeys,
      proxy: options.trustProxy,
       consentPolicy: options.consentPolicy,
       consentResolver: options.consentResolver,
       consentResolverV2: options.consentResolverV2,
       consentGrantStore,
       hostGrantPort: consentGrantPort,
       claimPolicy: options.claimPolicy,
       consentTenantId,
       consentApplicationId,
       allowInsecureHttp: config.profile !== "production",
    });
    const coordinator = logout.coordinator ?? createLogoutCoordinator(runtime, options, logout, config.profile);
    return {
      module: GetbrickOidcModule,
      providers: [
        { provide: GETBRICK_OIDC_RUNTIME, useValue: runtime },
        { provide: GETBRICK_OIDC_AUTH, useValue: options.auth },
        { provide: GETBRICK_OIDC_LOGIN_URL, useValue: config.oidc.op.loginURL },
        { provide: GETBRICK_OIDC_LOGOUT_COORDINATOR, useValue: coordinator },
        ...(options.platformLoginHandler === undefined ? [] : [{ provide: GETBRICK_OIDC_PLATFORM_LOGIN_HANDLER, useValue: options.platformLoginHandler }]),
        { provide: GETBRICK_OIDC_READINESS, useValue: readiness },
      ],
      exports: [
        GETBRICK_OIDC_RUNTIME,
        GETBRICK_OIDC_AUTH,
        GETBRICK_OIDC_LOGIN_URL,
        GETBRICK_OIDC_LOGOUT_COORDINATOR,
        ...(options.platformLoginHandler === undefined ? [] : [GETBRICK_OIDC_PLATFORM_LOGIN_HANDLER]),
      ],
    };
  }

  configure(consumer: MiddlewareConsumer): void {
    if (!this.runtime) return;
    consumer
      .apply(GetbrickOidcMiddleware)
      .forRoutes({ path: "*", method: RequestMethod.ALL });
  }
}

function toRemoteRegistryClient(
  client: OidcOpClient,
  clientSecret: string | undefined,
  jwksUri: string,
): OidcDynamicClient {
  return {
    client_id: client.clientId,
    ...(clientSecret === undefined ? {} : { client_secret: clientSecret }),
    ...(client.clientName === undefined ? {} : { client_name: client.clientName }),
    application_type: client.applicationType,
    redirect_uris: [...client.redirectUris],
    post_logout_redirect_uris: [...client.postLogoutRedirectUris],
    jwks_uri: jwksUri,
    grant_types: [...client.grantTypes],
    response_types: [...client.responseTypes],
    scope: client.scopes.join(" "),
    token_endpoint_auth_method: client.tokenEndpointAuthMethod,
    token_endpoint_auth_signing_alg: client.tokenEndpointAuthSigningAlg,
    require_pkce: true,
    status: "active",
  };
}

function createEmptyOidcAdapter(): AdapterFactory {
  return (() => ({
    find: async () => undefined,
    upsert: async () => undefined,
    destroy: async () => undefined,
  })) as unknown as AdapterFactory;
}

function uniqueStrings(values: readonly string[]): string[] {
  return [...new Set(values)];
}

function readinessCheck(
  options: GetbrickOidcModuleOptions,
  remoteStaticClientIds: ReadonlySet<string> = new Set(),
  registryAdapter?: OidcDynamicClientAdapterFactory,
): (() => Promise<boolean>) | undefined {
  const checks: Array<() => unknown | Promise<unknown>> = [];
  if (options.readiness) checks.push(options.readiness);
  const adapterReadiness = (options.adapter as { ready?: () => unknown | Promise<unknown> } | undefined)?.ready;
  if (typeof adapterReadiness === "function") checks.push(() => adapterReadiness.call(options.adapter));
  const storeReadiness = (options.clientStore as { isReady?: () => unknown | Promise<unknown> } | undefined)?.isReady;
  if (typeof storeReadiness === "function") checks.push(() => storeReadiness.call(options.clientStore));
  const storeValidation = (options.clientStore as { validate?: () => unknown | Promise<unknown> } | undefined)?.validate;
  if (typeof storeValidation === "function") {
    checks.push(async () => {
      const result = await storeValidation.call(options.clientStore);
      return result === undefined || result === true;
    });
  }
  const logout = readLogoutModuleOptions(options);
  const coordinatorReadiness = (logout.coordinator as { ready?: () => unknown | Promise<unknown> } | undefined)?.ready;
  if (typeof coordinatorReadiness === "function") checks.push(() => coordinatorReadiness.call(logout.coordinator));
  const coordinatorPersistence = (logout.coordinator as {
    persistence?: { ready?: () => unknown | Promise<unknown> };
    operationStore?: { ready?: () => unknown | Promise<unknown> };
  } | undefined);
  const coordinatorPersistenceValue = coordinatorPersistence?.persistence
    ?? coordinatorPersistence?.operationStore
    ?? coordinatorPersistence as { ready?: () => unknown | Promise<unknown> } | undefined;
  const coordinatorPersistenceReadiness = coordinatorPersistenceValue?.ready;
  if (typeof coordinatorPersistenceReadiness === "function") checks.push(() => coordinatorPersistenceReadiness.call(coordinatorPersistenceValue));
  const sessionReadiness = (logout.sessionRevocationPort as { ready?: () => unknown | Promise<unknown> } | undefined)?.ready;
  if (typeof sessionReadiness === "function") checks.push(() => sessionReadiness.call(logout.sessionRevocationPort));
  const grantReadiness = (logout.grantRevocationPort as { ready?: () => unknown | Promise<unknown> } | undefined)?.ready;
  if (typeof grantReadiness === "function") checks.push(() => grantReadiness.call(logout.grantRevocationPort));
  const persistenceReadiness = (logout.persistence as { ready?: () => unknown | Promise<unknown> } | undefined)?.ready;
  if (typeof persistenceReadiness === "function") checks.push(() => persistenceReadiness.call(logout.persistence));
  if (typeof registryAdapter?.resolveRemoteJwks === "function") {
    for (const clientId of remoteStaticClientIds) {
      checks.push(async () => {
        try {
          await registryAdapter.resolveRemoteJwks?.(clientId);
          return true;
        } catch {
          return false;
        }
      });
    }
  }
  if (checks.length === 0) return undefined;
  return async () => {
    for (const check of checks) {
      try {
        if ((await check()) !== true) return false;
      } catch {
        return false;
      }
    }
    return true;
  };
}

function createLogoutCoordinator(
  runtime: OidcProviderRuntime,
  options: GetbrickOidcModuleOptions,
  logout: GetbrickOidcLogoutModuleOptions,
  profile: IdaasProfile,
): OidcLogoutCoordinatorLike {
  const sessionPort = logout.sessionRevocationPort ?? (
    profile === "development" || profile === "test"
      ? createBetterAuthOidcSessionRevocationPort(
          options.auth,
          runtime.issuer,
        )
      : undefined
  );
  const grantPort = logout.grantRevocationPort ?? (
    profile === "development" || profile === "test"
      ? createProviderOidcGrantRevocationPort(runtime.provider, options.adapter)
      : undefined
  );
  if (sessionPort === undefined || grantPort === undefined) {
    throw new Error("[getbrick-idaas] OIDC logout requires session and grant revocation ports");
  }
  const provider = runtime.provider as unknown as {
    Client?: { find?: (clientId: string) => Promise<unknown> };
  };
  const findClient = provider.Client?.find;
  if (typeof findClient !== "function") {
    throw new Error("[getbrick-idaas] OIDC logout requires a client lookup port");
  }
  const coordinatorOptions: OidcLogoutCoordinatorOptions = {
    resolveClient: (clientId) => findClient.call(provider.Client, clientId),
    sessionRevocation: sessionPort,
    grantRevocation: grantPort,
    tenantId: logout.tenantId ?? options.logoutTenantId,
    applicationId: logout.applicationId ?? options.logoutApplicationId,
    namespace: logout.namespace ?? options.logoutNamespace,
    ...(logout.state ?? {}),
    persistence: logout.persistence,
    profile,
  };
  return createOidcLogoutCoordinator(coordinatorOptions);
}

function hasProductionLogoutCapabilities(logout: GetbrickOidcLogoutModuleOptions): boolean {
  if (logout.coordinator === undefined) {
    return hasSessionRevocationPort(logout.sessionRevocationPort)
      && hasRevocationReadiness(logout.sessionRevocationPort)
      && hasGrantRevocationPort(logout.grantRevocationPort)
      && hasRevocationReadiness(logout.grantRevocationPort)
      && hasPersistenceCapability(logout.persistence);
  }
  const coordinator = logout.coordinator as unknown as Record<string, unknown>;
  if (typeof coordinator.ready !== "function") return false;
  const persistence = coordinator.persistence ?? coordinator.operationStore ?? coordinator;
  return hasPersistenceCapability(persistence);
}

function hasPersistenceCapability(value: unknown): boolean {
  if (value === undefined || value === null || (typeof value !== "object" && typeof value !== "function")) return false;
  const record = value as Record<string, unknown>;
  const ready = typeof record.ready === "function";
  const load = typeof record.load === "function" || typeof record.get === "function";
  const save = typeof record.save === "function" || typeof record.set === "function";
  const remove = typeof record.delete === "function" || typeof record.remove === "function";
  return ready && load && save && remove;
}

function hasRevocationReadiness(value: unknown): boolean {
  if (value === undefined || value === null) return false;
  if (typeof value !== "object" && typeof value !== "function") return false;
  return typeof (value as { ready?: unknown }).ready === "function";
}

function hasSessionRevocationPort(value: unknown): boolean {
  if (value === undefined || value === null) return false;
  if (typeof value === "function") return true;
  if (typeof value !== "object") return false;
  const record = value as Record<string, unknown>;
  return ["revoke", "revokeSession", "revokeBySessionId", "revokeByAccountId"]
    .some((key) => typeof record[key] === "function");
}

function hasGrantRevocationPort(value: unknown): boolean {
  if (value === undefined || value === null) return false;
  if (typeof value === "function") return true;
  if (typeof value !== "object") return false;
  const record = value as Record<string, unknown>;
  return ["revoke", "revokeByGrantId", "revokeByAccountId"]
    .some((key) => typeof record[key] === "function");
}

function readLogoutModuleOptions(options: GetbrickOidcModuleOptions): GetbrickOidcLogoutModuleOptions {
  const nested = options.logout ?? {};
  return {
    coordinator: options.logoutCoordinator ?? nested.coordinator,
    sessionRevocationPort: options.logoutSessionRevocationPort
      ?? options.sessionRevocationPort
      ?? options.sessionRevocation
      ?? options.logoutSessionPort
      ?? options.sessionPort
      ?? nested.sessionRevocationPort
      ?? nested.sessionRevocation
      ?? nested.logoutSessionPort
      ?? nested.sessionPort,
    grantRevocationPort: options.logoutGrantRevocationPort
      ?? options.grantRevocationPort
      ?? options.grantRevocation
      ?? options.logoutGrantPort
      ?? options.grantPort
      ?? nested.grantRevocationPort
      ?? nested.grantRevocation
      ?? nested.logoutGrantPort
      ?? nested.grantPort,
    tenantId: nested.tenantId ?? options.logoutTenantId,
    applicationId: nested.applicationId ?? options.logoutApplicationId,
    namespace: nested.namespace ?? options.logoutNamespace,
    persistence: options.logoutPersistence
      ?? options.logoutOperationStore
      ?? nested.persistence
      ?? nested.operationStore,
    state: nested.state ?? options.logoutState,
  };
}

