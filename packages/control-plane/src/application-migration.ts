export * from "./tenant.js";
export * from "./identity.js";
export * from "./secret-binding.js";
export * from "./migration-coordinator.js";

import {
  createApplicationExternalIdentityTableMigrationSql,
  createIdentityTableMigrationSql,
  type ApplicationIdentitySqlColumns,
  type IdentitySqlColumns,
} from "./identity.js";
import {
  createSecretBindingTableMigrationSql,
  type SecretBindingSqlColumns,
} from "./secret-binding.js";
import {
  createTenantTableMigrationSql,
  createTenantSqlObjectName,
  normalizeTenantConfig,
  qualifyTenantTable,
  type TenantConfig,
  type TenantConfigInput,
  type TenantSqlColumns,
} from "./tenant.js";
import {
  MigrationCoordinator,
  createMigrationDefinition,
  createMigrationMetadataSql,
  migrationChecksum,
  type MigrationDefinition,
  type MigrationDryRunResult,
  type MigrationSqlExecutor,
  type MigrationRunResult,
} from "./migration-coordinator.js";
import {
  APPLICATION_MANAGEMENT_SQL_COLUMNS,
  APPLICATION_MANAGEMENT_SQL_TABLES,
  quoteApplicationSqlIdentifier,
  validateApplicationSqlIdentifier,
  type ApplicationSqlColumns,
  type ApplicationSqlTableNames,
} from "./application-sql-repository.js";

export const APPLICATION_MANAGEMENT_MIGRATION_VERSION = 2;
export const APPLICATION_MANAGEMENT_MIGRATION_NAME = "application-management-foundation";
export const APPLICATION_MANAGEMENT_LEGACY_MIGRATION_VERSION = APPLICATION_MANAGEMENT_MIGRATION_VERSION;
export const APPLICATION_MANAGEMENT_LEGACY_MIGRATION_NAME = APPLICATION_MANAGEMENT_MIGRATION_NAME;
export const APPLICATION_MANAGEMENT_ADDITIVE_MIGRATION_VERSION = 3;
export const APPLICATION_MANAGEMENT_ADDITIVE_MIGRATION_NAME = "application-management-client-platform-foundation";
export const APPLICATION_MANAGEMENT_CLIENT_PLATFORM_MIGRATION_VERSION = APPLICATION_MANAGEMENT_ADDITIVE_MIGRATION_VERSION;
export const APPLICATION_MANAGEMENT_CLIENT_PLATFORM_MIGRATION_NAME = APPLICATION_MANAGEMENT_ADDITIVE_MIGRATION_NAME;
export const APPLICATION_MANAGEMENT_PLATFORM_LOGIN_RETURN_TO_MIGRATION_VERSION = 4;
export const APPLICATION_MANAGEMENT_PLATFORM_LOGIN_RETURN_TO_MIGRATION_NAME = "application-management-platform-login-return-to";
export const APPLICATION_MANAGEMENT_RETURN_TO_MIGRATION_VERSION = APPLICATION_MANAGEMENT_PLATFORM_LOGIN_RETURN_TO_MIGRATION_VERSION;
export const APPLICATION_MANAGEMENT_RETURN_TO_MIGRATION_NAME = APPLICATION_MANAGEMENT_PLATFORM_LOGIN_RETURN_TO_MIGRATION_NAME;
export const APPLICATION_MANAGEMENT_V4_MIGRATION_VERSION = APPLICATION_MANAGEMENT_PLATFORM_LOGIN_RETURN_TO_MIGRATION_VERSION;
export const APPLICATION_MANAGEMENT_V4_MIGRATION_NAME = APPLICATION_MANAGEMENT_PLATFORM_LOGIN_RETURN_TO_MIGRATION_NAME;
export const APPLICATION_MANAGEMENT_CLIENT_AUTH_BFF_MIGRATION_VERSION = 5;
export const APPLICATION_MANAGEMENT_CLIENT_AUTH_BFF_MIGRATION_NAME = "application-management-client-auth-bff-state";
export const APPLICATION_MANAGEMENT_CLIENT_AUTH_BFF_STATE_MIGRATION_VERSION = APPLICATION_MANAGEMENT_CLIENT_AUTH_BFF_MIGRATION_VERSION;
export const APPLICATION_MANAGEMENT_CLIENT_AUTH_BFF_STATE_MIGRATION_NAME = APPLICATION_MANAGEMENT_CLIENT_AUTH_BFF_MIGRATION_NAME;
export const APPLICATION_MANAGEMENT_BFF_MIGRATION_VERSION = APPLICATION_MANAGEMENT_CLIENT_AUTH_BFF_MIGRATION_VERSION;
export const APPLICATION_MANAGEMENT_BFF_MIGRATION_NAME = APPLICATION_MANAGEMENT_CLIENT_AUTH_BFF_MIGRATION_NAME;
export const APPLICATION_MANAGEMENT_BFF_STATE_MIGRATION_VERSION = APPLICATION_MANAGEMENT_CLIENT_AUTH_BFF_MIGRATION_VERSION;
export const APPLICATION_MANAGEMENT_BFF_STATE_MIGRATION_NAME = APPLICATION_MANAGEMENT_CLIENT_AUTH_BFF_MIGRATION_NAME;
export const APPLICATION_MANAGEMENT_V5_MIGRATION_VERSION = APPLICATION_MANAGEMENT_CLIENT_AUTH_BFF_MIGRATION_VERSION;
export const APPLICATION_MANAGEMENT_V5_MIGRATION_NAME = APPLICATION_MANAGEMENT_CLIENT_AUTH_BFF_MIGRATION_NAME;
export const DEFAULT_APPLICATION_MANAGEMENT_CLIENT_AUTH_BFF_STATE_TABLE = "gb_idaas_client_auth_bff_state";
export const DEFAULT_APPLICATION_MANAGEMENT_BFF_STATE_TABLE = DEFAULT_APPLICATION_MANAGEMENT_CLIENT_AUTH_BFF_STATE_TABLE;
export const DEFAULT_CLIENT_AUTH_BFF_MIGRATION_TABLE = DEFAULT_APPLICATION_MANAGEMENT_CLIENT_AUTH_BFF_STATE_TABLE;
export const DEFAULT_BFF_STATE_MIGRATION_TABLE = DEFAULT_APPLICATION_MANAGEMENT_CLIENT_AUTH_BFF_STATE_TABLE;
export const DEFAULT_APPLICATION_MIGRATION_TABLE = "gb_idaas_schema_migration";
export const DEFAULT_APPLICATION_MIGRATION_LOCK_TABLE = "gb_idaas_schema_migration_lock";
export const DEFAULT_PLATFORM_LOGIN_STATE_TABLE = "gb_idaas_platform_login_state";
export const DEFAULT_CLIENT_SESSION_TABLE = "gb_idaas_client_session";
export const DEFAULT_OPAQUE_CLIENT_SESSION_TABLE = DEFAULT_CLIENT_SESSION_TABLE;
export const DEFAULT_WEBVIEW_TICKET_TABLE = "gb_idaas_webview_ticket";

export interface ApplicationManagementMigrationOptions {
  tables?: Partial<ApplicationSqlTableNames> & {
    clientSession?: string;
    clientSessions?: string;
    opaqueClientSession?: string;
    opaqueClientSessions?: string;
    webviewTicket?: string;
    webviewTickets?: string;
    clientTicket?: string;
    clientTickets?: string;
    clientAuthBffState?: string;
    clientAuthBffStates?: string;
    clientAuthState?: string;
    clientAuthStates?: string;
    bffState?: string;
    bffStates?: string;
    clientAuthBffStateTable?: string;
    clientAuthBffStatesTable?: string;
    clientAuthStateTable?: string;
    clientAuthStatesTable?: string;
    bffStateTable?: string;
    bffStatesTable?: string;
  };
  tableNames?: Partial<ApplicationSqlTableNames> & {
    clientSession?: string;
    clientSessions?: string;
    opaqueClientSession?: string;
    opaqueClientSessions?: string;
    webviewTicket?: string;
    webviewTickets?: string;
    clientTicket?: string;
    clientTickets?: string;
    clientAuthBffState?: string;
    clientAuthBffStates?: string;
    clientAuthState?: string;
    clientAuthStates?: string;
    bffState?: string;
    bffStates?: string;
    clientAuthBffStateTable?: string;
    clientAuthBffStatesTable?: string;
    clientAuthStateTable?: string;
    clientAuthStatesTable?: string;
    bffStateTable?: string;
    bffStatesTable?: string;
  };
  columns?: ApplicationSqlColumns & {
    clientAuthBffState?: Partial<Record<string, string | null>>;
    clientAuthBffStates?: Partial<Record<string, string | null>>;
    clientAuthState?: Partial<Record<string, string | null>>;
    bffState?: Partial<Record<string, string | null>>;
  };
  columnNames?: ApplicationSqlColumns & {
    clientAuthBffState?: Partial<Record<string, string | null>>;
    clientAuthBffStates?: Partial<Record<string, string | null>>;
    clientAuthState?: Partial<Record<string, string | null>>;
    bffState?: Partial<Record<string, string | null>>;
  };
  applicationsColumns?: Partial<Record<string, string | null>>;
  platformsColumns?: Partial<Record<string, string | null>>;
  applicationPlatformsColumns?: Partial<Record<string, string | null>>;
  clientsColumns?: Partial<Record<string, string | null>>;
  applicationClientsColumns?: Partial<Record<string, string | null>>;
  auditEventsColumns?: Partial<Record<string, string | null>>;
  tenantColumn?: string | null;
  tenantId?: string;
  schema?: string;
  tenant?: TenantConfigInput;
  tenantConfig?: TenantConfigInput;
  tenantMode?: string;
  mode?: string;
  requireRls?: boolean;
  requireTransactions?: boolean;
  allowSharedFallback?: boolean;
  sharedPool?: unknown;
  fallbackPool?: unknown;
  applicationTable?: string;
  application?: string;
  applicationPlatform?: string;
  applicationPlatforms?: string;
  applicationPlatformsTable?: string;
  platformTable?: string;
  applicationPlatformTable?: string;
  platform?: string;
  clientTable?: string;
  applicationClient?: string;
  applicationClientTable?: string;
  applicationClients?: string;
  applicationClientsTable?: string;
  client?: string;
  auditTable?: string;
  auditEventsTable?: string;
  tenantsTable?: string;
  tenantTable?: string;
  tenants?: string;
  identityTable?: string;
  identitiesTable?: string;
  identity?: string;
  secretBindingTable?: string;
  secretBindingsTable?: string;
  secretBinding?: string;
  secretBindings?: string;
  externalIdentitiesTable?: string;
  applicationIdentitiesTable?: string;
  externalIdentityTable?: string;
  applicationIdentityTable?: string;
  platformLoginStateTable?: string;
  platformLoginStatesTable?: string;
  platformLoginState?: string;
  platformLoginStates?: string;
  clientSessionTable?: string;
  clientSessionsTable?: string;
  clientSession?: string;
  clientSessions?: string;
  opaqueClientSessionTable?: string;
  opaqueClientSessionsTable?: string;
  webviewTicketTable?: string;
  webviewTicketsTable?: string;
  webviewTicket?: string;
  webviewTickets?: string;
  clientTicketTable?: string;
  clientTicketsTable?: string;
  clientAuthBffStateTable?: string;
  clientAuthBffStatesTable?: string;
  clientAuthStateTable?: string;
  clientAuthStatesTable?: string;
  bffStateTable?: string;
  bffStatesTable?: string;
  clientAuthBffState?: string;
  clientAuthBffStates?: string;
  clientAuthState?: string;
  clientAuthStates?: string;
  bffState?: string;
  bffStates?: string;
  clientAuthBffStateColumns?: Partial<Record<string, string | null>>;
  clientAuthBffStatesColumns?: Partial<Record<string, string | null>>;
  clientAuthStateColumns?: Partial<Record<string, string | null>>;
  bffStateColumns?: Partial<Record<string, string | null>>;
  clientAuthBffMigrationVersion?: number;
  clientAuthBffMigrationName?: string;
  clientAuthBffStateMigrationVersion?: number;
  clientAuthBffStateMigrationName?: string;
  bffMigrationVersion?: number;
  bffMigrationName?: string;
  bffStateMigrationVersion?: number;
  bffStateMigrationName?: string;
  includeClientAuthBffState?: boolean;
  includeClientAuthBffStateMigration?: boolean;
  includeBffState?: boolean;
  clientSessionColumns?: Partial<Record<string, string | null>>;
  clientSessionsColumns?: Partial<Record<string, string | null>>;
  opaqueClientSessionColumns?: Partial<Record<string, string | null>>;
  opaqueClientSessionsColumns?: Partial<Record<string, string | null>>;
  webviewTicketColumns?: Partial<Record<string, string | null>>;
  webviewTicketsColumns?: Partial<Record<string, string | null>>;
  clientTicketColumns?: Partial<Record<string, string | null>>;
  clientTicketsColumns?: Partial<Record<string, string | null>>;
  additiveColumns?: {
    clients?: Partial<Record<string, string | null>>;
    platforms?: Partial<Record<string, string | null>>;
    clientSessions?: Partial<Record<string, string | null>>;
    webviewTickets?: Partial<Record<string, string | null>>;
    clientAuthBffState?: Partial<Record<string, string | null>>;
    clientAuthBffStates?: Partial<Record<string, string | null>>;
    clientAuthState?: Partial<Record<string, string | null>>;
    bffState?: Partial<Record<string, string | null>>;
  };
  clientKindColumn?: string;
  clientTypeColumn?: string;
  redirectUriPolicyColumn?: string;
  pkceRequiredColumn?: string;
  pkceMethodColumn?: string;
  consentRequiredColumn?: string;
  consentModeColumn?: string;
  consentScopesColumn?: string;
  opaqueSessionEnabledColumn?: string;
  clientSessionTtlSecondsColumn?: string;
  componentAppIdColumn?: string;
  componentAppSecretRefColumn?: string;
  componentVerifyTicketRefColumn?: string;
  componentAccessTokenRefColumn?: string;
  authorizedAppIdColumn?: string;
  authorizerAppIdColumn?: string;
  authorizerRefreshTokenRefColumn?: string;
  authorizerAccessTokenRefColumn?: string;
  componentTicketRefColumn?: string;
  componentTicketExpiresAtColumn?: string;
  componentBindingStatusColumn?: string;
  componentBindingVersionColumn?: string;
  componentScopeColumn?: string;
  includeClientExtensions?: boolean;
  includeOpaqueClientSessions?: boolean;
  includeClientSessions?: boolean;
  includeWebviewTickets?: boolean;
  includeComponentPlatformBindings?: boolean;
  includeAdditive?: boolean;
  includeLegacyFoundation?: boolean;
  additiveMigrationVersion?: number;
  additiveMigrationName?: string;
  returnToMigrationVersion?: number;
  returnToMigrationName?: string;
  includeReturnToMigration?: boolean;
  includePlatformLoginReturnToMigration?: boolean;
  platformLoginStateReturnToColumn?: string | null;
  returnToColumn?: string | null;
  includeTenantFoundation?: boolean;
  includeMigrationMetadata?: boolean;
  includeRls?: boolean;
  migrationVersion?: number;
  migrationName?: string;
  migrationTable?: string;
  migrationHistoryTable?: string;
  migrationLockTable?: string;
  migrationLockKey?: string | number;
  migrationOwnerId?: string;
  requireTransaction?: boolean;
  allowNonTransactional?: boolean;
}

const DEFAULT_PLATFORM_LOGIN_STATE_COLUMNS = {
  tenantId: "tenant_id",
  stateHash: "state_hash",
  bindingHash: "binding_hash",
  browserBindingHash: "browser_binding_hash",
  sessionBindingHash: "session_binding_hash",
  applicationId: "application_id",
  platformId: "platform_id",
  flow: "flow",
  status: "status",
  leaseOwner: "lease_owner",
  leaseExpiresAt: "lease_expires_at",
  expiresAt: "expires_at",
  redirectUri: "redirect_uri",
  returnTo: "return_to",
  scope: "scope",
  linkingPolicy: "linking_policy",
  requestedUserId: "requested_user_id",
  createdAt: "created_at",
  updatedAt: "updated_at",
  consumedAt: "consumed_at",
} as const;

type MigrationTables = {
  applications: string;
  platforms: string;
  clients: string;
  auditEvents: string;
  tenants: string;
  identities: string;
  externalIdentities: string;
  secretBindings: string;
  platformLoginStates: string;
};

type MigrationColumns = {
  applications: Record<string, string>;
  platforms: Record<string, string>;
  clients: Record<string, string>;
  auditEvents: Record<string, string>;
  tenants: TenantSqlColumns;
  identities: IdentitySqlColumns;
  externalIdentities: ApplicationIdentitySqlColumns;
  secretBindings: SecretBindingSqlColumns;
  platformLoginStates: Record<string, string>;
};

type AdditiveMigrationTables = {
  applications: string;
  clients: string;
  platforms: string;
  clientSessions: string;
  webviewTickets: string;
};

type AdditiveMigrationColumns = {
  clients: Record<string, string>;
  platforms: Record<string, string>;
  clientSessions: Record<string, string>;
  webviewTickets: Record<string, string>;
};

type ClientAuthBffStateMigrationTables = {
  clientAuthBffStates: string;
};

type ClientAuthBffStateMigrationColumns = Record<string, string>;

const DEFAULT_CLIENT_AUTH_BFF_STATE_COLUMNS = {
  tenantId: "tenant_id",
  stateHash: "state_hash",
  nonce: "nonce",
  codeChallenge: "code_challenge",
  redirectUri: "redirect_uri",
  clientType: "client_type",
  clientId: "client_id",
  scope: "scope",
  bindingHash: "binding_hash",
  expiresAt: "expires_at",
} as const;

const DEFAULT_ADDITIVE_CLIENT_COLUMNS = {
  clientKind: "client_kind",
  clientType: "client_type",
  redirectUriPolicy: "redirect_uri_policy",
  pkceRequired: "pkce_required",
  pkceMethod: "pkce_method",
  consentRequired: "consent_required",
  consentMode: "consent_mode",
  consentScopes: "consent_scopes",
  opaqueSessionEnabled: "opaque_session_enabled",
  clientSessionTtlSeconds: "client_session_ttl_seconds",
} as const;

const DEFAULT_ADDITIVE_PLATFORM_COLUMNS = {
  componentAppId: "component_app_id",
  componentAppSecretRef: "component_app_secret_ref",
  componentVerifyTicketRef: "component_verify_ticket_ref",
  componentAccessTokenRef: "component_access_token_ref",
  authorizedAppId: "authorized_app_id",
  authorizerAppId: "authorizer_app_id",
  authorizerRefreshTokenRef: "authorizer_refresh_token_ref",
  authorizerAccessTokenRef: "authorizer_access_token_ref",
  componentTicketRef: "component_ticket_ref",
  componentTicketExpiresAt: "component_ticket_expires_at",
  componentBindingStatus: "component_binding_status",
  componentBindingVersion: "component_binding_version",
  componentScope: "component_scope",
} as const;

const DEFAULT_CLIENT_SESSION_COLUMNS = {
  id: "id",
  tenantId: "tenant_id",
  applicationId: "application_id",
  clientId: "client_id",
  clientKind: "client_kind",
  sessionHash: "session_hash",
  userId: "user_id",
  status: "status",
  deviceId: "device_id",
  bindingHash: "binding_hash",
  createdAt: "created_at",
  updatedAt: "updated_at",
  lastUsedAt: "last_used_at",
  expiresAt: "expires_at",
  revokedAt: "revoked_at",
} as const;

const DEFAULT_WEBVIEW_TICKET_COLUMNS = {
  id: "id",
  tenantId: "tenant_id",
  applicationId: "application_id",
  platformId: "platform_id",
  clientId: "client_id",
  ticketHash: "ticket_hash",
  sessionHash: "session_hash",
  bindingHash: "binding_hash",
  redirectUri: "redirect_uri",
  status: "status",
  createdAt: "created_at",
  updatedAt: "updated_at",
  consumedAt: "consumed_at",
  expiresAt: "expires_at",
  revokedAt: "revoked_at",
} as const;

export function createApplicationManagementMigrationSql(
  options: ApplicationManagementMigrationOptions = {},
): string {
  const tables = migrationTables(options);
  const columns = migrationColumns(options);
  const tenant = migrationTenant(options);
  const statements: string[] = [
    ...(options.includeTenantFoundation === false ? [] : [
      createTenantTableMigrationSql(tables.tenants, columns.tenants),
      createIdentityTableMigrationSql(tables.identities, columns.identities, columns.applications.tenantId),
      createApplicationExternalIdentityTableMigrationSql(tables.externalIdentities, columns.externalIdentities, columns.applications.tenantId),
      createSecretBindingTableMigrationSql(tables.secretBindings, columns.secretBindings, columns.applications.tenantId),
    ]),
    createApplicationTable(tables.applications, columns.applications),
      createPlatformTable(tables.platforms, columns.platforms, tables.applications, columns.applications.id, columns.applications.tenantId),
      uniqueIndex(createTenantSqlObjectName(tables.platforms, "application_id_uq"), tables.platforms, [columns.platforms.tenantId, columns.platforms.applicationId, columns.platforms.id]),
      createClientTable(tables.clients, columns.clients, tables.applications, columns.applications.id, columns.applications.tenantId),
      createPlatformLoginStateTable(
        tables.platformLoginStates,
        columns.platformLoginStates,
        tables.applications,
        columns.applications,
        tables.platforms,
        columns.platforms,
        options.includeReturnToMigration === true || options.includePlatformLoginReturnToMigration === true,
      ),
         createAuditTable(tables.auditEvents, columns.auditEvents),
         ensurePlatformLoginStateColumns(
         tables.platformLoginStates,
         columns.platformLoginStates,
         options.includeReturnToMigration === true || options.includePlatformLoginReturnToMigration === true,
       ),
                  ...(options.includeTenantFoundation === false ? [] : [addExternalIdentityForeignKeys(
        tables.externalIdentities,
        columns.externalIdentities,
        tables.applications,
        columns.applications,
        tables.platforms,
        columns.platforms,
      )]),
      addPlatformLoginStateForeignKeys(
        tables.platformLoginStates,
        columns.platformLoginStates,
        tables.applications,
        columns.applications,
        tables.platforms,
        columns.platforms,
      ),
      ensureApplicationColumns(tables.applications, columns.applications),

    ensurePlatformColumns(tables.platforms, columns.platforms),
     ensureClientColumns(tables.clients, columns.clients),
     ensureAuditColumns(tables.auditEvents, columns.auditEvents),
         uniqueLowerIndex(createTenantSqlObjectName(tables.applications, "slug_lower_uq"), tables.applications, [
      columns.applications.tenantId,
      columns.applications.slug,
    ]),
    uniqueLowerIndex(createTenantSqlObjectName(tables.clients, "client_id_lower_uq"), tables.clients, [
      columns.clients.tenantId,
      columns.clients.clientId,
    ]),
    uniqueIndex(createTenantSqlObjectName(tables.applications, "tenant_id_uq"), tables.applications, [columns.applications.tenantId, columns.applications.id]),
     uniqueIndex(createTenantSqlObjectName(tables.platforms, "tenant_id_uq"), tables.platforms, [columns.platforms.tenantId, columns.platforms.id]),
     uniqueIndex(createTenantSqlObjectName(tables.platforms, "application_id_uq"), tables.platforms, [columns.platforms.tenantId, columns.platforms.applicationId, columns.platforms.id]),
     uniqueIndex(createTenantSqlObjectName(tables.clients, "tenant_id_uq"), tables.clients, [columns.clients.tenantId, columns.clients.id]),
    queryIndex(createTenantSqlObjectName(tables.applications, "query_idx"), tables.applications, [
      columns.applications.tenantId,
      columns.applications.status,
      columns.applications.slug,
    ]),
    queryIndex(createTenantSqlObjectName(tables.platforms, "query_idx"), tables.platforms, [
      columns.platforms.tenantId,
      columns.platforms.applicationId,
      columns.platforms.status,
      columns.platforms.type,
    ]),
     queryIndex(createTenantSqlObjectName(tables.clients, "query_idx"), tables.clients, [
       columns.clients.tenantId,
       columns.clients.applicationId,
       columns.clients.status,
       columns.clients.clientId,
     ]),
      uniqueIndex(createTenantSqlObjectName(tables.platformLoginStates, "scope_uq"), tables.platformLoginStates, [columns.platformLoginStates.tenantId, columns.platformLoginStates.applicationId, columns.platformLoginStates.stateHash]),
     queryIndex(createTenantSqlObjectName(tables.platformLoginStates, "expiry_idx"), tables.platformLoginStates, [columns.platformLoginStates.tenantId, columns.platformLoginStates.status, columns.platformLoginStates.expiresAt]),
     queryIndex(createTenantSqlObjectName(tables.platformLoginStates, "lease_idx"), tables.platformLoginStates, [columns.platformLoginStates.tenantId, columns.platformLoginStates.leaseExpiresAt]),
     queryIndex(createTenantSqlObjectName(tables.auditEvents, "query_idx"), tables.auditEvents, [
      columns.auditEvents.tenantId,
      columns.auditEvents.occurredAt,
    ]),
  ];
  if (tenant.requireRls || options.includeRls === true) {
    statements.push(
      ...rlsStatements(tables.applications, columns.applications.tenantId, createTenantSqlObjectName(tables.applications, "tenant")),
       ...rlsStatements(tables.platforms, columns.platforms.tenantId, createTenantSqlObjectName(tables.platforms, "tenant")),
        ...rlsStatements(tables.clients, columns.clients.tenantId, createTenantSqlObjectName(tables.clients, "tenant")),
        ...rlsStatements(tables.platformLoginStates, columns.platformLoginStates.tenantId, createTenantSqlObjectName(tables.platformLoginStates, "tenant")),
        ...rlsStatements(tables.auditEvents, columns.auditEvents.tenantId, createTenantSqlObjectName(tables.auditEvents, "tenant")),
      ...(options.includeTenantFoundation === false ? [] : [
         ...rlsStatements(tables.tenants, columns.tenants.id, createTenantSqlObjectName(tables.tenants, "tenant")),
         ...rlsStatements(tables.identities, columns.identities.tenantId, createTenantSqlObjectName(tables.identities, "tenant")),
         ...rlsStatements(tables.externalIdentities, columns.externalIdentities.tenantId, createTenantSqlObjectName(tables.externalIdentities, "tenant")),
         ...rlsStatements(tables.secretBindings, columns.secretBindings.tenantId, createTenantSqlObjectName(tables.secretBindings, "tenant")),
      ]),
    );
  }
  if (options.includeMigrationMetadata !== false) {
    const migrationSchema = tenant.schema;
    statements.push(createMigrationMetadataSql({
      tableName: qualifyTenantTable(options.migrationTable ?? options.migrationHistoryTable ?? DEFAULT_APPLICATION_MIGRATION_TABLE, migrationSchema),
      lockTableName: qualifyTenantTable(options.migrationLockTable ?? DEFAULT_APPLICATION_MIGRATION_LOCK_TABLE, migrationSchema),
    }));
  }
  return `${statements.join(";\n")};\n`;
}

export const buildApplicationManagementMigrationSql = createApplicationManagementMigrationSql;
export const getApplicationManagementMigrationSql = createApplicationManagementMigrationSql;
export const createApplicationManagementMigration = createApplicationManagementMigrationSql;
export const getApplicationManagementMigration = createApplicationManagementMigrationSql;
export const applicationManagementMigrationSql = createApplicationManagementMigrationSql;

export const APPLICATION_MANAGEMENT_MIGRATION_SQL = createApplicationManagementMigrationSql();
export const APPLICATION_MANAGEMENT_LEGACY_MIGRATION_SQL = APPLICATION_MANAGEMENT_MIGRATION_SQL;
export const APPLICATION_MANAGEMENT_LEGACY_MIGRATION_CHECKSUM = migrationChecksum(APPLICATION_MANAGEMENT_LEGACY_MIGRATION_SQL);

export function getApplicationManagementMigrationDefinition(
  options: ApplicationManagementMigrationOptions = {},
): MigrationDefinition {
  return createMigrationDefinition(
    options.migrationVersion ?? APPLICATION_MANAGEMENT_MIGRATION_VERSION,
    options.migrationName ?? APPLICATION_MANAGEMENT_MIGRATION_NAME,
    createApplicationManagementMigrationSql(options),
    {
      component: "application-management",
      tenantMode: migrationTenant(options).mode,
      tenantId: migrationTenant(options).tenantId,
      scope: applicationMigrationScope(options),
      checksumAlgorithm: "sha256",
    },
    applicationMigrationScope(options),
  );
}

export const createApplicationManagementMigrationDefinition = getApplicationManagementMigrationDefinition;
export const getApplicationManagementLegacyMigrationDefinition = getApplicationManagementMigrationDefinition;
export const createApplicationManagementLegacyMigrationDefinition = getApplicationManagementMigrationDefinition;

export function getApplicationManagementMigrations(
  options: ApplicationManagementMigrationOptions = {},
): MigrationDefinition[] {
  const migrations: MigrationDefinition[] = [];
  const historicalOptions = {
    ...options,
    includeReturnToMigration: false,
    includePlatformLoginReturnToMigration: false,
  };
  if (options.includeLegacyFoundation !== false) migrations.push(getApplicationManagementMigrationDefinition(historicalOptions));
  if (options.includeAdditive !== false) {
    migrations.push(getApplicationManagementAdditiveMigrationDefinition(historicalOptions));
    if (options.includeReturnToMigration !== false && options.includePlatformLoginReturnToMigration !== false) {
      migrations.push(getApplicationManagementReturnToMigrationDefinition(options));
      if (options.includeClientAuthBffState !== false && options.includeClientAuthBffStateMigration !== false && options.includeBffState !== false) {
        migrations.push(getApplicationManagementClientAuthBffMigrationDefinition(options));
      }
    }
  }
  return migrations;
}

export function getApplicationManagementMigrationChecksum(
  options: ApplicationManagementMigrationOptions = {},
): string {
  return migrationChecksum(createApplicationManagementMigrationSql(options));
}

export const getApplicationManagementLegacyMigrationChecksum = getApplicationManagementMigrationChecksum;
export const createApplicationManagementLegacyMigrationChecksum = getApplicationManagementMigrationChecksum;

export function createApplicationManagementMigrationPlan(
  options: ApplicationManagementMigrationOptions = {},
): { version: number; name: string; checksum: string; sql: string } {
  const definition = getApplicationManagementMigrationDefinition(options);
  return {
    version: definition.version,
    name: definition.name,
    checksum: migrationChecksum(definition.sql),
    sql: definition.sql,
  };
}

export function dryRunApplicationManagementMigration(
  options?: ApplicationManagementMigrationOptions,
): MigrationDryRunResult;
export function dryRunApplicationManagementMigration(
  executor: MigrationSqlExecutor,
  options?: ApplicationManagementMigrationOptions,
): MigrationDryRunResult;
export function dryRunApplicationManagementMigration(
  executorOrOptions: MigrationSqlExecutor | ApplicationManagementMigrationOptions = {},
  secondOptions: ApplicationManagementMigrationOptions = {},
): MigrationDryRunResult {
  const hasExecutor = isMigrationExecutor(executorOrOptions);
  const options = hasExecutor ? secondOptions : executorOrOptions;
  const definition = getApplicationManagementMigrationDefinition(options);
  const coordinator = new MigrationCoordinator(
    hasExecutor ? executorOrOptions : { query: async () => ({ rows: [] }) },
    [definition],
    {
      tableName: qualifyTenantTable(options.migrationTable ?? options.migrationHistoryTable ?? DEFAULT_APPLICATION_MIGRATION_TABLE, options.schema ?? migrationTenant(options).schema),
      lockTableName: qualifyTenantTable(options.migrationLockTable ?? DEFAULT_APPLICATION_MIGRATION_LOCK_TABLE, options.schema ?? migrationTenant(options).schema),
       lockKey: options.migrationLockKey,
       lockNamespace: applicationMigrationLockNamespace(options),
       scope: applicationMigrationScope(options),
       ownerId: options.migrationOwnerId,
       requireTransaction: false,
    },
  );
  return coordinator.dryRun([definition]);
}

export async function applyVersionedApplicationManagementMigration(
  executor: { query(text: string, values?: unknown[]): unknown | Promise<unknown>; transaction?: MigrationSqlExecutor["transaction"] },
  options: ApplicationManagementMigrationOptions = {},
): Promise<MigrationRunResult> {
  const definition = getApplicationManagementMigrationDefinition(options);
  const migrationExecutor: MigrationSqlExecutor = {
    query: (text, values) => executor.query(text, values ?? []),
    ...(typeof executor.transaction === "function"
      ? { transaction: executor.transaction.bind(executor) as unknown as MigrationSqlExecutor["transaction"] }
      : {}),
  };
  const coordinator = new MigrationCoordinator(
    migrationExecutor,
    [definition],
    {
      tableName: qualifyTenantTable(options.migrationTable ?? options.migrationHistoryTable ?? DEFAULT_APPLICATION_MIGRATION_TABLE, options.schema ?? migrationTenant(options).schema),
      lockTableName: qualifyTenantTable(options.migrationLockTable ?? DEFAULT_APPLICATION_MIGRATION_LOCK_TABLE, options.schema ?? migrationTenant(options).schema),
       lockKey: options.migrationLockKey,
       lockNamespace: applicationMigrationLockNamespace(options),
       scope: applicationMigrationScope(options),
       ownerId: options.migrationOwnerId,
       requireTransaction: options.requireTransaction ?? options.allowNonTransactional !== true,
    },
  );
  return coordinator.run([definition]);
}

export async function applyApplicationManagementMigration(
  executor: { query(text: string, values?: unknown[]): unknown | Promise<unknown> },
  options: ApplicationManagementMigrationOptions = {},
): Promise<void> {
  await applyVersionedApplicationManagementMigration(executor, options);
}

export const runApplicationManagementMigration = applyVersionedApplicationManagementMigration;
export const runVersionedApplicationManagementMigration = applyVersionedApplicationManagementMigration;
export const getApplicationManagementMigrationPlan = createApplicationManagementMigrationPlan;
export const planApplicationManagementMigration = createApplicationManagementMigrationPlan;

function isMigrationExecutor(value: unknown): value is MigrationSqlExecutor {
  return typeof value === "object" && value !== null && typeof (value as { query?: unknown }).query === "function";
}

function applicationMigrationScope(options: ApplicationManagementMigrationOptions): string {
  const tenant = migrationTenant(options);
  return `application-management:${tenant.mode}:${tenant.schema}:${tenant.tenantId}`;
}

function applicationMigrationLockNamespace(options: ApplicationManagementMigrationOptions): string {
  const tenant = migrationTenant(options);
  const table = options.migrationTable ?? options.migrationHistoryTable ?? DEFAULT_APPLICATION_MIGRATION_TABLE;
  return `application-management:${tenant.schema}:${unqualifiedName(table)}`;
}

function migrationTenant(options: ApplicationManagementMigrationOptions): TenantConfig {
  return normalizeTenantConfig({
    ...(options.tenant ?? {}),
    ...(options.tenantConfig ?? {}),
    ...(options.tenantMode === undefined ? {} : { mode: options.tenantMode }),
    ...(options.mode === undefined ? {} : { mode: options.mode }),
    ...(options.tenantId === undefined ? {} : { tenantId: options.tenantId }),
    ...(options.tenantColumn === undefined ? {} : { tenantColumn: options.tenantColumn }),
    ...(options.schema === undefined ? {} : { schema: options.schema }),
    ...(options.requireRls === undefined ? {} : { requireRls: options.requireRls }),
     ...(options.requireTransactions === undefined ? {} : { requireTransactions: options.requireTransactions }),
     ...(options.allowSharedFallback === undefined ? {} : { allowSharedFallback: options.allowSharedFallback }),
     ...(options.sharedPool === undefined ? {} : { sharedPool: options.sharedPool }),
     ...(options.fallbackPool === undefined ? {} : { fallbackPool: options.fallbackPool }),
   });
}

function migrationTables(options: ApplicationManagementMigrationOptions): MigrationTables {
  const tables = {
    ...APPLICATION_MANAGEMENT_SQL_TABLES,
    ...(options.tables ?? {}),
    ...(options.tableNames ?? {}),
    ...(options.tables?.applicationPlatforms === undefined ? {} : { platforms: options.tables.applicationPlatforms }),
    ...(options.tables?.application === undefined ? {} : { applications: options.tables.application }),
    ...(options.tableNames?.application === undefined ? {} : { applications: options.tableNames.application }),
    ...(options.tables?.applicationPlatform === undefined ? {} : { platforms: options.tables.applicationPlatform }),
    ...(options.tableNames?.applicationPlatform === undefined ? {} : { platforms: options.tableNames.applicationPlatform }),
    ...(options.tables?.applicationPlatforms === undefined ? {} : { platforms: options.tables.applicationPlatforms }),
    ...(options.tableNames?.applicationPlatforms === undefined ? {} : { platforms: options.tableNames.applicationPlatforms }),
    ...(options.tables?.platform === undefined ? {} : { platforms: options.tables.platform }),
    ...(options.tableNames?.platform === undefined ? {} : { platforms: options.tableNames.platform }),
    ...(options.tables?.applicationClient === undefined ? {} : { clients: options.tables.applicationClient }),
    ...(options.tableNames?.applicationClient === undefined ? {} : { clients: options.tableNames.applicationClient }),
    ...(options.tables?.applicationClients === undefined ? {} : { clients: options.tables.applicationClients }),
    ...(options.tableNames?.applicationClients === undefined ? {} : { clients: options.tableNames.applicationClients }),
    ...(options.tables?.client === undefined ? {} : { clients: options.tables.client }),
    ...(options.tableNames?.client === undefined ? {} : { clients: options.tableNames.client }),
    ...(options.tables?.audit === undefined ? {} : { auditEvents: options.tables.audit }),
    ...(options.tableNames?.audit === undefined ? {} : { auditEvents: options.tableNames.audit }),
    ...(options.applicationTable === undefined ? {} : { applications: options.applicationTable }),
    ...(options.application === undefined ? {} : { applications: options.application }),
    ...(options.applicationPlatform === undefined ? {} : { platforms: options.applicationPlatform }),
    ...(options.applicationPlatforms === undefined ? {} : { platforms: options.applicationPlatforms }),
    ...(options.applicationPlatformsTable === undefined ? {} : { platforms: options.applicationPlatformsTable }),
    ...(options.platformTable === undefined ? {} : { platforms: options.platformTable }),
    ...(options.applicationPlatformTable === undefined ? {} : { platforms: options.applicationPlatformTable }),
    ...(options.platform === undefined ? {} : { platforms: options.platform }),
    ...(options.clientTable === undefined ? {} : { clients: options.clientTable }),
    ...(options.applicationClient === undefined ? {} : { clients: options.applicationClient }),
    ...(options.applicationClientTable === undefined ? {} : { clients: options.applicationClientTable }),
    ...(options.applicationClients === undefined ? {} : { clients: options.applicationClients }),
    ...(options.applicationClientsTable === undefined ? {} : { clients: options.applicationClientsTable }),
    ...(options.client === undefined ? {} : { clients: options.client }),
    ...(options.auditTable === undefined ? {} : { auditEvents: options.auditTable }),
    ...(options.auditEventsTable === undefined ? {} : { auditEvents: options.auditEventsTable }),
  };
  const schema = migrationTenant(options).schema;
  return {
    applications: qualifyTenantTable(validateApplicationSqlIdentifier(tables.applications, "applications table"), schema),
    platforms: qualifyTenantTable(validateApplicationSqlIdentifier(tables.platforms, "platforms table"), schema),
    clients: qualifyTenantTable(validateApplicationSqlIdentifier(tables.clients, "clients table"), schema),
    auditEvents: qualifyTenantTable(validateApplicationSqlIdentifier(tables.auditEvents, "audit events table"), schema),
    tenants: qualifyTenantTable(options.tenantsTable ?? options.tenantTable ?? options.tenants ?? "gb_idaas_tenant", schema),
    identities: qualifyTenantTable(options.identityTable ?? options.identitiesTable ?? options.identity ?? options.tables?.identities ?? options.tableNames?.identities ?? "gb_idaas_identity", schema),
    externalIdentities: qualifyTenantTable(options.externalIdentitiesTable ?? options.applicationIdentitiesTable ?? options.externalIdentityTable ?? options.applicationIdentityTable ?? options.tables?.externalIdentities ?? options.tables?.applicationExternalIdentities ?? options.tableNames?.externalIdentities ?? options.tableNames?.applicationExternalIdentities ?? "gb_idaas_application_external_identity", schema),
     secretBindings: qualifyTenantTable(options.secretBindingTable ?? options.secretBindingsTable ?? options.secretBinding ?? options.secretBindings ?? options.tables?.secretBindings ?? options.tableNames?.secretBindings ?? "gb_idaas_secret_binding", schema),
     platformLoginStates: qualifyTenantTable(options.platformLoginStateTable ?? options.platformLoginStatesTable ?? options.platformLoginState ?? options.platformLoginStates ?? options.tables?.platformLoginStates ?? options.tableNames?.platformLoginStates ?? DEFAULT_PLATFORM_LOGIN_STATE_TABLE, schema),
   };
}

function migrationColumns(options: ApplicationManagementMigrationOptions): MigrationColumns {
  const tenant = migrationTenant(options);
  const tenantColumn = tenant.tenantColumn;
  const applications = mergeColumns(
    APPLICATION_MANAGEMENT_SQL_COLUMNS.applications ?? {},
    options.columns?.applications,
    options.columns?.application,
    options.columnNames?.applications,
    options.columnNames?.application,
    options.applicationsColumns,
  );
  const platforms = mergeColumns(
    APPLICATION_MANAGEMENT_SQL_COLUMNS.platforms ?? {},
    options.columns?.platforms,
    options.columns?.applicationPlatform,
    options.columns?.applicationPlatforms,
    options.columnNames?.platforms,
    options.columnNames?.applicationPlatform,
    options.columnNames?.applicationPlatforms,
    options.platformsColumns,
    options.applicationPlatformsColumns,
  );
  const clients = mergeColumns(
    APPLICATION_MANAGEMENT_SQL_COLUMNS.clients ?? {},
    options.columns?.clients,
    options.columns?.applicationClient,
    options.columns?.applicationClients,
    options.columnNames?.clients,
    options.columnNames?.applicationClient,
    options.columnNames?.applicationClients,
    options.clientsColumns,
    options.applicationClientsColumns,
  );
  const auditEvents = mergeColumns(
    APPLICATION_MANAGEMENT_SQL_COLUMNS.auditEvents ?? {},
    options.columns?.auditEvents,
    options.columns?.audit,
    options.columnNames?.auditEvents,
    options.columnNames?.audit,
    options.auditEventsColumns,
  );
  setColumn(applications, "tenantId", tenantColumn);
  setColumn(platforms, "tenantId", tenantColumn);
  setColumn(clients, "tenantId", tenantColumn);
  setColumn(auditEvents, "tenantId", tenantColumn);
  return {
    applications: requiredColumns(applications, ["id", "tenantId", "name", "slug", "status", "createdAt", "updatedAt", "version"]),
    platforms: requiredColumns(platforms, ["id", "tenantId", "applicationId", "type", "status", "createdAt", "updatedAt", "version"]),
    clients: requiredColumns(clients, ["id", "tenantId", "applicationId", "clientId", "clientIdScope", "status", "createdAt", "updatedAt", "version"]),
    auditEvents: requiredColumns(auditEvents, ["id", "tenantId", "event", "occurredAt", "createdAt"]),
    tenants: {
      id: "id",
      mode: "mode",
      status: "status",
      schemaName: "schema_name",
      version: "version",
      metadata: "metadata",
      createdAt: "created_at",
      updatedAt: "updated_at",
    },
    identities: {
      id: "id",
      tenantId: tenant.tenantColumn,
      kind: "kind",
      provider: "provider",
      subject: "subject",
      externalId: "external_id",
      label: "label",
      metadata: "metadata",
      version: "version",
      createdAt: "created_at",
      updatedAt: "updated_at",
      disabledAt: "disabled_at",
    },
    externalIdentities: {
      id: "id",
      tenantId: tenant.tenantColumn,
      applicationId: "application_id",
      platformId: "platform_id",
      platform: "platform",
      provider: "provider",
      providerAppId: "provider_app_id",
      subject: "subject",
      externalAppId: "external_app_id",
      openid: "openid",
      unionid: "unionid",
      nickname: "nickname",
      displayName: "display_name",
      email: "email",
       avatarUrl: "avatar_url",
       scopes: "scopes",
       canonicalUserId: "canonical_user_id",
       linkStatus: "link_status",
       emailVerified: "email_verified",
       firstLinkedAt: "first_linked_at",
      linkedAt: "linked_at",
      lastAuthenticatedAt: "last_authenticated_at",
      version: "version",
      createdAt: "created_at",
      updatedAt: "updated_at",
    },
    secretBindings: {
      id: "id",
      tenantId: tenant.tenantColumn,
      subjectType: "subject_type",
      subjectId: "subject_id",
      purpose: "purpose",
      version: "version",
      secretRef: "secret_ref",
      status: "status",
      gracePeriodSeconds: "grace_period_seconds",
      validFrom: "valid_from",
      graceUntil: "grace_until",
      supersededAt: "superseded_at",
      revokedAt: "revoked_at",
      createdAt: "created_at",
      updatedAt: "updated_at",
    },
    platformLoginStates: {
      ...DEFAULT_PLATFORM_LOGIN_STATE_COLUMNS,
      tenantId: tenant.tenantColumn,
      ...(typeof options.platformLoginStateReturnToColumn === "string" ? { returnTo: validateMigrationColumn(options.platformLoginStateReturnToColumn, "returnTo") } : {}),
      ...(typeof options.returnToColumn === "string" ? { returnTo: validateMigrationColumn(options.returnToColumn, "returnTo") } : {}),
    },
  };
}

function mergeColumns(
  base: Partial<Record<string, string | null>>,
  ...sources: Array<Partial<Record<string, string | null>> | undefined>
): Record<string, string> {
  const output: Record<string, string> = {};
  for (const [key, value] of Object.entries(base)) {
    if (typeof value === "string") output[key] = validateMigrationColumn(value, key);
  }
  for (const source of sources) {
    if (!source) continue;
    for (const [key, value] of Object.entries(source)) {
      if (typeof value === "string") output[key] = validateMigrationColumn(value, key);
    }
  }
  return output;
}

function validateMigrationColumn(value: string, field: string): string {
  const normalized = value.replace(/[-_]/g, "").toLowerCase();
  if (["secret", "clientsecret", "token", "accesstoken", "refreshtoken", "idtoken", "privatekey"].includes(normalized)) {
    throw new TypeError(`Sensitive SQL column name for ${field} is not allowed`);
  }
  return validateApplicationSqlIdentifier(value, `column ${field}`);
}

function setColumn(target: Record<string, string>, key: string, value: string | undefined): void {
  if (value === undefined) delete target[key];
  else target[key] = validateMigrationColumn(value, key);
}

function requiredColumns(columns: Record<string, string>, required: string[]): Record<string, string> {
  for (const key of required) {
    if (!columns[key]) throw new TypeError(`Missing SQL column ${key}`);
  }
  return columns;
}

function ensureApplicationColumns(table: string, columns: Record<string, string>): string {
  return [
    addColumn(table, columns.id, "TEXT"),
    addColumn(table, columns.tenantId, "TEXT"),
    addColumn(table, columns.applicationType, "TEXT DEFAULT 'web'"),
    addColumn(table, columns.name, "TEXT"),
    addColumn(table, columns.slug, "TEXT"),
    addColumn(table, columns.description, "TEXT"),
    addColumn(table, columns.status, "TEXT DEFAULT 'active'"),
    addColumn(table, columns.lifecycleStatus, "TEXT DEFAULT 'active'"),
    addColumn(table, columns.readiness, "TEXT DEFAULT 'ready'"),
    addColumn(table, columns.effectiveStatus, "TEXT DEFAULT 'active'"),
    addColumn(table, columns.version, "INTEGER DEFAULT 1"),
    addColumn(table, columns.etag, "TEXT"),
    addColumn(table, columns.previousStatus, "TEXT"),
    addColumn(table, columns.createdAt, "TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP"),
    addColumn(table, columns.updatedAt, "TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP"),
    addColumn(table, columns.enabledAt, "TIMESTAMPTZ"),
    addColumn(table, columns.disabledAt, "TIMESTAMPTZ"),
    addColumn(table, columns.archivedAt, "TIMESTAMPTZ"),
    addColumn(table, columns.purgedAt, "TIMESTAMPTZ"),
  ].filter((statement): statement is string => statement !== undefined).join(";\n");
}

function ensurePlatformColumns(table: string, columns: Record<string, string>): string {
  return [
    addColumn(table, columns.id, "TEXT"),
    addColumn(table, columns.tenantId, "TEXT"),
    addColumn(table, columns.applicationId, "TEXT"),
    addColumn(table, columns.type, "TEXT"),
    addColumn(table, columns.externalAppId, "TEXT"),
    addColumn(table, columns.displayName, "TEXT"),
    addColumn(table, columns.loginMode, "TEXT"),
    addColumn(table, columns.scope, "TEXT"),
    addColumn(table, columns.scopes, "TEXT DEFAULT '[]'"),
    addColumn(table, columns.redirectUris, "TEXT DEFAULT '[]'"),
    addColumn(table, columns.endpointUrl, "TEXT"),
    addColumn(table, columns.secretRef, "TEXT"),
    addColumn(table, columns.lifecycleStatus, "TEXT DEFAULT 'active'"),
    addColumn(table, columns.readiness, "TEXT DEFAULT 'not_ready'"),
    addColumn(table, columns.effectiveStatus, "TEXT DEFAULT 'not_ready'"),
    addColumn(table, columns.version, "INTEGER DEFAULT 1"),
    addColumn(table, columns.etag, "TEXT"),
    addColumn(table, columns.secretVersion, "INTEGER DEFAULT 0"),
    addColumn(table, columns.status, "TEXT DEFAULT 'active'"),
    addColumn(table, columns.createdAt, "TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP"),
    addColumn(table, columns.updatedAt, "TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP"),
    addColumn(table, columns.enabledAt, "TIMESTAMPTZ"),
    addColumn(table, columns.disabledAt, "TIMESTAMPTZ"),
    addColumn(table, columns.archivedAt, "TIMESTAMPTZ"),
    addColumn(table, columns.purgedAt, "TIMESTAMPTZ"),
  ].filter((statement): statement is string => statement !== undefined).join(";\n");
}

function ensureClientColumns(table: string, columns: Record<string, string>): string {
  return [
    addColumn(table, columns.id, "TEXT"),
    addColumn(table, columns.tenantId, "TEXT"),
    addColumn(table, columns.applicationId, "TEXT"),
    addColumn(table, columns.clientId, "TEXT"),
    addColumn(table, columns.clientIdScope, "TEXT DEFAULT 'global'"),
    addColumn(table, columns.status, "TEXT DEFAULT 'active'"),
    addColumn(table, columns.redirectUris, "TEXT DEFAULT '[]'"),
    addColumn(table, columns.postLogoutRedirectUris, "TEXT DEFAULT '[]'"),
    addColumn(table, columns.grantTypes, "TEXT DEFAULT '[]'"),
    addColumn(table, columns.responseTypes, "TEXT DEFAULT '[]'"),
    addColumn(table, columns.scopes, "TEXT DEFAULT '[]'"),
    addColumn(table, columns.tokenEndpointAuthMethod, "TEXT DEFAULT 'client_secret_basic'"),
    addColumn(table, columns.tokenEndpointAuthSigningAlg, "TEXT"),
    addColumn(table, columns.jwksUri, "TEXT"),
    addColumn(table, columns.privateKeyRef, "TEXT"),
    addColumn(table, columns.keyId, "TEXT"),
    addColumn(table, columns.requirePkce, "BOOLEAN DEFAULT TRUE"),
    addColumn(table, columns.secretRef, "TEXT"),
    addColumn(table, columns.lifecycleStatus, "TEXT DEFAULT 'active'"),
    addColumn(table, columns.readiness, "TEXT DEFAULT 'not_ready'"),
    addColumn(table, columns.effectiveStatus, "TEXT DEFAULT 'not_ready'"),
    addColumn(table, columns.version, "INTEGER DEFAULT 1"),
    addColumn(table, columns.etag, "TEXT"),
    addColumn(table, columns.secretVersion, "INTEGER DEFAULT 0"),
    addColumn(table, columns.createdAt, "TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP"),
    addColumn(table, columns.updatedAt, "TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP"),
    addColumn(table, columns.enabledAt, "TIMESTAMPTZ"),
    addColumn(table, columns.disabledAt, "TIMESTAMPTZ"),
    addColumn(table, columns.archivedAt, "TIMESTAMPTZ"),
    addColumn(table, columns.purgedAt, "TIMESTAMPTZ"),
  ].filter((statement): statement is string => statement !== undefined).join(";\n");
}

function ensureAuditColumns(table: string, columns: Record<string, string>): string {
  return [
    addColumn(table, columns.id, "TEXT"),
    addColumn(table, columns.tenantId, "TEXT"),
    addColumn(table, columns.event, "TEXT"),
    addColumn(table, columns.action, "TEXT"),
    addColumn(table, columns.actorId, "TEXT"),
    addColumn(table, columns.targetId, "TEXT"),
    addColumn(table, columns.requestId, "TEXT"),
    addColumn(table, columns.outcome, "TEXT"),
    addColumn(table, columns.ipAddress, "TEXT"),
    addColumn(table, columns.userAgent, "TEXT"),
    addColumn(table, columns.detail, "TEXT DEFAULT '{}'"),
    addColumn(table, columns.version, "INTEGER DEFAULT 1"),
    addColumn(table, columns.occurredAt, "TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP"),
    addColumn(table, columns.createdAt, "TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP"),
  ].filter((statement): statement is string => statement !== undefined).join(";\n");
}

function addColumn(table: string, column: string | undefined, definition: string): string | undefined {
  if (!column) return undefined;
  return `ALTER TABLE ${quoteTable(table)} ADD COLUMN IF NOT EXISTS ${quoteColumn(column)} ${definition}`;
}

function createApplicationTable(table: string, columns: Record<string, string>): string {
  const definitions = [
    `${quoteColumn(columns.id)} TEXT NOT NULL`,
    `${quoteColumn(columns.tenantId)} TEXT NOT NULL`,
    `${quoteColumn(columns.applicationType)} TEXT NOT NULL DEFAULT 'web'`,
    `${quoteColumn(columns.name)} TEXT NOT NULL`,
    `${quoteColumn(columns.slug)} TEXT NOT NULL`,
    ...(columns.description ? [`${quoteColumn(columns.description)} TEXT`] : []),
    `${quoteColumn(columns.status)} TEXT NOT NULL DEFAULT 'active'`,
    ...(columns.lifecycleStatus ? [`${quoteColumn(columns.lifecycleStatus)} TEXT NOT NULL DEFAULT 'active'`] : []),
    ...(columns.readiness ? [`${quoteColumn(columns.readiness)} TEXT NOT NULL DEFAULT 'ready'`] : []),
    ...(columns.effectiveStatus ? [`${quoteColumn(columns.effectiveStatus)} TEXT NOT NULL DEFAULT 'active'`] : []),
    `${quoteColumn(columns.version)} INTEGER NOT NULL DEFAULT 1`,
    ...(columns.etag ? [`${quoteColumn(columns.etag)} TEXT`] : []),
    ...(columns.previousStatus ? [`${quoteColumn(columns.previousStatus)} TEXT`] : []),
    `${quoteColumn(columns.createdAt)} TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP`,
    `${quoteColumn(columns.updatedAt)} TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP`,
    ...(columns.enabledAt ? [`${quoteColumn(columns.enabledAt)} TIMESTAMPTZ`] : []),
    ...(columns.disabledAt ? [`${quoteColumn(columns.disabledAt)} TIMESTAMPTZ`] : []),
    ...(columns.archivedAt ? [`${quoteColumn(columns.archivedAt)} TIMESTAMPTZ`] : []),
    ...(columns.purgedAt ? [`${quoteColumn(columns.purgedAt)} TIMESTAMPTZ`] : []),
    `PRIMARY KEY (${quoteColumn(columns.tenantId)}, ${quoteColumn(columns.id)})`,
  ];
  return `CREATE TABLE IF NOT EXISTS ${quoteTable(table)} (${definitions.join(", ")})`;
}

function createPlatformTable(
  table: string,
  columns: Record<string, string>,
  applicationTable: string,
  applicationIdColumn: string,
  applicationTenantColumn: string,
): string {
  const definitions = [
    `${quoteColumn(columns.id)} TEXT NOT NULL`,
    `${quoteColumn(columns.tenantId)} TEXT NOT NULL`,
    `${quoteColumn(columns.applicationId)} TEXT NOT NULL`,
    `${quoteColumn(columns.type)} TEXT NOT NULL`,
    ...(columns.externalAppId ? [`${quoteColumn(columns.externalAppId)} TEXT`] : []),
    ...(columns.displayName ? [`${quoteColumn(columns.displayName)} TEXT`] : []),
    ...(columns.loginMode ? [`${quoteColumn(columns.loginMode)} TEXT`] : []),
    ...(columns.scope ? [`${quoteColumn(columns.scope)} TEXT`] : []),
    ...(columns.scopes ? [`${quoteColumn(columns.scopes)} TEXT NOT NULL DEFAULT '[]'`] : []),
    ...(columns.redirectUris ? [`${quoteColumn(columns.redirectUris)} TEXT NOT NULL DEFAULT '[]'`] : []),
    ...(columns.endpointUrl ? [`${quoteColumn(columns.endpointUrl)} TEXT`] : []),
    ...(columns.secretRef ? [`${quoteColumn(columns.secretRef)} TEXT`] : []),
    `${quoteColumn(columns.status)} TEXT NOT NULL DEFAULT 'active'`,
    ...(columns.lifecycleStatus ? [`${quoteColumn(columns.lifecycleStatus)} TEXT NOT NULL DEFAULT 'active'`] : []),
    ...(columns.readiness ? [`${quoteColumn(columns.readiness)} TEXT NOT NULL DEFAULT 'not_ready'`] : []),
    ...(columns.effectiveStatus ? [`${quoteColumn(columns.effectiveStatus)} TEXT NOT NULL DEFAULT 'not_ready'`] : []),
    `${quoteColumn(columns.version)} INTEGER NOT NULL DEFAULT 1`,
    ...(columns.etag ? [`${quoteColumn(columns.etag)} TEXT`] : []),
    ...(columns.secretVersion ? [`${quoteColumn(columns.secretVersion)} INTEGER NOT NULL DEFAULT 0`] : []),
    `${quoteColumn(columns.createdAt)} TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP`,
    `${quoteColumn(columns.updatedAt)} TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP`,
    ...(columns.enabledAt ? [`${quoteColumn(columns.enabledAt)} TIMESTAMPTZ`] : []),
    ...(columns.disabledAt ? [`${quoteColumn(columns.disabledAt)} TIMESTAMPTZ`] : []),
    ...(columns.archivedAt ? [`${quoteColumn(columns.archivedAt)} TIMESTAMPTZ`] : []),
    ...(columns.purgedAt ? [`${quoteColumn(columns.purgedAt)} TIMESTAMPTZ`] : []),
    `PRIMARY KEY (${quoteColumn(columns.tenantId)}, ${quoteColumn(columns.id)})`,
    `FOREIGN KEY (${quoteColumn(columns.tenantId)}, ${quoteColumn(columns.applicationId)}) REFERENCES ${quoteTable(applicationTable)} (${quoteColumn(applicationTenantColumn)}, ${quoteColumn(applicationIdColumn)}) ON DELETE CASCADE`,
  ];
  return `CREATE TABLE IF NOT EXISTS ${quoteTable(table)} (${definitions.join(", ")})`;
}

function createClientTable(
  table: string,
  columns: Record<string, string>,
  applicationTable: string,
  applicationIdColumn: string,
  applicationTenantColumn: string,
): string {
  const definitions = [
    `${quoteColumn(columns.id)} TEXT NOT NULL`,
    `${quoteColumn(columns.tenantId)} TEXT NOT NULL`,
    `${quoteColumn(columns.applicationId)} TEXT NOT NULL`,
    `${quoteColumn(columns.clientId)} TEXT NOT NULL`,
    ...(columns.clientIdScope ? [`${quoteColumn(columns.clientIdScope)} TEXT NOT NULL DEFAULT 'global'`] : []),
    `${quoteColumn(columns.status)} TEXT NOT NULL DEFAULT 'active'`,
    ...(columns.redirectUris ? [`${quoteColumn(columns.redirectUris)} TEXT NOT NULL DEFAULT '[]'`] : []),
    ...(columns.postLogoutRedirectUris ? [`${quoteColumn(columns.postLogoutRedirectUris)} TEXT NOT NULL DEFAULT '[]'`] : []),
    ...(columns.grantTypes ? [`${quoteColumn(columns.grantTypes)} TEXT NOT NULL DEFAULT '[]'`] : []),
    ...(columns.responseTypes ? [`${quoteColumn(columns.responseTypes)} TEXT NOT NULL DEFAULT '[]'`] : []),
    ...(columns.scopes ? [`${quoteColumn(columns.scopes)} TEXT NOT NULL DEFAULT '[]'`] : []),
    ...(columns.tokenEndpointAuthMethod ? [`${quoteColumn(columns.tokenEndpointAuthMethod)} TEXT NOT NULL DEFAULT 'client_secret_basic'`] : []),
    ...(columns.tokenEndpointAuthSigningAlg ? [`${quoteColumn(columns.tokenEndpointAuthSigningAlg)} TEXT`] : []),
    ...(columns.jwksUri ? [`${quoteColumn(columns.jwksUri)} TEXT`] : []),
    ...(columns.privateKeyRef ? [`${quoteColumn(columns.privateKeyRef)} TEXT`] : []),
    ...(columns.keyId ? [`${quoteColumn(columns.keyId)} TEXT`] : []),
    ...(columns.requirePkce ? [`${quoteColumn(columns.requirePkce)} BOOLEAN NOT NULL DEFAULT TRUE`] : []),
    ...(columns.secretRef ? [`${quoteColumn(columns.secretRef)} TEXT`] : []),
    ...(columns.lifecycleStatus ? [`${quoteColumn(columns.lifecycleStatus)} TEXT NOT NULL DEFAULT 'active'`] : []),
    ...(columns.readiness ? [`${quoteColumn(columns.readiness)} TEXT NOT NULL DEFAULT 'not_ready'`] : []),
    ...(columns.effectiveStatus ? [`${quoteColumn(columns.effectiveStatus)} TEXT NOT NULL DEFAULT 'not_ready'`] : []),
    `${quoteColumn(columns.version)} INTEGER NOT NULL DEFAULT 1`,
    ...(columns.etag ? [`${quoteColumn(columns.etag)} TEXT`] : []),
    ...(columns.secretVersion ? [`${quoteColumn(columns.secretVersion)} INTEGER NOT NULL DEFAULT 0`] : []),
    `${quoteColumn(columns.createdAt)} TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP`,
    `${quoteColumn(columns.updatedAt)} TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP`,
    ...(columns.enabledAt ? [`${quoteColumn(columns.enabledAt)} TIMESTAMPTZ`] : []),
    ...(columns.disabledAt ? [`${quoteColumn(columns.disabledAt)} TIMESTAMPTZ`] : []),
    ...(columns.archivedAt ? [`${quoteColumn(columns.archivedAt)} TIMESTAMPTZ`] : []),
    ...(columns.purgedAt ? [`${quoteColumn(columns.purgedAt)} TIMESTAMPTZ`] : []),
    `PRIMARY KEY (${quoteColumn(columns.tenantId)}, ${quoteColumn(columns.id)})`,
    `FOREIGN KEY (${quoteColumn(columns.tenantId)}, ${quoteColumn(columns.applicationId)}) REFERENCES ${quoteTable(applicationTable)} (${quoteColumn(applicationTenantColumn)}, ${quoteColumn(applicationIdColumn)}) ON DELETE CASCADE`,
  ];
  return `CREATE TABLE IF NOT EXISTS ${quoteTable(table)} (${definitions.join(", ")})`;
}

function createAuditTable(table: string, columns: Record<string, string>): string {
  const definitions = [
    `${quoteColumn(columns.id)} TEXT NOT NULL`,
    `${quoteColumn(columns.tenantId)} TEXT NOT NULL`,
    `${quoteColumn(columns.event)} TEXT NOT NULL`,
    ...(columns.action ? [`${quoteColumn(columns.action)} TEXT`] : []),
    ...(columns.actorId ? [`${quoteColumn(columns.actorId)} TEXT`] : []),
    ...(columns.targetId ? [`${quoteColumn(columns.targetId)} TEXT`] : []),
    ...(columns.requestId ? [`${quoteColumn(columns.requestId)} TEXT`] : []),
    ...(columns.outcome ? [`${quoteColumn(columns.outcome)} TEXT`] : []),
    ...(columns.ipAddress ? [`${quoteColumn(columns.ipAddress)} TEXT`] : []),
    ...(columns.userAgent ? [`${quoteColumn(columns.userAgent)} TEXT`] : []),
    ...(columns.detail ? [`${quoteColumn(columns.detail)} TEXT NOT NULL DEFAULT '{}'`] : []),
    ...(columns.version ? [`${quoteColumn(columns.version)} INTEGER NOT NULL DEFAULT 1`] : []),
    `${quoteColumn(columns.occurredAt)} TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP`,
    `${quoteColumn(columns.createdAt)} TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP`,
    `PRIMARY KEY (${quoteColumn(columns.tenantId)}, ${quoteColumn(columns.id)})`,
  ];
  return `CREATE TABLE IF NOT EXISTS ${quoteTable(table)} (${definitions.join(", ")})`;
}

export function createPlatformLoginStateTableMigrationSql(
  table = DEFAULT_PLATFORM_LOGIN_STATE_TABLE,
  columns: Partial<Record<string, string>> = {},
  tenantColumn = "tenant_id",
): string {
  const normalized: Record<string, string> = {};
  const source = { ...DEFAULT_PLATFORM_LOGIN_STATE_COLUMNS, ...columns, tenantId: columns.tenantId ?? tenantColumn };
  for (const [key, value] of Object.entries(source)) normalized[key] = validateMigrationColumn(value, key);
  return createPlatformLoginStateTable(
    table,
    normalized,
    "gb_idaas_application",
    { tenantId: "tenant_id", id: "id" },
     "gb_idaas_application_platform",
      { tenantId: "tenant_id", applicationId: "application_id", id: "id" },
     true,
   );
}

export const createPlatformLoginStateTableSql = createPlatformLoginStateTableMigrationSql;

function createPlatformLoginStateTable(
  table: string,
  columns: Record<string, string>,
  applicationTable: string,
  applicationColumns: Record<string, string>,
  platformTable: string,
  platformColumns: Record<string, string>,
  includeReturnTo = false,
): string {
  const definitions = [
    `${quoteColumn(columns.tenantId)} TEXT NOT NULL`,
    `${quoteColumn(columns.stateHash)} TEXT NOT NULL`,
    `${quoteColumn(columns.bindingHash)} TEXT NOT NULL`,
    `${quoteColumn(columns.browserBindingHash)} TEXT`,
    `${quoteColumn(columns.sessionBindingHash)} TEXT`,
    `${quoteColumn(columns.applicationId)} TEXT NOT NULL`,
    `${quoteColumn(columns.platformId)} TEXT NOT NULL`,
    `${quoteColumn(columns.flow)} TEXT NOT NULL CHECK (${quoteColumn(columns.flow)} <> '')`,
    `${quoteColumn(columns.status)} TEXT NOT NULL DEFAULT 'issued' CHECK (${quoteColumn(columns.status)} IN ('issued', 'claimed', 'leased', 'consumed', 'expired', 'revoked'))`,
    `${quoteColumn(columns.leaseOwner)} TEXT`,
    `${quoteColumn(columns.leaseExpiresAt)} TIMESTAMPTZ`,
    `${quoteColumn(columns.expiresAt)} TIMESTAMPTZ NOT NULL`,
    `${quoteColumn(columns.redirectUri)} TEXT NOT NULL`,
    ...(includeReturnTo ? [`${quoteColumn(columns.returnTo)} TEXT`] : []),
    `${quoteColumn(columns.scope)} TEXT`,
    `${quoteColumn(columns.linkingPolicy)} JSONB NOT NULL DEFAULT '{}'::jsonb`,
    `${quoteColumn(columns.requestedUserId)} TEXT`,
    `${quoteColumn(columns.createdAt)} TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP`,
    `${quoteColumn(columns.updatedAt)} TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP`,
    `${quoteColumn(columns.consumedAt)} TIMESTAMPTZ`,
     `PRIMARY KEY (${quoteColumn(columns.tenantId)}, ${quoteColumn(columns.applicationId)}, ${quoteColumn(columns.stateHash)})`,
    `CHECK (${quoteColumn(columns.expiresAt)} > ${quoteColumn(columns.createdAt)})`,
    `FOREIGN KEY (${quoteColumn(columns.tenantId)}, ${quoteColumn(columns.applicationId)}) REFERENCES ${quoteTable(applicationTable)} (${quoteColumn(applicationColumns.tenantId)}, ${quoteColumn(applicationColumns.id)}) ON DELETE CASCADE`,
    `FOREIGN KEY (${quoteColumn(columns.tenantId)}, ${quoteColumn(columns.applicationId)}, ${quoteColumn(columns.platformId)}) REFERENCES ${quoteTable(platformTable)} (${quoteColumn(platformColumns.tenantId)}, ${quoteColumn(platformColumns.applicationId)}, ${quoteColumn(platformColumns.id)}) ON DELETE CASCADE`,
  ];
  return `CREATE TABLE IF NOT EXISTS ${quoteTable(table)} (${definitions.join(", ")})`;
}

function ensurePlatformLoginStateColumns(
  table: string,
  columns: Record<string, string>,
  includeReturnTo = false,
): string {
  return [
    addColumn(table, columns.tenantId, "TEXT"),
    addColumn(table, columns.stateHash, "TEXT"),
    addColumn(table, columns.bindingHash, "TEXT"),
    addColumn(table, columns.browserBindingHash, "TEXT"),
    addColumn(table, columns.sessionBindingHash, "TEXT"),
    addColumn(table, columns.applicationId, "TEXT"),
    addColumn(table, columns.platformId, "TEXT"),
    addColumn(table, columns.flow, "TEXT"),
    addColumn(table, columns.status, "TEXT DEFAULT 'issued'"),
    addColumn(table, columns.leaseOwner, "TEXT"),
    addColumn(table, columns.leaseExpiresAt, "TIMESTAMPTZ"),
    addColumn(table, columns.expiresAt, "TIMESTAMPTZ"),
    addColumn(table, columns.redirectUri, "TEXT"),
    ...(includeReturnTo ? [addColumn(table, columns.returnTo, "TEXT")] : []),
    addColumn(table, columns.scope, "TEXT"),
    addColumn(table, columns.linkingPolicy, "JSONB DEFAULT '{}'::jsonb"),
    addColumn(table, columns.requestedUserId, "TEXT"),
    addColumn(table, columns.createdAt, "TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP"),
    addColumn(table, columns.updatedAt, "TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP"),
    addColumn(table, columns.consumedAt, "TIMESTAMPTZ"),
  ].filter((statement): statement is string => statement !== undefined).join(";\n");
}

function addPlatformLoginStateForeignKeys(
  table: string,
  columns: Record<string, string>,
  applicationTable: string,
  applicationColumns: Record<string, string>,
  platformTable: string,
  platformColumns: Record<string, string>,
): string {
  const constraints = [
    {
      name: createTenantSqlObjectName(table, "application_fk"),
      columns: [columns.tenantId, columns.applicationId],
      targetTable: applicationTable,
      targetColumns: [applicationColumns.tenantId, applicationColumns.id],
    },
    {
      name: createTenantSqlObjectName(table, "platform_fk"),
       columns: [columns.tenantId, columns.applicationId, columns.platformId],
       targetTable: platformTable,
       targetColumns: [platformColumns.tenantId, platformColumns.applicationId, platformColumns.id],
    },
  ];
  return constraints.flatMap((constraint) => [
    `DO $$ BEGIN ALTER TABLE ${quoteTable(table)} ADD CONSTRAINT ${quoteIndex(constraint.name)} FOREIGN KEY (${constraint.columns.map(quoteColumn).join(", ")}) REFERENCES ${quoteTable(constraint.targetTable)} (${constraint.targetColumns.map(quoteColumn).join(", ")}) ON DELETE CASCADE NOT VALID; EXCEPTION WHEN duplicate_object THEN NULL; END $$`,
    `ALTER TABLE ${quoteTable(table)} VALIDATE CONSTRAINT ${quoteIndex(constraint.name)}`,
  ]).join(";\n");
}

function addExternalIdentityForeignKeys(
  table: string,
  identityColumns: ApplicationIdentitySqlColumns,
  applicationTable: string,
  applicationColumns: Record<string, string>,
  platformTable: string,
  platformColumns: Record<string, string>,
): string {
  const constraints = [
    {
      name: createTenantSqlObjectName(table, "application_fk"),
      columns: [identityColumns.tenantId, identityColumns.applicationId],
      targetTable: applicationTable,
      targetColumns: [applicationColumns.tenantId, applicationColumns.id],
    },
    {
      name: createTenantSqlObjectName(table, "platform_fk"),
       columns: [identityColumns.tenantId, identityColumns.applicationId, identityColumns.platformId],
       targetTable: platformTable,
       targetColumns: [platformColumns.tenantId, platformColumns.applicationId, platformColumns.id],
    },
  ];
  return constraints.flatMap((constraint) => [
    `DO $$ BEGIN ALTER TABLE ${quoteTable(table)} ADD CONSTRAINT ${quoteIndex(constraint.name)} FOREIGN KEY (${constraint.columns.map(quoteColumn).join(", ")}) REFERENCES ${quoteTable(constraint.targetTable)} (${constraint.targetColumns.map(quoteColumn).join(", ")}) ON DELETE CASCADE NOT VALID; EXCEPTION WHEN duplicate_object THEN NULL; END $$`,
    `ALTER TABLE ${quoteTable(table)} VALIDATE CONSTRAINT ${quoteIndex(constraint.name)}`,
  ]).join(";\n");
}

function unqualifiedName(value: string): string {
  return value.split(".").at(-1) ?? value;
}

function rlsStatements(table: string, tenantColumn: string, policy: string): string[] {
  return [
    `ALTER TABLE ${quoteTable(table)} ENABLE ROW LEVEL SECURITY`,
    `ALTER TABLE ${quoteTable(table)} FORCE ROW LEVEL SECURITY`,
    `DROP POLICY IF EXISTS ${quoteIndex(policy)} ON ${quoteTable(table)}`,
    `CREATE POLICY ${quoteIndex(policy)} ON ${quoteTable(table)} USING (${quoteColumn(tenantColumn)} = current_setting('app.tenant_id', true)) WITH CHECK (${quoteColumn(tenantColumn)} = current_setting('app.tenant_id', true))`,
  ];
}

function uniqueIndex(name: string, table: string, columns: string[]): string {
  return `CREATE UNIQUE INDEX IF NOT EXISTS ${quoteIndex(name)} ON ${quoteTable(table)} (${columns.map(quoteColumn).join(", ")})`;
}

function uniqueLowerIndex(name: string, table: string, columns: string[]): string {
  const expressions = columns.map((column, index) => index === columns.length - 1 ? `LOWER(${quoteColumn(column)})` : quoteColumn(column));
  return `CREATE UNIQUE INDEX IF NOT EXISTS ${quoteIndex(name)} ON ${quoteTable(table)} (${expressions.join(", ")})`;
}

function queryIndex(name: string, table: string, columns: string[]): string {
  return `CREATE INDEX IF NOT EXISTS ${quoteIndex(name)} ON ${quoteTable(table)} (${columns.map(quoteColumn).join(", ")})`;
}

function quoteTable(value: string): string {
  return quoteApplicationSqlIdentifier(value, "table");
}

function quoteColumn(value: string): string {
  return quoteApplicationSqlIdentifier(value, "column");
}

function quoteIndex(value: string): string {
  return quoteApplicationSqlIdentifier(value, "index");
}

export function createApplicationManagementAdditiveMigrationSql(
  options: ApplicationManagementMigrationOptions = {},
): string {
  const tenant = migrationTenant(options);
  const tables = additiveMigrationTables(options);
  const columns = additiveMigrationColumns(options);
  const includeSessions = options.includeOpaqueClientSessions ?? options.includeClientSessions ?? true;
  const includeWebviewTickets = options.includeWebviewTickets ?? true;
  const statements: string[] = [];
  if (options.includeClientExtensions !== false) {
    statements.push(createClientExtensionSql(tables.clients, columns.clients));
    statements.push(createPlatformComponentBindingSql(tables.platforms, columns.platforms));
  }
  if (includeSessions) {
    statements.push(createClientSessionTable(tables.clientSessions, columns.clientSessions, tables.applications, migrationColumns(options).applications));
    statements.push(uniqueIndex(createTenantSqlObjectName(tables.clientSessions, "session_hash_uq"), tables.clientSessions, [columns.clientSessions.tenantId, columns.clientSessions.sessionHash]));
    statements.push(queryIndex(createTenantSqlObjectName(tables.clientSessions, "expiry_idx"), tables.clientSessions, [columns.clientSessions.tenantId, columns.clientSessions.status, columns.clientSessions.expiresAt]));
  }
  if (includeWebviewTickets) {
    statements.push(createWebviewTicketTable(tables.webviewTickets, columns.webviewTickets, tables.applications, migrationColumns(options).applications));
    statements.push(uniqueIndex(createTenantSqlObjectName(tables.webviewTickets, "ticket_hash_uq"), tables.webviewTickets, [columns.webviewTickets.tenantId, columns.webviewTickets.ticketHash]));
    statements.push(queryIndex(createTenantSqlObjectName(tables.webviewTickets, "expiry_idx"), tables.webviewTickets, [columns.webviewTickets.tenantId, columns.webviewTickets.status, columns.webviewTickets.expiresAt]));
  }
  if (options.includeClientExtensions !== false) {
    statements.push(queryIndex(createTenantSqlObjectName(tables.clients, "client_kind_idx"), tables.clients, [columns.clients.tenantId, columns.clients.clientKind]));
  }
  if (options.includeComponentPlatformBindings !== false && options.includeClientExtensions !== false) {
    statements.push(uniqueIndex(createTenantSqlObjectName(tables.platforms, "component_authorizer_uq"), tables.platforms, [columns.platforms.tenantId, columns.platforms.componentAppId, columns.platforms.authorizedAppId]));
    statements.push(queryIndex(createTenantSqlObjectName(tables.platforms, "component_idx"), tables.platforms, [columns.platforms.tenantId, columns.platforms.componentAppId, columns.platforms.authorizedAppId]));
  }
  if (tenant.requireRls || options.includeRls === true) {
    if (includeSessions) {
      statements.push(...rlsStatements(tables.clientSessions, columns.clientSessions.tenantId, createTenantSqlObjectName(tables.clientSessions, "tenant")));
    }
    if (includeWebviewTickets) {
      statements.push(...rlsStatements(tables.webviewTickets, columns.webviewTickets.tenantId, createTenantSqlObjectName(tables.webviewTickets, "tenant")));
    }
  }
  if (options.includeMigrationMetadata === true) {
    const migrationSchema = tenant.schema;
    statements.push(createMigrationMetadataSql({
      tableName: qualifyTenantTable(options.migrationTable ?? options.migrationHistoryTable ?? DEFAULT_APPLICATION_MIGRATION_TABLE, migrationSchema),
      lockTableName: qualifyTenantTable(options.migrationLockTable ?? DEFAULT_APPLICATION_MIGRATION_LOCK_TABLE, migrationSchema),
    }));
  }
  return `${statements.join(";\n")};\n`;
}

export const createApplicationManagementAdditiveSql = createApplicationManagementAdditiveMigrationSql;
export const createApplicationManagementClientPlatformMigrationSql = createApplicationManagementAdditiveMigrationSql;
export const buildApplicationManagementAdditiveMigrationSql = createApplicationManagementAdditiveMigrationSql;

export function createClientAuthBffStateMigrationSql(
  options: ApplicationManagementMigrationOptions = {},
): string {
  const tenant = migrationTenant(options);
  const tables = clientAuthBffStateMigrationTables(options);
  const columns = clientAuthBffStateMigrationColumns(options);
  const statements: string[] = [
    createClientAuthBffStateTable(tables.clientAuthBffStates, columns),
    queryIndex(createTenantSqlObjectName(tables.clientAuthBffStates, "expiry_idx"), tables.clientAuthBffStates, [columns.tenantId, columns.expiresAt]),
  ];
  if (tenant.requireRls || options.includeRls === true) {
    statements.push(...rlsStatements(tables.clientAuthBffStates, columns.tenantId, createTenantSqlObjectName(tables.clientAuthBffStates, "tenant")));
  }
  if (options.includeMigrationMetadata === true) {
    statements.push(createMigrationMetadataSql({
      tableName: qualifyTenantTable(options.migrationTable ?? options.migrationHistoryTable ?? DEFAULT_APPLICATION_MIGRATION_TABLE, tenant.schema),
      lockTableName: qualifyTenantTable(options.migrationLockTable ?? DEFAULT_APPLICATION_MIGRATION_LOCK_TABLE, tenant.schema),
    }));
  }
  return `${statements.join(";\n")};\n`;
}

export const createApplicationManagementClientAuthBffMigrationSql = createClientAuthBffStateMigrationSql;
export const createApplicationManagementClientAuthBffStateMigrationSql = createClientAuthBffStateMigrationSql;
export const createApplicationManagementClientAuthBffStateTableMigrationSql = createClientAuthBffStateMigrationSql;
export const createApplicationManagementBffStateMigrationSql = createClientAuthBffStateMigrationSql;
export const createApplicationManagementV5MigrationSql = createClientAuthBffStateMigrationSql;
export const createClientAuthBffMigrationSql = createClientAuthBffStateMigrationSql;

export function createApplicationManagementReturnToMigrationSql(
  options: ApplicationManagementMigrationOptions = {},
): string {
  const tables = migrationTables(options);
  const columns = migrationColumns(options);
  const column = columns.platformLoginStates.returnTo;
  if (typeof column !== "string") throw new TypeError("Platform login returnTo migration requires a SQL column");
  return `${addColumn(tables.platformLoginStates, column, "TEXT")};\n`;
}

export const createApplicationManagementPlatformLoginReturnToMigrationSql = createApplicationManagementReturnToMigrationSql;
export const createApplicationManagementPlatformLoginStateReturnToMigrationSql = createApplicationManagementReturnToMigrationSql;
export const createApplicationManagementV4MigrationSql = createApplicationManagementReturnToMigrationSql;

export function createCompleteApplicationManagementMigrationSql(
  options: ApplicationManagementMigrationOptions = {},
): string {
  const includeReturnTo = options.includeReturnToMigration !== false && options.includePlatformLoginReturnToMigration !== false;
  const returnToSql = includeReturnTo
    ? createApplicationManagementReturnToMigrationSql({ ...options, includeMigrationMetadata: false })
    : "";
  const clientAuthBffSql = includeReturnTo && options.includeClientAuthBffState !== false && options.includeClientAuthBffStateMigration !== false && options.includeBffState !== false
    ? createClientAuthBffStateMigrationSql({ ...options, includeMigrationMetadata: false })
    : "";
  const foundationSql = createApplicationManagementMigrationSql(includeReturnTo ? { ...options, includeReturnToMigration: true } : options);
  return `${foundationSql}${createApplicationManagementAdditiveMigrationSql({ ...options, includeMigrationMetadata: false })}${returnToSql}${clientAuthBffSql}`;
}

export const createApplicationManagementCompleteMigrationSql = createCompleteApplicationManagementMigrationSql;
export const createApplicationManagementFreshMigrationSql = createCompleteApplicationManagementMigrationSql;
export const createApplicationManagementFreshSchemaSql = createCompleteApplicationManagementMigrationSql;
export const APPLICATION_MANAGEMENT_COMPLETE_MIGRATION_SQL = createCompleteApplicationManagementMigrationSql();

export function getApplicationManagementAdditiveMigrationDefinition(
  options: ApplicationManagementMigrationOptions = {},
): MigrationDefinition {
  const version = options.additiveMigrationVersion ?? APPLICATION_MANAGEMENT_ADDITIVE_MIGRATION_VERSION;
  if (!Number.isSafeInteger(version) || version <= APPLICATION_MANAGEMENT_MIGRATION_VERSION) {
    throw new TypeError("Additive application migration version must be greater than the foundation version");
  }
  const definition = createMigrationDefinition(
    version,
    options.additiveMigrationName ?? APPLICATION_MANAGEMENT_ADDITIVE_MIGRATION_NAME,
    createApplicationManagementAdditiveMigrationSql(options),
    {
      component: "application-management",
      additive: true,
      baseVersion: APPLICATION_MANAGEMENT_MIGRATION_VERSION,
      baseChecksum: getApplicationManagementMigrationChecksum(options),
      tenantMode: migrationTenant(options).mode,
      tenantId: migrationTenant(options).tenantId,
      checksumAlgorithm: "sha256",
    },
    applicationMigrationScope(options),
    { additive: true, requires: [APPLICATION_MANAGEMENT_MIGRATION_VERSION] },
  );
  return definition;
}

export const getApplicationManagementClientPlatformMigrationDefinition = getApplicationManagementAdditiveMigrationDefinition;
export const createApplicationManagementAdditiveMigrationDefinition = getApplicationManagementAdditiveMigrationDefinition;

export function getApplicationManagementReturnToMigrationDefinition(
  options: ApplicationManagementMigrationOptions = {},
): MigrationDefinition {
  const version = options.returnToMigrationVersion ?? APPLICATION_MANAGEMENT_PLATFORM_LOGIN_RETURN_TO_MIGRATION_VERSION;
  if (!Number.isSafeInteger(version) || version <= APPLICATION_MANAGEMENT_ADDITIVE_MIGRATION_VERSION) {
    throw new TypeError("Platform login returnTo migration version must be greater than the additive migration version");
  }
  return createMigrationDefinition(
    version,
    options.returnToMigrationName ?? APPLICATION_MANAGEMENT_PLATFORM_LOGIN_RETURN_TO_MIGRATION_NAME,
    createApplicationManagementReturnToMigrationSql(options),
    {
      component: "application-management",
      additive: true,
      baseVersion: APPLICATION_MANAGEMENT_ADDITIVE_MIGRATION_VERSION,
      baseChecksum: createApplicationManagementAdditiveMigrationChecksum(options),
      tenantMode: migrationTenant(options).mode,
      tenantId: migrationTenant(options).tenantId,
      checksumAlgorithm: "sha256",
    },
    applicationMigrationScope(options),
    { additive: true, requires: [APPLICATION_MANAGEMENT_ADDITIVE_MIGRATION_VERSION] },
  );
}

export const getApplicationManagementPlatformLoginReturnToMigrationDefinition = getApplicationManagementReturnToMigrationDefinition;
export const getApplicationManagementPlatformLoginStateReturnToMigrationDefinition = getApplicationManagementReturnToMigrationDefinition;
export const createApplicationManagementReturnToMigrationDefinition = getApplicationManagementReturnToMigrationDefinition;
export const getApplicationManagementV4MigrationDefinition = getApplicationManagementReturnToMigrationDefinition;

export function getApplicationManagementClientAuthBffMigrationDefinition(
  options: ApplicationManagementMigrationOptions = {},
): MigrationDefinition {
  const returnToVersion = options.returnToMigrationVersion ?? APPLICATION_MANAGEMENT_PLATFORM_LOGIN_RETURN_TO_MIGRATION_VERSION;
  const version = options.clientAuthBffMigrationVersion ?? options.clientAuthBffStateMigrationVersion ?? options.bffMigrationVersion ?? options.bffStateMigrationVersion ?? APPLICATION_MANAGEMENT_CLIENT_AUTH_BFF_MIGRATION_VERSION;
  if (!Number.isSafeInteger(version) || version <= returnToVersion) {
    throw new TypeError("Client auth BFF state migration version must be greater than the returnTo migration version");
  }
  return createMigrationDefinition(
    version,
    options.clientAuthBffMigrationName ?? options.clientAuthBffStateMigrationName ?? options.bffMigrationName ?? options.bffStateMigrationName ?? APPLICATION_MANAGEMENT_CLIENT_AUTH_BFF_MIGRATION_NAME,
    createClientAuthBffStateMigrationSql(options),
    {
      component: "application-management",
      additive: true,
      baseVersion: returnToVersion,
      baseChecksum: getApplicationManagementReturnToMigrationChecksum(options),
      tenantMode: migrationTenant(options).mode,
      tenantId: migrationTenant(options).tenantId,
      checksumAlgorithm: "sha256",
    },
    applicationMigrationScope(options),
    { additive: true, requires: [returnToVersion] },
  );
}

export const getApplicationManagementBffStateMigrationDefinition = getApplicationManagementClientAuthBffMigrationDefinition;
export const getApplicationManagementClientAuthBffStateMigrationDefinition = getApplicationManagementClientAuthBffMigrationDefinition;
export const createApplicationManagementClientAuthBffMigrationDefinition = getApplicationManagementClientAuthBffMigrationDefinition;
export const createApplicationManagementClientAuthBffStateMigrationDefinition = getApplicationManagementClientAuthBffMigrationDefinition;
export const createApplicationManagementBffStateMigrationDefinition = getApplicationManagementClientAuthBffMigrationDefinition;
export const getApplicationManagementV5MigrationDefinition = getApplicationManagementClientAuthBffMigrationDefinition;

export const getApplicationManagementMigrationDefinitions = getApplicationManagementMigrations;
export const getApplicationManagementMigrationSeries = getApplicationManagementMigrations;

export function getApplicationManagementAdditiveMigrationChecksum(
  options: ApplicationManagementMigrationOptions = {},
): string {
  return migrationChecksum(createApplicationManagementAdditiveMigrationSql(options));
}

export const getApplicationManagementClientPlatformMigrationChecksum = getApplicationManagementAdditiveMigrationChecksum;
export const createApplicationManagementAdditiveMigrationChecksum = getApplicationManagementAdditiveMigrationChecksum;
export const createApplicationManagementClientPlatformMigrationChecksum = getApplicationManagementAdditiveMigrationChecksum;

export function getApplicationManagementReturnToMigrationChecksum(
  options: ApplicationManagementMigrationOptions = {},
): string {
  return migrationChecksum(createApplicationManagementReturnToMigrationSql(options));
}

export const getApplicationManagementPlatformLoginReturnToMigrationChecksum = getApplicationManagementReturnToMigrationChecksum;
export const getApplicationManagementPlatformLoginStateReturnToMigrationChecksum = getApplicationManagementReturnToMigrationChecksum;
export const createApplicationManagementReturnToMigrationChecksum = getApplicationManagementReturnToMigrationChecksum;
export const createApplicationManagementV4MigrationChecksum = getApplicationManagementReturnToMigrationChecksum;

export function getApplicationManagementClientAuthBffMigrationChecksum(
  options: ApplicationManagementMigrationOptions = {},
): string {
  return migrationChecksum(createClientAuthBffStateMigrationSql(options));
}

export const getApplicationManagementBffStateMigrationChecksum = getApplicationManagementClientAuthBffMigrationChecksum;
export const getApplicationManagementClientAuthBffStateMigrationChecksum = getApplicationManagementClientAuthBffMigrationChecksum;
export const createApplicationManagementClientAuthBffMigrationChecksum = getApplicationManagementClientAuthBffMigrationChecksum;
export const createApplicationManagementClientAuthBffStateMigrationChecksum = getApplicationManagementClientAuthBffMigrationChecksum;
export const createApplicationManagementBffStateMigrationChecksum = getApplicationManagementClientAuthBffMigrationChecksum;
export const createApplicationManagementV5MigrationChecksum = getApplicationManagementClientAuthBffMigrationChecksum;

export function createApplicationManagementAdditiveMigrationPlan(
  options: ApplicationManagementMigrationOptions = {},
): { version: number; name: string; checksum: string; sql: string } {
  const definition = getApplicationManagementAdditiveMigrationDefinition(options);
  return {
    version: definition.version,
    name: definition.name,
    checksum: migrationChecksum(definition.sql),
    sql: definition.sql,
  };
}

export const planApplicationManagementAdditiveMigration = createApplicationManagementAdditiveMigrationPlan;
export const createApplicationManagementClientPlatformMigrationPlan = createApplicationManagementAdditiveMigrationPlan;

export function createApplicationManagementReturnToMigrationPlan(
  options: ApplicationManagementMigrationOptions = {},
): { version: number; name: string; checksum: string; sql: string } {
  const definition = getApplicationManagementReturnToMigrationDefinition(options);
  return {
    version: definition.version,
    name: definition.name,
    checksum: migrationChecksum(definition.sql),
    sql: definition.sql,
  };
}

export const planApplicationManagementReturnToMigration = createApplicationManagementReturnToMigrationPlan;
export const createApplicationManagementPlatformLoginReturnToMigrationPlan = createApplicationManagementReturnToMigrationPlan;
export const createApplicationManagementV4MigrationPlan = createApplicationManagementReturnToMigrationPlan;

export function createApplicationManagementClientAuthBffMigrationPlan(
  options: ApplicationManagementMigrationOptions = {},
): { version: number; name: string; checksum: string; sql: string } {
  const definition = getApplicationManagementClientAuthBffMigrationDefinition(options);
  return {
    version: definition.version,
    name: definition.name,
    checksum: migrationChecksum(definition.sql),
    sql: definition.sql,
  };
}

export const createApplicationManagementBffStateMigrationPlan = createApplicationManagementClientAuthBffMigrationPlan;
export const createApplicationManagementClientAuthBffStateMigrationPlan = createApplicationManagementClientAuthBffMigrationPlan;
export const createApplicationManagementV5MigrationPlan = createApplicationManagementClientAuthBffMigrationPlan;

export function createApplicationManagementMigrationSeriesPlan(
  options: ApplicationManagementMigrationOptions = {},
): Array<{ version: number; name: string; checksum: string; sql: string }> {
  return getApplicationManagementMigrations(options).map((definition) => ({
    version: definition.version,
    name: definition.name,
    checksum: migrationChecksum(definition.sql),
    sql: definition.sql,
  }));
}

export const planApplicationManagementMigrations = createApplicationManagementMigrationSeriesPlan;

export function dryRunApplicationManagementMigrations(
  executorOrOptions: MigrationSqlExecutor | ApplicationManagementMigrationOptions = {},
  secondOptions: ApplicationManagementMigrationOptions = {},
): MigrationDryRunResult {
  const hasExecutor = isMigrationExecutor(executorOrOptions);
  const options = hasExecutor ? secondOptions : executorOrOptions;
  const definitions = getApplicationManagementMigrations(options);
  const coordinator = new MigrationCoordinator(
    hasExecutor ? executorOrOptions : { query: async () => ({ rows: [] }) },
    definitions,
    applicationMigrationCoordinatorOptions(options, false),
  );
  return coordinator.dryRun(definitions);
}

export async function applyVersionedApplicationManagementMigrations(
  executor: { query(text: string, values?: unknown[]): unknown | Promise<unknown>; transaction?: MigrationSqlExecutor["transaction"] },
  options: ApplicationManagementMigrationOptions = {},
): Promise<MigrationRunResult> {
  const definitions = getApplicationManagementMigrations(options);
  const migrationExecutor: MigrationSqlExecutor = {
    query: (text, values) => executor.query(text, values ?? []),
    ...(typeof executor.transaction === "function"
      ? { transaction: executor.transaction.bind(executor) as unknown as MigrationSqlExecutor["transaction"] }
      : {}),
  };
  const coordinator = new MigrationCoordinator(
    migrationExecutor,
    definitions,
    applicationMigrationCoordinatorOptions(options, options.requireTransaction ?? options.allowNonTransactional !== true),
  );
  return coordinator.run(definitions);
}

export async function applyApplicationManagementMigrations(
  executor: { query(text: string, values?: unknown[]): unknown | Promise<unknown>; transaction?: MigrationSqlExecutor["transaction"] },
  options: ApplicationManagementMigrationOptions = {},
): Promise<void> {
  await applyVersionedApplicationManagementMigrations(executor, options);
}

export const runApplicationManagementMigrations = applyVersionedApplicationManagementMigrations;
export const applyVersionedApplicationManagementMigrationSeries = applyVersionedApplicationManagementMigrations;

function applicationMigrationCoordinatorOptions(
  options: ApplicationManagementMigrationOptions,
  requireTransaction: boolean,
): {
  tableName: string;
  lockTableName: string;
  lockKey?: string | number;
  lockNamespace: string;
  scope: string;
  ownerId?: string;
  requireTransaction: boolean;
} {
  const tenant = migrationTenant(options);
  return {
    tableName: qualifyTenantTable(options.migrationTable ?? options.migrationHistoryTable ?? DEFAULT_APPLICATION_MIGRATION_TABLE, tenant.schema),
    lockTableName: qualifyTenantTable(options.migrationLockTable ?? DEFAULT_APPLICATION_MIGRATION_LOCK_TABLE, tenant.schema),
    ...(options.migrationLockKey === undefined ? {} : { lockKey: options.migrationLockKey }),
    lockNamespace: applicationMigrationLockNamespace(options),
    scope: applicationMigrationScope(options),
    ...(options.migrationOwnerId === undefined ? {} : { ownerId: options.migrationOwnerId }),
    requireTransaction,
  };
}

function additiveMigrationTables(options: ApplicationManagementMigrationOptions): AdditiveMigrationTables {
  const base = migrationTables(options);
  const tables = options.tables as (Partial<ApplicationSqlTableNames> & {
    clientSession?: string;
    clientSessions?: string;
    opaqueClientSession?: string;
    opaqueClientSessions?: string;
    webviewTicket?: string;
    webviewTickets?: string;
    clientTicket?: string;
    clientTickets?: string;
  }) | undefined;
  const tableNames = options.tableNames as typeof tables;
  const schema = migrationTenant(options).schema;
  const clientSessions = options.clientSessionTable ?? options.clientSessionsTable ?? options.clientSession ?? options.clientSessions ?? options.opaqueClientSessionTable ?? options.opaqueClientSessionsTable ?? tables?.clientSession ?? tables?.clientSessions ?? tables?.opaqueClientSession ?? tables?.opaqueClientSessions ?? tableNames?.clientSession ?? tableNames?.clientSessions ?? tableNames?.opaqueClientSession ?? tableNames?.opaqueClientSessions ?? DEFAULT_CLIENT_SESSION_TABLE;
  const webviewTickets = options.webviewTicketTable ?? options.webviewTicketsTable ?? options.webviewTicket ?? options.webviewTickets ?? options.clientTicketTable ?? options.clientTicketsTable ?? tables?.webviewTicket ?? tables?.webviewTickets ?? tables?.clientTicket ?? tables?.clientTickets ?? tableNames?.webviewTicket ?? tableNames?.webviewTickets ?? tableNames?.clientTicket ?? tableNames?.clientTickets ?? DEFAULT_WEBVIEW_TICKET_TABLE;
  return {
    applications: base.applications,
    clients: base.clients,
    platforms: base.platforms,
    clientSessions: qualifyTenantTable(validateApplicationSqlIdentifier(clientSessions, "client sessions table"), schema),
    webviewTickets: qualifyTenantTable(validateApplicationSqlIdentifier(webviewTickets, "webview tickets table"), schema),
  };
}

function clientAuthBffStateMigrationTables(options: ApplicationManagementMigrationOptions): ClientAuthBffStateMigrationTables {
  const tables = options.tables as (Partial<ApplicationSqlTableNames> & {
    clientAuthBffState?: string;
    clientAuthBffStates?: string;
    clientAuthState?: string;
    clientAuthStates?: string;
    bffState?: string;
    bffStates?: string;
    clientAuthBffStateTable?: string;
    clientAuthBffStatesTable?: string;
    clientAuthStateTable?: string;
    clientAuthStatesTable?: string;
    bffStateTable?: string;
    bffStatesTable?: string;
  }) | undefined;
  const tableNames = options.tableNames as typeof tables;
  const schema = migrationTenant(options).schema;
  const table = options.clientAuthBffStateTable
    ?? options.clientAuthBffStatesTable
    ?? options.clientAuthStateTable
    ?? options.clientAuthStatesTable
    ?? options.bffStateTable
    ?? options.bffStatesTable
    ?? options.clientAuthBffState
    ?? options.clientAuthBffStates
    ?? options.clientAuthState
    ?? options.clientAuthStates
    ?? options.bffState
    ?? options.bffStates
    ?? tables?.clientAuthBffState
    ?? tables?.clientAuthBffStates
    ?? tables?.clientAuthState
    ?? tables?.clientAuthStates
     ?? tables?.bffState
     ?? tables?.bffStates
     ?? tables?.clientAuthBffStateTable
     ?? tables?.clientAuthBffStatesTable
     ?? tables?.clientAuthStateTable
     ?? tables?.clientAuthStatesTable
     ?? tables?.bffStateTable
     ?? tables?.bffStatesTable
     ?? tableNames?.clientAuthBffState
    ?? tableNames?.clientAuthBffStates
    ?? tableNames?.clientAuthState
    ?? tableNames?.clientAuthStates
     ?? tableNames?.bffState
     ?? tableNames?.bffStates
     ?? tableNames?.clientAuthBffStateTable
     ?? tableNames?.clientAuthBffStatesTable
     ?? tableNames?.clientAuthStateTable
     ?? tableNames?.clientAuthStatesTable
     ?? tableNames?.bffStateTable
     ?? tableNames?.bffStatesTable
     ?? DEFAULT_APPLICATION_MANAGEMENT_CLIENT_AUTH_BFF_STATE_TABLE;
  return {
    clientAuthBffStates: qualifyTenantTable(validateApplicationSqlIdentifier(table, "client auth BFF state table"), schema),
  };
}

function clientAuthBffStateMigrationColumns(options: ApplicationManagementMigrationOptions): ClientAuthBffStateMigrationColumns {
  const columns = mergeAdditiveColumns(
    DEFAULT_CLIENT_AUTH_BFF_STATE_COLUMNS,
    options.clientAuthBffStateColumns,
    options.clientAuthBffStatesColumns,
     options.clientAuthStateColumns,
     options.bffStateColumns,
     options.columns?.clientAuthBffState,
     options.columns?.clientAuthBffStates,
     options.columns?.clientAuthState,
     options.columns?.bffState,
     options.columnNames?.clientAuthBffState,
     options.columnNames?.clientAuthBffStates,
     options.columnNames?.clientAuthState,
     options.columnNames?.bffState,
     options.additiveColumns?.clientAuthBffState,
    options.additiveColumns?.clientAuthBffStates,
    options.additiveColumns?.clientAuthState,
    options.additiveColumns?.bffState,
  );
  columns.tenantId = validateMigrationColumn(migrationTenant(options).tenantColumn, "tenantId");
  validateClientAuthBffStateColumnNames(columns);
  return requiredAdditiveColumns(columns, Object.keys(DEFAULT_CLIENT_AUTH_BFF_STATE_COLUMNS));
}

function validateClientAuthBffStateColumnNames(columns: Record<string, string>): void {
  for (const [field, value] of Object.entries(columns)) {
    const normalized = value.replace(/[-_]/gu, "").toLowerCase();
    if (["state", "codeverifier", "rawstate", "rawcodeverifier", "clientsecret"].includes(normalized)) {
      throw new TypeError(`Invalid client auth BFF state SQL column for ${field}`);
    }
  }
}

function additiveMigrationColumns(options: ApplicationManagementMigrationOptions): AdditiveMigrationColumns {
  const clients = mergeAdditiveColumns(
    { ...migrationColumns(options).clients, ...DEFAULT_ADDITIVE_CLIENT_COLUMNS },
    options.additiveColumns?.clients,
    options.columns?.clients as Partial<Record<string, string | null>> | undefined,
    options.columnNames?.clients as Partial<Record<string, string | null>> | undefined,
    options.clientsColumns as Partial<Record<string, string | null>> | undefined,
  );
  const platforms = mergeAdditiveColumns(
    { ...migrationColumns(options).platforms, ...DEFAULT_ADDITIVE_PLATFORM_COLUMNS },
    options.additiveColumns?.platforms,
    options.columns?.platforms as Partial<Record<string, string | null>> | undefined,
    options.columnNames?.platforms as Partial<Record<string, string | null>> | undefined,
    options.platformsColumns as Partial<Record<string, string | null>> | undefined,
    options.applicationPlatformsColumns as Partial<Record<string, string | null>> | undefined,
  );
  const clientSessions = mergeAdditiveColumns(
    DEFAULT_CLIENT_SESSION_COLUMNS,
    options.additiveColumns?.clientSessions,
    options.clientSessionColumns,
    options.clientSessionsColumns,
    options.opaqueClientSessionColumns,
    options.opaqueClientSessionsColumns,
  );
  const webviewTickets = mergeAdditiveColumns(
    DEFAULT_WEBVIEW_TICKET_COLUMNS,
    options.additiveColumns?.webviewTickets,
    options.webviewTicketColumns,
    options.webviewTicketsColumns,
    options.clientTicketColumns,
    options.clientTicketsColumns,
  );
  setAdditiveColumn(clients, "clientKind", options.clientKindColumn);
  setAdditiveColumn(clients, "clientType", options.clientTypeColumn);
  setAdditiveColumn(clients, "redirectUriPolicy", options.redirectUriPolicyColumn);
  setAdditiveColumn(clients, "pkceRequired", options.pkceRequiredColumn);
  setAdditiveColumn(clients, "pkceMethod", options.pkceMethodColumn);
  setAdditiveColumn(clients, "consentRequired", options.consentRequiredColumn);
  setAdditiveColumn(clients, "consentMode", options.consentModeColumn);
  setAdditiveColumn(clients, "consentScopes", options.consentScopesColumn);
  setAdditiveColumn(clients, "opaqueSessionEnabled", options.opaqueSessionEnabledColumn);
  setAdditiveColumn(clients, "clientSessionTtlSeconds", options.clientSessionTtlSecondsColumn);
  setAdditiveColumn(platforms, "componentAppId", options.componentAppIdColumn);
  setAdditiveColumn(platforms, "componentAppSecretRef", options.componentAppSecretRefColumn);
  setAdditiveColumn(platforms, "componentVerifyTicketRef", options.componentVerifyTicketRefColumn);
  setAdditiveColumn(platforms, "componentAccessTokenRef", options.componentAccessTokenRefColumn);
  setAdditiveColumn(platforms, "authorizedAppId", options.authorizedAppIdColumn);
  setAdditiveColumn(platforms, "authorizerAppId", options.authorizerAppIdColumn);
  setAdditiveColumn(platforms, "authorizerRefreshTokenRef", options.authorizerRefreshTokenRefColumn);
  setAdditiveColumn(platforms, "authorizerAccessTokenRef", options.authorizerAccessTokenRefColumn);
  setAdditiveColumn(platforms, "componentTicketRef", options.componentTicketRefColumn);
  setAdditiveColumn(platforms, "componentTicketExpiresAt", options.componentTicketExpiresAtColumn);
  setAdditiveColumn(platforms, "componentBindingStatus", options.componentBindingStatusColumn);
  setAdditiveColumn(platforms, "componentBindingVersion", options.componentBindingVersionColumn);
  setAdditiveColumn(platforms, "componentScope", options.componentScopeColumn);
  return {
    clients: requiredAdditiveColumns(clients, Object.keys(DEFAULT_ADDITIVE_CLIENT_COLUMNS)),
    platforms: requiredAdditiveColumns(platforms, Object.keys(DEFAULT_ADDITIVE_PLATFORM_COLUMNS)),
    clientSessions: requiredAdditiveColumns(clientSessions, Object.keys(DEFAULT_CLIENT_SESSION_COLUMNS)),
    webviewTickets: requiredAdditiveColumns(webviewTickets, Object.keys(DEFAULT_WEBVIEW_TICKET_COLUMNS)),
  };
}

function mergeAdditiveColumns(
  base: Record<string, string>,
  ...sources: Array<Partial<Record<string, string | null>> | undefined>
): Record<string, string> {
  const output: Record<string, string> = {};
  for (const [key, value] of Object.entries(base)) output[key] = validateMigrationColumn(value, key);
  for (const source of sources) {
    if (source === undefined) continue;
    for (const [key, value] of Object.entries(source)) {
      if (typeof value === "string") output[key] = validateMigrationColumn(value, key);
    }
  }
  return output;
}

function setAdditiveColumn(target: Record<string, string>, key: string, value: string | undefined): void {
  if (value !== undefined) target[key] = validateMigrationColumn(value, key);
}

function requiredAdditiveColumns(columns: Record<string, string>, required: string[]): Record<string, string> {
  for (const key of required) {
    if (columns[key] === undefined) throw new TypeError(`Missing additive SQL column ${key}`);
  }
  return columns;
}

function createClientExtensionSql(table: string, columns: Record<string, string>): string {
  return [
    addColumn(table, columns.clientKind, "TEXT DEFAULT 'web'"),
    addColumn(table, columns.clientType, "TEXT DEFAULT 'web'"),
    addColumn(table, columns.redirectUriPolicy, "TEXT DEFAULT 'exact'"),
    addColumn(table, columns.pkceRequired, "BOOLEAN DEFAULT TRUE"),
    addColumn(table, columns.pkceMethod, "TEXT DEFAULT 'S256'"),
    addColumn(table, columns.consentRequired, "BOOLEAN DEFAULT TRUE"),
    addColumn(table, columns.consentMode, "TEXT DEFAULT 'explicit'"),
    addColumn(table, columns.consentScopes, "TEXT DEFAULT '[]'"),
    addColumn(table, columns.opaqueSessionEnabled, "BOOLEAN DEFAULT FALSE"),
    addColumn(table, columns.clientSessionTtlSeconds, "INTEGER DEFAULT 2592000"),
  ].filter((statement): statement is string => statement !== undefined).join(";\n");
}

function createPlatformComponentBindingSql(table: string, columns: Record<string, string>): string {
  return [
    addColumn(table, columns.componentAppId, "TEXT"),
    addColumn(table, columns.componentAppSecretRef, "TEXT"),
    addColumn(table, columns.componentVerifyTicketRef, "TEXT"),
    addColumn(table, columns.componentAccessTokenRef, "TEXT"),
    addColumn(table, columns.authorizedAppId, "TEXT"),
    addColumn(table, columns.authorizerAppId, "TEXT"),
    addColumn(table, columns.authorizerRefreshTokenRef, "TEXT"),
    addColumn(table, columns.authorizerAccessTokenRef, "TEXT"),
    addColumn(table, columns.componentTicketRef, "TEXT"),
    addColumn(table, columns.componentTicketExpiresAt, "TIMESTAMPTZ"),
    addColumn(table, columns.componentBindingStatus, "TEXT DEFAULT 'unbound'"),
    addColumn(table, columns.componentBindingVersion, "INTEGER DEFAULT 1"),
    addColumn(table, columns.componentScope, "TEXT"),
  ].filter((statement): statement is string => statement !== undefined).join(";\n");
}

function createClientAuthBffStateTable(
  table: string,
  columns: ClientAuthBffStateMigrationColumns,
): string {
  const definitions = [
    `${quoteColumn(columns.tenantId)} TEXT NOT NULL`,
    `${quoteColumn(columns.stateHash)} TEXT NOT NULL`,
    `${quoteColumn(columns.nonce)} TEXT NOT NULL`,
    `${quoteColumn(columns.codeChallenge)} TEXT NOT NULL`,
    `${quoteColumn(columns.redirectUri)} TEXT NOT NULL`,
    `${quoteColumn(columns.clientType)} TEXT NOT NULL`,
    `${quoteColumn(columns.clientId)} TEXT NOT NULL`,
    `${quoteColumn(columns.scope)} TEXT NOT NULL`,
    `${quoteColumn(columns.bindingHash)} TEXT`,
    `${quoteColumn(columns.expiresAt)} TIMESTAMPTZ NOT NULL`,
    `created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP`,
    `PRIMARY KEY (${quoteColumn(columns.tenantId)}, ${quoteColumn(columns.stateHash)})`,
    `CHECK (${quoteColumn(columns.tenantId)} <> '')`,
    `CHECK (${quoteColumn(columns.stateHash)} ~ '^[0-9a-f]{64}$')`,
    `CHECK (${quoteColumn(columns.nonce)} ~ '^[A-Za-z0-9_-]{32,512}$')`,
    `CHECK (${quoteColumn(columns.codeChallenge)} ~ '^[A-Za-z0-9_-]{43}$')`,
    `CHECK (${quoteColumn(columns.redirectUri)} <> '')`,
    `CHECK (${quoteColumn(columns.clientType)} IN ('web', 'native'))`,
    `CHECK (${quoteColumn(columns.clientId)} <> '')`,
    `CHECK (${quoteColumn(columns.scope)} <> '')`,
    `CHECK (${quoteColumn(columns.bindingHash)} IS NULL OR ${quoteColumn(columns.bindingHash)} ~ '^[0-9a-f]{64}$')`,
    `CHECK ((${quoteColumn(columns.clientType)} = 'web' AND ${quoteColumn(columns.bindingHash)} IS NOT NULL) OR (${quoteColumn(columns.clientType)} = 'native' AND ${quoteColumn(columns.bindingHash)} IS NULL))`,
    `CHECK (${quoteColumn(columns.expiresAt)} > ${quoteColumn("created_at")})`,
    `CHECK (${quoteColumn(columns.expiresAt)} > TIMESTAMPTZ '1970-01-01 00:00:00+00')`,
  ];
  return `CREATE TABLE IF NOT EXISTS ${quoteTable(table)} (${definitions.join(", ")})`;
}

function createClientSessionTable(
  table: string,
  columns: Record<string, string>,
  applicationTable: string,
  applicationColumns: Record<string, string>,
): string {
  const definitions = [
    `${quoteColumn(columns.id)} TEXT NOT NULL`,
    `${quoteColumn(columns.tenantId)} TEXT NOT NULL`,
    `${quoteColumn(columns.applicationId)} TEXT NOT NULL`,
    `${quoteColumn(columns.clientId)} TEXT NOT NULL`,
    `${quoteColumn(columns.clientKind)} TEXT NOT NULL CHECK (${quoteColumn(columns.clientKind)} IN ('mp_weixin', 'native'))`,
    `${quoteColumn(columns.sessionHash)} TEXT NOT NULL`,
    `${quoteColumn(columns.userId)} TEXT NOT NULL`,
    `${quoteColumn(columns.status)} TEXT NOT NULL DEFAULT 'active' CHECK (${quoteColumn(columns.status)} IN ('active', 'expired', 'revoked'))`,
    `${quoteColumn(columns.deviceId)} TEXT`,
    `${quoteColumn(columns.bindingHash)} TEXT`,
    `${quoteColumn(columns.createdAt)} TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP`,
    `${quoteColumn(columns.updatedAt)} TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP`,
    `${quoteColumn(columns.lastUsedAt)} TIMESTAMPTZ`,
    `${quoteColumn(columns.expiresAt)} TIMESTAMPTZ NOT NULL`,
    `${quoteColumn(columns.revokedAt)} TIMESTAMPTZ`,
    `PRIMARY KEY (${quoteColumn(columns.tenantId)}, ${quoteColumn(columns.id)})`,
    `FOREIGN KEY (${quoteColumn(columns.tenantId)}, ${quoteColumn(columns.applicationId)}) REFERENCES ${quoteTable(applicationTable)} (${quoteColumn(applicationColumns.tenantId)}, ${quoteColumn(applicationColumns.id)}) ON DELETE CASCADE`,
  ];
  return `CREATE TABLE IF NOT EXISTS ${quoteTable(table)} (${definitions.join(", ")})`;
}

function createWebviewTicketTable(
  table: string,
  columns: Record<string, string>,
  applicationTable: string,
  applicationColumns: Record<string, string>,
): string {
  const definitions = [
    `${quoteColumn(columns.id)} TEXT NOT NULL`,
    `${quoteColumn(columns.tenantId)} TEXT NOT NULL`,
    `${quoteColumn(columns.applicationId)} TEXT NOT NULL`,
    `${quoteColumn(columns.platformId)} TEXT NOT NULL`,
    `${quoteColumn(columns.clientId)} TEXT`,
    `${quoteColumn(columns.ticketHash)} TEXT NOT NULL`,
    `${quoteColumn(columns.sessionHash)} TEXT`,
    `${quoteColumn(columns.bindingHash)} TEXT`,
    `${quoteColumn(columns.redirectUri)} TEXT NOT NULL`,
    `${quoteColumn(columns.status)} TEXT NOT NULL DEFAULT 'issued' CHECK (${quoteColumn(columns.status)} IN ('issued', 'consumed', 'expired', 'revoked'))`,
    `${quoteColumn(columns.createdAt)} TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP`,
    `${quoteColumn(columns.updatedAt)} TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP`,
    `${quoteColumn(columns.consumedAt)} TIMESTAMPTZ`,
    `${quoteColumn(columns.expiresAt)} TIMESTAMPTZ NOT NULL`,
    `${quoteColumn(columns.revokedAt)} TIMESTAMPTZ`,
    `PRIMARY KEY (${quoteColumn(columns.tenantId)}, ${quoteColumn(columns.id)})`,
    `FOREIGN KEY (${quoteColumn(columns.tenantId)}, ${quoteColumn(columns.applicationId)}) REFERENCES ${quoteTable(applicationTable)} (${quoteColumn(applicationColumns.tenantId)}, ${quoteColumn(applicationColumns.id)}) ON DELETE CASCADE`,
  ];
  return `CREATE TABLE IF NOT EXISTS ${quoteTable(table)} (${definitions.join(", ")})`;
}
