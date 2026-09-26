import { createHash, randomBytes, randomUUID } from "node:crypto";
import { AsyncLocalStorage } from "node:async_hooks";
import {
  getTenantTransactionExecutor,
  normalizeTenantConfig,
  qualifyTenantTable,
  runWithTenantTransaction,
  type TenantConfig,
  type TenantConfigInput,
  type TenantMode,
  type TenantSqlExecutor,
} from "./tenant.js";
import { externalIdentityCanonicalKey } from "./identity.js";
import type {
  ApplicationClientCreateRequest,
  ApplicationClientListQuery,
  ApplicationClientRotateSecretRequest,
  ApplicationClientStatus,
  ApplicationClientUpdateRequest,
  ApplicationCreateRequest,
  ApplicationExternalIdentityListQuery,
  ApplicationListQuery,
  ApplicationPlatformCreateRequest,
  ApplicationPlatformListQuery,
  ApplicationPlatformUpdateRequest,
  ApplicationStatus,
  ApplicationUpdateRequest,
  OpaqueClientSessionIssueResult,
  OpaqueClientSessionRecord,
  WebviewTicketConsumeRequest,
  WebviewTicketIssueResult,
  WebviewTicketRecord,
} from "@getbrick/idaas-contracts";
import {
  ControlPlaneSqlRollbackError,
  conflict,
  invalidRequest,
  notFound,
} from "./errors.js";
import { sanitizeAuditDetail } from "./dto.js";
import {
  decodeApplicationCursor,
  encodeApplicationCursor,
} from "./application-repository.js";
import {
  parseApplicationClientIdentifier,
  parseApplicationClientListQuery,
  parseApplicationExternalIdentityListQuery,
  parseApplicationIdentifier,
  parseApplicationListQuery,
  parseApplicationPlatformIdentifier,
  parseApplicationPlatformListQuery,
} from "./application-validation.js";
import type {
  ApplicationAuditEvent,
  ApplicationClientRecord,
  ApplicationClientMutationRequest,
  ApplicationPlatformMutationRequest,
  ApplicationExternalIdentityRecord,
  ApplicationExternalIdentityUpsertInput,
  ApplicationPage,
  ApplicationPlatformRecord,
  ApplicationRecord,
  ApplicationRepository,
  ApplicationWriteContext,
  OpaqueClientSessionIssueInput,
  OpaqueClientSessionRepository,
  WebviewTicketIssueInput,
  WebviewTicketRepository,
  NormalizedApplicationClientQuery,
  NormalizedApplicationExternalIdentityQuery,
  NormalizedApplicationPlatformQuery,
  NormalizedApplicationQuery,
} from "./application-types.js";

const DEFAULT_TENANT_ID = "default";
const CURSOR_VERSION = 1;

export type ApplicationSqlQuery = (
  text: string,
  values: unknown[],
) => unknown | Promise<unknown>;

export interface ApplicationSqlExecutor {
  query: ApplicationSqlQuery;
  transaction?<T>(callback: (executor: ApplicationSqlExecutor) => Promise<T>): Promise<T>;
}

export type ApplicationQueryExecutor = ApplicationSqlExecutor;
export type SqlApplicationQueryExecutor = ApplicationSqlExecutor;

export interface ApplicationSqlTableNames {
  applications: string;
  platforms: string;
  clients: string;
  auditEvents: string;
  application?: string;
  applicationPlatform?: string;
  applicationPlatforms?: string;
  platform?: string;
  applicationClient?: string;
  applicationClients?: string;
  client?: string;
  audit?: string;
  externalIdentities?: string;
  applicationExternalIdentities?: string;
  externalIdentity?: string;
  applicationIdentity?: string;
  identities?: string;
  secretBindings?: string;
  platformLoginStates?: string;
  platformLoginState?: string;
  tenants?: string;
  clientSessions?: string;
  opaqueClientSessions?: string;
  webviewTickets?: string;
  clientTickets?: string;
}

export interface ApplicationSqlApplicationColumns {
  id: string;
  tenantId: string | null;
  applicationType: string;
  name: string;
  slug: string;
  description: string | null;
  status: string;
  lifecycleStatus: string | null;
  readiness: string | null;
  effectiveStatus: string | null;
  version: string | null;
  etag: string | null;
  previousStatus: string | null;
  createdAt: string;
  updatedAt: string;
  enabledAt: string | null;
  disabledAt: string | null;
  archivedAt: string | null;
  purgedAt: string | null;
  [key: string]: string | null;
}

export interface ApplicationSqlPlatformColumns {
  id: string;
  tenantId: string | null;
  applicationId: string;
  type: string;
  externalAppId: string | null;
  displayName: string | null;
  loginMode: string | null;
  scope: string | null;
  scopes: string | null;
  redirectUris: string | null;
  endpointUrl: string | null;
  secretRef: string | null;
  lifecycleStatus: string | null;
  readiness: string | null;
  effectiveStatus: string | null;
  version: string | null;
  etag: string | null;
  secretVersion: string | null;
  status: string;
  createdAt: string;
  updatedAt: string;
  enabledAt: string | null;
  disabledAt: string | null;
  archivedAt: string | null;
  purgedAt: string | null;
  componentAppId: string | null;
  componentAppSecretRef: string | null;
  componentVerifyTicketRef: string | null;
  componentAccessTokenRef: string | null;
  authorizedAppId: string | null;
  authorizerAppId: string | null;
  authorizerRefreshTokenRef: string | null;
  authorizerAccessTokenRef: string | null;
  componentTicketRef: string | null;
  componentTicketExpiresAt: string | null;
  componentBindingStatus: string | null;
  componentBindingVersion: string | null;
  componentScope: string | null;
  [key: string]: string | null;
}

export interface ApplicationSqlClientColumns {
  id: string;
  tenantId: string | null;
  applicationId: string;
  clientId: string;
  clientIdScope: string;
  status: string;
  redirectUris: string | null;
  postLogoutRedirectUris: string | null;
  grantTypes: string | null;
  responseTypes: string | null;
  scopes: string | null;
  tokenEndpointAuthMethod: string | null;
  tokenEndpointAuthSigningAlg: string | null;
  jwksUri: string | null;
  privateKeyRef: string | null;
  keyId: string | null;
  requirePkce: string | null;
  secretRef: string | null;
  lifecycleStatus: string | null;
  readiness: string | null;
  effectiveStatus: string | null;
  version: string | null;
  etag: string | null;
  secretVersion: string | null;
  createdAt: string;
  updatedAt: string;
  enabledAt: string | null;
  disabledAt: string | null;
  archivedAt: string | null;
  purgedAt: string | null;
  clientKind: string | null;
  clientType: string | null;
  redirectUriPolicy: string | null;
  pkceRequired: string | null;
  pkceMethod: string | null;
  consentRequired: string | null;
  consentMode: string | null;
  consentScopes: string | null;
  opaqueSessionEnabled: string | null;
  clientSessionTtlSeconds: string | null;
  [key: string]: string | null;
}

export interface ApplicationSqlAuditColumns {
  id: string;
  tenantId: string | null;
  event: string;
  action: string;
  actorId: string;
  targetId: string;
  requestId: string;
  outcome: string;
  ipAddress: string;
  userAgent: string;
  detail: string;
  version: string | null;
  occurredAt: string;
  createdAt: string;
  [key: string]: string | null;
}

export interface ApplicationSqlExternalIdentityColumns {
  id: string;
  tenantId: string | null;
  applicationId: string;
  platformId: string | null;
  platform: string;
  provider: string;
  providerAppId: string;
  subject: string;
  externalAppId: string | null;
  openid: string | null;
  unionid: string | null;
  nickname: string | null;
  displayName: string | null;
  email: string | null;
  avatarUrl: string | null;
  scopes: string | null;
  canonicalUserId: string | null;
  linkStatus: string;
  emailVerified: string;
  firstLinkedAt: string | null;
  linkedAt: string | null;
  lastAuthenticatedAt: string | null;
  version: string;
  createdAt: string;
  updatedAt: string;
  [key: string]: string | null;
}

export interface ApplicationSqlColumns {
  applications?: Partial<ApplicationSqlApplicationColumns>;
  application?: Partial<ApplicationSqlApplicationColumns>;
  platforms?: Partial<ApplicationSqlPlatformColumns>;
  applicationPlatform?: Partial<ApplicationSqlPlatformColumns>;
  applicationPlatforms?: Partial<ApplicationSqlPlatformColumns>;
  clients?: Partial<ApplicationSqlClientColumns>;
  applicationClient?: Partial<ApplicationSqlClientColumns>;
  applicationClients?: Partial<ApplicationSqlClientColumns>;
  auditEvents?: Partial<ApplicationSqlAuditColumns>;
  audit?: Partial<ApplicationSqlAuditColumns>;
  externalIdentities?: Partial<ApplicationSqlExternalIdentityColumns>;
  applicationExternalIdentities?: Partial<ApplicationSqlExternalIdentityColumns>;
}

export interface ApplicationSqlRepositoryOptions {
  executor?: ApplicationSqlExecutor;
  query?: ApplicationSqlQuery;
  sharedExecutor?: ApplicationSqlExecutor;
  dedicatedExecutor?: ApplicationSqlExecutor;
  fallbackExecutor?: ApplicationSqlExecutor;
  allowSharedFallback?: boolean;
  secretBindings?: {
    resolve(subjectType: string, subjectId: string, purpose: string, at?: Date): Promise<{ binding: { secretRef: string; status?: string; version?: number } } | undefined>;
  };
  tenantId?: string;
  tenant?: TenantConfigInput;
  tenantConfig?: TenantConfigInput;
  tenantMode?: string;
  mode?: string;
  requireRls?: boolean;
  requireTransactions?: boolean;
  requireClientSessions?: boolean;
  requireWebviewTickets?: boolean;
  tenantColumn?: string | null;
  schema?: string;
  tables?: Partial<ApplicationSqlTableNames>;
  tableNames?: Partial<ApplicationSqlTableNames>;
  columns?: ApplicationSqlColumns;
  columnNames?: ApplicationSqlColumns;
  applicationTable?: string;
  application?: string;
  applicationPlatforms?: string;
  applicationPlatformsTable?: string;
  platformTable?: string;
  applicationPlatformTable?: string;
  platform?: string;
  clientTable?: string;
  applicationClientTable?: string;
  applicationClients?: string;
  applicationClientsTable?: string;
  client?: string;
  auditTable?: string;
  auditEventsTable?: string;
  externalIdentitiesTable?: string;
  applicationExternalIdentitiesTable?: string;
  externalIdentityTable?: string;
  applicationIdentityTable?: string;
  platformLoginStateTable?: string;
  platformLoginStatesTable?: string;
  platformLoginState?: string;
  platformLoginStates?: string;
  applicationsColumns?: Partial<ApplicationSqlApplicationColumns>;
  platformsColumns?: Partial<ApplicationSqlPlatformColumns>;
  applicationPlatformsColumns?: Partial<ApplicationSqlPlatformColumns>;
  clientsColumns?: Partial<ApplicationSqlClientColumns>;
  applicationClientsColumns?: Partial<ApplicationSqlClientColumns>;
  auditEventsColumns?: Partial<ApplicationSqlAuditColumns>;
  externalIdentitiesColumns?: Partial<ApplicationSqlExternalIdentityColumns>;
  applicationExternalIdentitiesColumns?: Partial<ApplicationSqlExternalIdentityColumns>;
  clientSessionRepository?: OpaqueClientSessionRepository;
  webviewTicketRepository?: WebviewTicketRepository;
  clientSessionTable?: string;
  clientSessionsTable?: string;
  opaqueClientSessionTable?: string;
  opaqueClientSessionsTable?: string;
  webviewTicketTable?: string;
  webviewTicketsTable?: string;
  clientTicketTable?: string;
  clientTicketsTable?: string;
}

export type SqlApplicationRepositoryOptions = ApplicationSqlRepositoryOptions;
export type ApplicationManagementSqlRepositoryOptions = ApplicationSqlRepositoryOptions;

type SqlRepositoryInput =
  | ApplicationSqlRepositoryOptions
  | ApplicationSqlExecutor
  | ApplicationSqlQuery;

type SqlRepositorySecondOptions = Omit<
  ApplicationSqlRepositoryOptions,
  "executor" | "query"
>;

type SqlRecord = Record<string, unknown>;
type NormalizedTables = {
  applications: string;
  platforms: string;
  clients: string;
  auditEvents: string;
  externalIdentities: string;
  platformLoginStates: string;
  clientSessions: string;
  webviewTickets: string;
};
type NormalizedColumns = {
  applications: ApplicationSqlApplicationColumns;
  platforms: ApplicationSqlPlatformColumns;
  clients: ApplicationSqlClientColumns;
  auditEvents: ApplicationSqlAuditColumns;
  externalIdentities: ApplicationSqlExternalIdentityColumns;
};

const DEFAULT_TABLES: NormalizedTables = {
  applications: "gb_idaas_application",
  platforms: "gb_idaas_application_platform",
  clients: "gb_idaas_application_client",
  auditEvents: "gb_idaas_audit",
  externalIdentities: "gb_idaas_application_external_identity",
  platformLoginStates: "gb_idaas_platform_login_state",
  clientSessions: "gb_idaas_client_session",
  webviewTickets: "gb_idaas_webview_ticket",
};

const DEFAULT_COLUMNS: NormalizedColumns = {
  applications: {
    id: "id",
    tenantId: "tenant_id",
    applicationType: "application_type",
    name: "name",
    slug: "slug",
    description: "description",
    status: "status",
    lifecycleStatus: "lifecycle_status",
    readiness: "readiness",
    effectiveStatus: "effective_status",
    version: "version",
    etag: "etag",
    previousStatus: "previous_status",
    createdAt: "created_at",
    updatedAt: "updated_at",
    enabledAt: "enabled_at",
    disabledAt: "disabled_at",
    archivedAt: "archived_at",
    purgedAt: "purged_at",
  },
  platforms: {
    id: "id",
    tenantId: "tenant_id",
    applicationId: "application_id",
    type: "type",
    externalAppId: "external_app_id",
    displayName: "display_name",
    loginMode: "login_mode",
    scope: "scope",
    scopes: "scopes",
    redirectUris: "redirect_uris",
    endpointUrl: "endpoint_url",
    secretRef: "secret_ref",
    lifecycleStatus: "lifecycle_status",
    readiness: "readiness",
    effectiveStatus: "effective_status",
    version: "version",
    etag: "etag",
    secretVersion: "secret_version",
    status: "status",
    createdAt: "created_at",
    updatedAt: "updated_at",
    enabledAt: "enabled_at",
    disabledAt: "disabled_at",
     archivedAt: "archived_at",
     purgedAt: "purged_at",
     componentAppId: null,
     componentAppSecretRef: null,
     componentVerifyTicketRef: null,
     componentAccessTokenRef: null,
     authorizedAppId: null,
     authorizerAppId: null,
     authorizerRefreshTokenRef: null,
     authorizerAccessTokenRef: null,
     componentTicketRef: null,
     componentTicketExpiresAt: null,
     componentBindingStatus: null,
     componentBindingVersion: null,
     componentScope: null,
   },
   clients: {
    id: "id",
    tenantId: "tenant_id",
    applicationId: "application_id",
    clientId: "client_id",
    clientIdScope: "client_id_scope",
    status: "status",
    redirectUris: "redirect_uris",
    postLogoutRedirectUris: "post_logout_redirect_uris",
    grantTypes: "grant_types",
    responseTypes: "response_types",
    scopes: "scopes",
    tokenEndpointAuthMethod: "token_endpoint_auth_method",
    tokenEndpointAuthSigningAlg: "token_endpoint_auth_signing_alg",
    jwksUri: "jwks_uri",
    privateKeyRef: "private_key_ref",
    keyId: "key_id",
    requirePkce: "require_pkce",
    secretRef: "secret_ref",
    lifecycleStatus: "lifecycle_status",
    readiness: "readiness",
    effectiveStatus: "effective_status",
    version: "version",
    etag: "etag",
    secretVersion: "secret_version",
    createdAt: "created_at",
    updatedAt: "updated_at",
    enabledAt: "enabled_at",
    disabledAt: "disabled_at",
     archivedAt: "archived_at",
     purgedAt: "purged_at",
     clientKind: null,
     clientType: null,
     redirectUriPolicy: null,
     pkceRequired: null,
     pkceMethod: null,
     consentRequired: null,
     consentMode: null,
     consentScopes: null,
     opaqueSessionEnabled: null,
     clientSessionTtlSeconds: null,
   },
   auditEvents: {
    id: "id",
    tenantId: "tenant_id",
    event: "event",
    action: "action",
    actorId: "actor_id",
    targetId: "target_id",
    requestId: "request_id",
    outcome: "outcome",
    ipAddress: "ip_address",
    userAgent: "user_agent",
    detail: "detail",
    version: "version",
    occurredAt: "occurred_at",
    createdAt: "created_at",
  },
  externalIdentities: {
    id: "id",
    tenantId: "tenant_id",
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
};

export const APPLICATION_MANAGEMENT_SQL_TABLES = DEFAULT_TABLES;
export const APPLICATION_SQL_TABLES = DEFAULT_TABLES;
export const DEFAULT_APPLICATION_TABLES = DEFAULT_TABLES;
export const APPLICATION_MANAGEMENT_SQL_COLUMNS: ApplicationSqlColumns = DEFAULT_COLUMNS;
export const APPLICATION_SQL_COLUMNS: ApplicationSqlColumns = DEFAULT_COLUMNS;
export const APPLICATION_MANAGEMENT_REQUIRED_COLUMNS = {
  applications: ["id", "tenantId", "name", "slug", "status", "createdAt", "updatedAt", "version"],
  platforms: ["id", "tenantId", "applicationId", "type", "status", "createdAt", "updatedAt", "version"],
  clients: ["id", "tenantId", "applicationId", "clientId", "clientIdScope", "status", "createdAt", "updatedAt", "version"],
  auditEvents: ["id", "tenantId", "event", "occurredAt", "createdAt"],
  externalIdentities: ["id", "tenantId", "applicationId", "platform", "provider", "providerAppId", "subject", "firstLinkedAt", "version"],
} as const;

const APPLICATION_FIELDS: readonly string[] = [
  "id",
  "tenantId",
  "applicationType",
  "name",
  "slug",
  "description",
  "status",
  "lifecycleStatus",
  "readiness",
  "effectiveStatus",
  "version",
  "etag",
  "previousStatus",
  "createdAt",
  "updatedAt",
  "enabledAt",
  "disabledAt",
  "archivedAt",
  "purgedAt",
];
const PLATFORM_FIELDS: readonly string[] = [
  "id",
  "tenantId",
  "applicationId",
  "type",
  "externalAppId",
  "displayName",
  "loginMode",
  "scope",
  "scopes",
  "redirectUris",
  "endpointUrl",
  "secretRef",
  "lifecycleStatus",
  "readiness",
  "effectiveStatus",
  "version",
  "etag",
  "secretVersion",
  "status",
  "createdAt",
  "updatedAt",
  "enabledAt",
  "disabledAt",
  "archivedAt",
  "purgedAt",
  "componentAppId",
  "componentAppSecretRef",
  "componentVerifyTicketRef",
  "componentAccessTokenRef",
  "authorizedAppId",
  "authorizerAppId",
  "authorizerRefreshTokenRef",
  "authorizerAccessTokenRef",
  "componentTicketRef",
  "componentTicketExpiresAt",
  "componentBindingStatus",
  "componentBindingVersion",
  "componentScope",
];
const CLIENT_FIELDS: readonly string[] = [
  "id",
  "tenantId",
  "applicationId",
  "clientId",
  "clientIdScope",
  "status",
  "redirectUris",
  "postLogoutRedirectUris",
  "grantTypes",
  "responseTypes",
  "scopes",
  "tokenEndpointAuthMethod",
  "tokenEndpointAuthSigningAlg",
  "jwksUri",
  "privateKeyRef",
  "keyId",
  "requirePkce",
  "secretRef",
  "lifecycleStatus",
  "readiness",
  "effectiveStatus",
  "version",
  "etag",
  "secretVersion",
  "createdAt",
  "updatedAt",
  "enabledAt",
  "disabledAt",
  "archivedAt",
  "purgedAt",
  "clientKind",
  "clientType",
  "redirectUriPolicy",
  "pkceRequired",
  "pkceMethod",
  "consentRequired",
  "consentMode",
  "consentScopes",
  "opaqueSessionEnabled",
  "clientSessionTtlSeconds",
];
const EXTERNAL_IDENTITY_FIELDS: readonly (keyof ApplicationSqlExternalIdentityColumns)[] = [
  "id",
  "tenantId",
  "applicationId",
  "platformId",
  "platform",
  "provider",
  "providerAppId",
  "subject",
  "externalAppId",
  "openid",
  "unionid",
  "nickname",
  "displayName",
  "email",
  "avatarUrl",
  "scopes",
  "canonicalUserId",
  "linkStatus",
  "emailVerified",
  "firstLinkedAt",
  "linkedAt",
  "lastAuthenticatedAt",
  "version",
  "createdAt",
  "updatedAt",
];
const AUDIT_FIELDS: readonly (keyof ApplicationSqlAuditColumns)[] = [
  "id",
  "tenantId",
  "event",
  "action",
  "actorId",
  "targetId",
  "requestId",
  "outcome",
  "ipAddress",
  "userAgent",
  "detail",
  "version",
  "occurredAt",
  "createdAt",
];

export class SqlApplicationRepository implements ApplicationRepository {
  readonly tenantId: string;
  readonly tenant: TenantConfig;
  private readonly executor: ApplicationSqlExecutor;
  private readonly secretBindings?: ApplicationSqlRepositoryOptions["secretBindings"];
  private readonly clientSessionRepository?: OpaqueClientSessionRepository;
  private readonly webviewTicketRepository?: WebviewTicketRepository;
  private readonly requireClientSessions: boolean;
  private readonly requireWebviewTickets: boolean;
  private readonly scopedExecutors = new WeakSet<object>();
  private readonly transactionContext = new AsyncLocalStorage<ApplicationSqlExecutor>();
  private readonly tables: NormalizedTables;
  private readonly columns: NormalizedColumns;

  constructor(options: ApplicationSqlRepositoryOptions);
  constructor(executor: ApplicationSqlExecutor, options?: SqlRepositorySecondOptions);
  constructor(query: ApplicationSqlQuery, options?: SqlRepositorySecondOptions);
  constructor(input: SqlRepositoryInput, secondOptions: SqlRepositorySecondOptions = {}) {
    const options = normalizeOptions(input, secondOptions);
    assertNoApplicationDedicatedFallback(options);
    this.secretBindings = options.secretBindings;
    this.clientSessionRepository = options.clientSessionRepository;
    this.webviewTicketRepository = options.webviewTicketRepository;
    this.requireClientSessions = options.requireClientSessions === true;
    this.requireWebviewTickets = options.requireWebviewTickets === true;
    this.tenant = normalizeTenantConfig({
      ...(options.tenant ?? {}),
      ...(options.tenantConfig ?? {}),
      ...(options.tenantMode === undefined ? {} : { mode: options.tenantMode }),
      ...(options.mode === undefined ? {} : { mode: options.mode }),
      ...(options.tenantId === undefined ? {} : { tenantId: options.tenantId }),
      ...(options.tenantColumn === undefined ? {} : { tenantColumn: options.tenantColumn }),
      ...(options.schema === undefined ? {} : { schema: options.schema }),
      ...(options.requireRls === undefined ? {} : { requireRls: options.requireRls }),
      ...(options.requireTransactions === undefined ? {} : { requireTransactions: options.requireTransactions }),
    });
    this.executor = normalizeExecutor(options, this.tenant.mode);
    this.tenantId = this.tenant.tenantId;
    this.tables = normalizeTables(options);
    this.columns = normalizeColumns(options, this.tenant.tenantColumn);
  }

  async listApplications(
    query: ApplicationListQuery | NormalizedApplicationQuery = {},
  ): Promise<ApplicationPage<ApplicationRecord>> {
    const normalized = parseApplicationListQuery(query);
    const where = this.applicationWhere(normalized);
    const total = await this.count(
      `SELECT COUNT(*)::int AS "total" FROM ${this.applicationsTable()}${where.text}`,
      where.values,
    );
    const scope = applicationScope(normalized);
    const keyset = normalized.cursor === undefined ? undefined : decodeApplicationKeysetCursor(normalized.cursor, "applications", scope, this.tenantId);
    if (keyset !== undefined) this.addKeysetClause("applications", keyset.id, where.values, where.clauses);
    const text = whereText(where.clauses);
    const offset = keyset === undefined ? cursorOffset("applications", scope, normalized.cursor, normalized.offset) : 0;
    const order = keyset === undefined ? this.quote(this.columns.applications.id) : `${this.quote(this.columns.applications.tenantId)}, ${this.quote(this.columns.applications.id)}`;
    const rows = await this.queryRows(
      `SELECT ${this.select(this.columns.applications, APPLICATION_FIELDS)} FROM ${this.applicationsTable()}${text} ORDER BY ${order} ASC LIMIT $${where.values.length + 1}${keyset === undefined ? ` OFFSET $${where.values.length + 2}` : ""}`,
      [...where.values, keyset === undefined ? normalized.limit : normalized.limit + 1, ...(keyset === undefined ? [offset] : [])],
    );
    const items = rows.slice(0, normalized.limit).map((row) => this.mapApplication(row)).filter((record) => this.belongs(record));
    const hasMore = keyset === undefined ? offset + rows.length < total : rows.length > normalized.limit;
    return this.page("applications", normalized, items, total, scope, keyset !== undefined, hasMore);
  }

  async getApplication(id: string): Promise<ApplicationRecord | undefined> {
    const identifier = parseApplicationIdentifier(id);
    const values: unknown[] = [];
    const clauses: string[] = [];
    this.addTenantClause("applications", values, clauses);
    values.push(identifier);
    clauses.push(`${this.quote(this.columns.applications.id)} = $${values.length}`);
    const rows = await this.queryRows(
      `SELECT ${this.select(this.columns.applications, APPLICATION_FIELDS)} FROM ${this.applicationsTable()}${whereText(clauses)} LIMIT 1`,
      values,
    );
    if (rows[0] === undefined) return undefined;
    const application = this.mapApplication(rows[0]);
    return this.belongs(application) ? application : undefined;
  }

  async createApplication(
    input: ApplicationCreateRequest & { id?: string },
    context: ApplicationWriteContext = {},
  ): Promise<ApplicationRecord> {
    const id = input.id ?? randomUUID();
    const now = new Date();
    const values: ApplicationRecord = {
      id,
      tenantId: this.tenantId,
      applicationType: input.applicationType ?? "web",
      name: input.name,
      slug: input.slug,
      description: input.description ?? null,
      status: "active",
      lifecycleStatus: "active",
      readiness: "ready",
      effectiveStatus: "active",
      version: 1,
      etag: `application:${id}:1`,
      createdAt: now,
      updatedAt: now,
      enabledAt: now,
      disabledAt: null,
      archivedAt: null,
      purgedAt: null,
    };
    return this.auditedWrite(
      async (executor) => {
        await this.assertSlugAvailable(executor, input.slug);
        const row = await this.insertRecord(
          this.columns.applications,
          APPLICATION_FIELDS,
          values,
          this.applicationsTable(),
          executor,
        );
        return { result: row === undefined ? values : this.mapApplication(row), applied: true };
      },
      this.auditEvent("application.created", id, context, { fields: ["name", "slug"] }),
      async (executor) => {
        const rollbackValues: unknown[] = [];
        const rollbackClauses: string[] = [];
        this.addTenantClause("applications", rollbackValues, rollbackClauses);
        rollbackValues.push(id);
        rollbackClauses.push(`${this.quote(this.columns.applications.id)} = $${rollbackValues.length}`);
        const count = await this.queryAffected(
          `DELETE FROM ${this.applicationsTable()}${whereText(rollbackClauses)}`,
          rollbackValues,
          executor,
        );
        if (count !== 1) throw new Error("Application SQL rollback did not affect a row");
      },
    );
  }

  async updateApplication(
    id: string,
    input: ApplicationUpdateRequest & { id?: string },
    context: ApplicationWriteContext = {},
  ): Promise<ApplicationRecord> {
    const identifier = parseApplicationIdentifier(id);
    const current = await this.requireApplication(identifier);
    if (input.slug !== undefined && input.slug !== current.slug) await this.assertSlugAvailable(this.activeExecutor(), input.slug, identifier);
    const values: Record<string, unknown> = {};
    if (input.name !== undefined) values.name = input.name;
    if (input.slug !== undefined) values.slug = input.slug;
    if (input.description !== undefined) values.description = input.description;
    if (input.applicationType !== undefined) values.applicationType = input.applicationType;
    values.updatedAt = new Date();
    values.version = nextVersion(current.version);
    values.etag = `application:${identifier}:${String(values.version)}`;
    const updated = { ...current, ...values } as ApplicationRecord;
    updated.readiness = readinessForRecord(updated);
    updated.effectiveStatus = effectiveStatusForRecord(updated);
    values.readiness = updated.readiness;
    values.effectiveStatus = updated.effectiveStatus;
    return this.auditedWrite(
      async (executor) => {
        const row = await this.updateRecord(
          "applications",
          this.columns.applications,
          APPLICATION_FIELDS,
          this.applicationsTable(),
          identifier,
          values,
          executor,
          undefined,
          undefined,
          undefined,
          currentVersion(current),
        );
        return { result: row === undefined ? updated : this.mapApplication(row), applied: row !== undefined };
      },
      this.auditEvent("application.updated", identifier, context, { fields: Object.keys(values).filter((field) => field !== "updatedAt") }),
      async (executor) => {
        await this.restoreApplicationRow(identifier, current, executor);
      },
    );
  }

  async setApplicationStatus(
    id: string,
    status: ApplicationStatus,
    context: ApplicationWriteContext = {},
  ): Promise<ApplicationRecord> {
    const identifier = parseApplicationIdentifier(id);
    const current = await this.requireApplication(identifier);
    if (status !== "active" && status !== "disabled") throw invalidRequest("Invalid application status");
    const currentStatus = lifecycleStatusOf(current);
    if (currentStatus !== "active" && currentStatus !== "disabled") throw conflict("Application is archived or purged");
    if (currentStatus === status) throw conflict("Application is already in the requested state");
    const now = new Date();
    const version = nextVersion(current.version);
    const updated = { ...current, status, lifecycleStatus: status, version, etag: `application:${identifier}:${String(version)}`, updatedAt: now } as ApplicationRecord;
    updated.readiness = readinessForRecord(updated);
    updated.effectiveStatus = effectiveStatusForRecord(updated);
    if (status === "active") {
      updated.enabledAt = now;
      updated.disabledAt = null;
    } else {
      updated.disabledAt = now;
      updated.enabledAt = null;
    }
    return this.auditedWrite(
      async (executor) => {
        const row = await this.updateRecord(
          "applications",
          this.columns.applications,
          APPLICATION_FIELDS,
          this.applicationsTable(),
          identifier,
          { status, lifecycleStatus: status, version, etag: updated.etag, readiness: updated.readiness, effectiveStatus: updated.effectiveStatus, updatedAt: now, enabledAt: updated.enabledAt, disabledAt: updated.disabledAt },
          executor,
          currentStatus,
          "status",
          undefined,
          currentVersion(current),
        );
        if (row === undefined) throw conflict("Application state changed");
        return { result: this.mapApplication(row), applied: true };
      },
      this.auditEvent(status === "active" ? "application.enabled" : "application.disabled", identifier, context, { status }),
      async (executor) => this.restoreApplicationRow(identifier, current, executor),
    );
  }

  async archiveApplication(id: string, context: ApplicationWriteContext = {}): Promise<ApplicationRecord> {
    const identifier = parseApplicationIdentifier(id);
    const current = await this.requireApplication(identifier);
    const currentStatus = lifecycleStatusOf(current);
    if (currentStatus === "archived" || currentStatus === "purged") throw conflict("Application is already archived or purged");
    const now = new Date();
    const version = nextVersion(current.version);
    const updated = {
      ...current,
      previousStatus: currentStatus,
      status: "archived",
      lifecycleStatus: "archived",
      readiness: "not_ready",
      effectiveStatus: "archived",
      archivedAt: now,
      updatedAt: now,
      version,
      etag: `application:${identifier}:${String(version)}`,
    } as ApplicationRecord;
    delete updated.purgedAt;
    return this.auditedWrite(
      async (executor) => {
        const row = await this.updateRecord(
          "applications",
          this.columns.applications,
          APPLICATION_FIELDS,
          this.applicationsTable(),
          identifier,
          {
            previousStatus: currentStatus,
            status: "archived",
            lifecycleStatus: "archived",
            readiness: "not_ready",
            effectiveStatus: "archived",
            archivedAt: now,
            updatedAt: now,
            version,
            etag: updated.etag,
          },
          executor,
          undefined,
          undefined,
          undefined,
          currentVersion(current),
        );
        if (row === undefined) throw conflict("Application state changed");
        return { result: this.mapApplication(row), applied: true };
      },
      this.auditEvent("application.archived", identifier, context, { previousStatus: currentStatus }),
      async (executor) => this.restoreApplicationRow(identifier, current, executor),
    );
  }

  async restoreApplication(id: string, context: ApplicationWriteContext = {}): Promise<ApplicationRecord> {
    const identifier = parseApplicationIdentifier(id);
    const current = await this.requireApplication(identifier);
    if (lifecycleStatusOf(current) !== "archived") throw conflict("Only archived applications can be restored");
    const restoredStatus = current.previousStatus === "disabled" ? "disabled" : "active";
    const now = new Date();
    const version = nextVersion(current.version);
    const updated = {
      ...current,
      status: restoredStatus,
      lifecycleStatus: restoredStatus,
      readiness: restoredStatus === "active" ? "ready" : "not_ready",
      effectiveStatus: restoredStatus,
      enabledAt: restoredStatus === "active" ? now : current.enabledAt,
      disabledAt: restoredStatus === "disabled" ? now : null,
      updatedAt: now,
      version,
      etag: `application:${identifier}:${String(version)}`,
    } as ApplicationRecord;
    delete updated.previousStatus;
    delete updated.archivedAt;
    const values: Record<string, unknown> = {
      status: restoredStatus,
      lifecycleStatus: restoredStatus,
      readiness: updated.readiness,
      effectiveStatus: restoredStatus,
      enabledAt: updated.enabledAt,
      disabledAt: updated.disabledAt,
      updatedAt: now,
      version,
      etag: updated.etag,
      previousStatus: null,
      archivedAt: null,
    };
    return this.auditedWrite(
      async (executor) => {
        const row = await this.updateRecord(
          "applications",
          this.columns.applications,
          APPLICATION_FIELDS,
          this.applicationsTable(),
          identifier,
          values,
          executor,
          "archived",
          "status",
          undefined,
          currentVersion(current),
        );
        if (row === undefined) throw conflict("Application state changed");
        return { result: this.mapApplication(row), applied: true };
      },
      this.auditEvent("application.restored", identifier, context, { status: restoredStatus }),
      async (executor) => this.restoreApplicationRow(identifier, current, executor),
    );
  }

  async purgeApplication(id: string, context: ApplicationWriteContext = {}): Promise<ApplicationRecord> {
    const identifier = parseApplicationIdentifier(id);
    const current = await this.requireApplication(identifier);
    if (lifecycleStatusOf(current) !== "archived") throw conflict("Only archived applications can be purged");
    const platforms = await this.listAllPlatforms(identifier);
    const clients = await this.listAllClients(identifier);
    const externalIdentities = await this.listAllExternalIdentities(identifier);
    const now = new Date();
    const version = nextVersion(current.version);
    const result = {
      ...current,
      status: "purged",
      lifecycleStatus: "purged",
      readiness: "not_ready",
      effectiveStatus: "purged",
      purgedAt: now,
      updatedAt: now,
      version,
      etag: `application:${identifier}:${String(version)}`,
    } as ApplicationRecord;
    return this.auditedWrite(
      async (executor) => {
        const values: unknown[] = [];
        const clauses: string[] = [];
        this.addTenantClause("applications", values, clauses);
        values.push(identifier);
        clauses.push(`${this.quote(this.columns.applications.id)} = $${values.length}`);
         for (const platform of platforms.items) await this.deletePlatformRow(platform.id, executor);
         for (const client of clients.items) await this.deleteClientRow(client.id, executor);
         await this.deleteExternalIdentityRows(identifier, executor);
         const count = await this.queryAffected(`DELETE FROM ${this.applicationsTable()}${whereText(clauses)}`, values, executor);

        if (count !== 1) throw notFound("Application not found");
        return { result, applied: true };
      },
       this.auditEvent("application.purged", identifier, context, { platformCount: platforms.total, clientCount: clients.total, externalIdentityCount: externalIdentities.length }),

      async (executor) => {
        await this.restoreApplicationRow(identifier, current, executor);
         for (const platform of platforms.items) await this.restorePlatformRow(platform, executor);
         for (const client of clients.items) await this.restoreClientRow(client, executor);
         await this.restoreExternalIdentityRows(externalIdentities, executor);
       },

    );
  }

  async deleteApplication(
    id: string,
    context: ApplicationWriteContext = {},
  ): Promise<ApplicationRecord> {
    const identifier = parseApplicationIdentifier(id);
    const current = await this.requireApplication(identifier);
     const platforms = await this.listAllPlatforms(identifier);
     const clients = await this.listAllClients(identifier);
     const externalIdentities = await this.listAllExternalIdentities(identifier);

    return this.auditedWrite(
      async (executor) => {
        const values: unknown[] = [];
        const clauses: string[] = [];
        this.addTenantClause("applications", values, clauses);
        values.push(identifier);
        clauses.push(`${this.quote(this.columns.applications.id)} = $${values.length}`);
        for (const platform of platforms.items) {
          await this.deletePlatformRow(platform.id, executor);
        }
         for (const client of clients.items) {
           await this.deleteClientRow(client.id, executor);
         }
         await this.deleteExternalIdentityRows(identifier, executor);
         const count = await this.queryAffected(

          `DELETE FROM ${this.applicationsTable()}${whereText(clauses)}`,
          values,
          executor,
        );
        if (count !== 1) throw notFound("Application not found");
        return { result: current, applied: true };
      },
       this.auditEvent("application.deleted", identifier, context, { platformCount: platforms.total, clientCount: clients.total, externalIdentityCount: externalIdentities.length }),

      async (executor) => {
        await this.restoreApplicationRow(identifier, current, executor);
         for (const platform of platforms.items) await this.restorePlatformRow(platform, executor);
         for (const client of clients.items) await this.restoreClientRow(client, executor);
         await this.restoreExternalIdentityRows(externalIdentities, executor);
       },

    );
  }

  async listPlatforms(
    applicationId: string,
    query: ApplicationPlatformListQuery | NormalizedApplicationPlatformQuery = {},
  ): Promise<ApplicationPage<ApplicationPlatformRecord>> {
    const appId = parseApplicationIdentifier(applicationId);
    const normalized = parseApplicationPlatformListQuery(query);
    const where = this.platformWhere(appId, normalized);
    const total = await this.count(
      `SELECT COUNT(*)::int AS "total" FROM ${this.platformsTable()}${where.text}`,
      where.values,
    );
    const scope = platformScope(appId, normalized);
    const keyset = normalized.cursor === undefined ? undefined : decodeApplicationKeysetCursor(normalized.cursor, `platforms:${appId}`, scope, this.tenantId);
    if (keyset !== undefined) this.addKeysetClause("platforms", keyset.id, where.values, where.clauses);
    const text = whereText(where.clauses);
    const offset = keyset === undefined ? cursorOffset(`platforms:${appId}`, scope, normalized.cursor, normalized.offset) : 0;
    const order = keyset === undefined ? this.quote(this.columns.platforms.id) : `${this.quote(this.columns.platforms.tenantId)}, ${this.quote(this.columns.platforms.id)}`;
    const rows = await this.queryRows(
      `SELECT ${this.select(this.columns.platforms, PLATFORM_FIELDS)} FROM ${this.platformsTable()}${text} ORDER BY ${order} ASC LIMIT $${where.values.length + 1}${keyset === undefined ? ` OFFSET $${where.values.length + 2}` : ""}`,
      [...where.values, keyset === undefined ? normalized.limit : normalized.limit + 1, ...(keyset === undefined ? [offset] : [])],
    );
    const mapped = rows.slice(0, normalized.limit).map((row) => this.mapPlatform(row)).filter((record) => this.belongs(record));
    const items = this.secretBindings === undefined ? mapped : await Promise.all(mapped.map((record) => this.enrichPlatform(record)));
    const hasMore = keyset === undefined ? offset + rows.length < total : rows.length > normalized.limit;
    return this.page(`platforms:${appId}`, normalized, items, total, scope, keyset !== undefined, hasMore);
  }

  async getPlatform(applicationId: string, id: string): Promise<ApplicationPlatformRecord | undefined> {
    const appId = parseApplicationIdentifier(applicationId);
    const platformId = parseApplicationPlatformIdentifier(id);
    const values: unknown[] = [];
    const clauses: string[] = [];
    this.addTenantClause("platforms", values, clauses);
    values.push(platformId, appId);
    clauses.push(`${this.quote(this.columns.platforms.id)} = $${values.length - 1}`);
    clauses.push(`${this.quote(this.columns.platforms.applicationId)} = $${values.length}`);
    const rows = await this.queryRows(
      `SELECT ${this.select(this.columns.platforms, PLATFORM_FIELDS)} FROM ${this.platformsTable()}${whereText(clauses)} LIMIT 1`,
      values,
    );
    if (rows[0] === undefined) return undefined;
    const platform = this.mapPlatform(rows[0]);
    if (!this.belongs(platform)) return undefined;
    return this.secretBindings === undefined ? platform : this.enrichPlatform(platform);
  }

  async createPlatform(
    applicationId: string,
    input: ApplicationPlatformCreateRequest & { id?: string },
    context: ApplicationWriteContext = {},
  ): Promise<ApplicationPlatformRecord> {
    const appId = parseApplicationIdentifier(applicationId);
    await this.requireApplication(appId);
    const id = input.id ?? randomUUID();
    const now = new Date();
    const values: ApplicationPlatformRecord = {
      id,
      applicationId: appId,
      tenantId: this.tenantId,
      type: input.type,
      externalAppId: input.externalAppId ?? null,
      displayName: input.displayName ?? null,
      loginMode: input.loginMode ?? null,
      scope: input.scope ?? null,
      redirectUris: input.redirectUris ?? [],
       endpointUrl: input.endpointUrl ?? null,
       secretRef: this.secretBindings === undefined ? input.secretRef ?? null : null,
       ...platformComponentSqlValues(input),
       lifecycleStatus: "active",

      readiness: input.secretRef === undefined ? "not_ready" : "ready",
      effectiveStatus: input.secretRef === undefined ? "not_ready" : "active",
      version: 1,
      etag: `application-platform:${id}:1`,
      secretVersion: input.secretRef === undefined ? 0 : 1,
      status: "active",
      createdAt: now,
      updatedAt: now,
      enabledAt: now,
      disabledAt: null,
      archivedAt: null,
      purgedAt: null,
     };
     if (this.secretBindings !== undefined) stripSqlComponentSecrets(values);
     return this.auditedWrite(
       async (executor) => {
         const row = await this.insertRecord(
           this.columns.platforms,

          PLATFORM_FIELDS,
          values,
          this.platformsTable(),
          executor,
        );
        return { result: row === undefined ? values : this.mapPlatform(row), applied: true };
      },
      this.auditEvent("application-platform.created", id, context, { applicationId: appId, type: input.type }),
      async (executor) => this.deletePlatformRow(id, executor),
    );
  }

  async updatePlatform(
    applicationId: string,
    id: string,
    input: ApplicationPlatformMutationRequest & { id?: string },
    context: ApplicationWriteContext = {},
  ): Promise<ApplicationPlatformRecord> {
    const appId = parseApplicationIdentifier(applicationId);
    const platformId = parseApplicationPlatformIdentifier(id);
    const current = await this.requirePlatform(appId, platformId);
     const values = platformInputValues(input);
     if (this.secretBindings !== undefined) {
       if (input.secretRef !== undefined) values.secretRef = null;
       stripSqlComponentSecrets(values);
     }

    const version = nextVersion(current.version);
    values.updatedAt = new Date();
    values.version = version;
    values.etag = `application-platform:${platformId}:${String(version)}`;
    if (input.secretRef !== undefined) values.secretVersion = nextVersion(current.secretVersion);
    const updated = { ...current, ...values } as ApplicationPlatformRecord;
    updated.readiness = readinessForRecord(updated);
    updated.effectiveStatus = effectiveStatusForRecord(updated);
    values.readiness = updated.readiness;
    values.effectiveStatus = updated.effectiveStatus;
    return this.auditedWrite(
      async (executor) => {
        const row = await this.updateRecord(
          "platforms",
          this.columns.platforms,
          PLATFORM_FIELDS,
          this.platformsTable(),
          platformId,
          values,
          executor,
          undefined,
          undefined,
          appId,
          currentVersion(current),
        );
        if (row === undefined) throw notFound("Application platform not found");
        return { result: this.mapPlatform(row), applied: true };
      },
      this.auditEvent("application-platform.updated", platformId, context, { applicationId: appId, fields: Object.keys(values).filter((field) => field !== "updatedAt" && field !== "secretRef") }),
      async (executor) => this.restorePlatformRow(current, executor),
    );
  }

  async setPlatformStatus(
    applicationId: string,
    id: string,
    status: ApplicationStatus,
    context: ApplicationWriteContext = {},
  ): Promise<ApplicationPlatformRecord> {
    const appId = parseApplicationIdentifier(applicationId);
    const platformId = parseApplicationPlatformIdentifier(id);
    const current = await this.requirePlatform(appId, platformId);
    if (status !== "active" && status !== "disabled") throw invalidRequest("Invalid platform status");
    const currentStatus = lifecycleStatusOf(current);
    if (currentStatus === "archived" || currentStatus === "purged") throw conflict("Platform is archived or purged");
    if (currentStatus === status) throw conflict("Platform is already in the requested state");
    const now = new Date();
    const version = nextVersion(current.version);
    const updated = { ...current, status, lifecycleStatus: status, version, etag: `application-platform:${platformId}:${String(version)}`, updatedAt: now } as ApplicationPlatformRecord;
    updated.readiness = readinessForRecord(updated);
    updated.effectiveStatus = effectiveStatusForRecord(updated);
    if (status === "active") {
      updated.enabledAt = now;
      updated.disabledAt = null;
    } else {
      updated.disabledAt = now;
      updated.enabledAt = null;
    }
    return this.auditedWrite(
      async (executor) => {
        const row = await this.updateRecord(
          "platforms",
          this.columns.platforms,
          PLATFORM_FIELDS,
          this.platformsTable(),
          platformId,
          { status, lifecycleStatus: status, version, etag: updated.etag, readiness: updated.readiness, effectiveStatus: updated.effectiveStatus, updatedAt: now, enabledAt: updated.enabledAt, disabledAt: updated.disabledAt },
          executor,
          normalizeStatus(current.status),
          "status",
          appId,
          currentVersion(current),
        );
        if (row === undefined) throw conflict("Platform state changed");
        return { result: this.mapPlatform(row), applied: true };
      },
      this.auditEvent(status === "active" ? "application-platform.enabled" : "application-platform.disabled", platformId, context, { applicationId: appId, status }),
      async (executor) => this.restorePlatformRow(current, executor),
    );
  }

  async archivePlatform(
    applicationId: string,
    id: string,
    context: ApplicationWriteContext = {},
  ): Promise<ApplicationPlatformRecord> {
    const appId = parseApplicationIdentifier(applicationId);
    const platformId = parseApplicationPlatformIdentifier(id);
    const current = await this.requirePlatform(appId, platformId);
    const currentStatus = lifecycleStatusOf(current);
    if (currentStatus === "archived" || currentStatus === "purged") throw conflict("Platform is already archived or purged");
    const now = new Date();
    const version = nextVersion(current.version);
    const values = {
      status: "archived",
      lifecycleStatus: "archived",
      previousStatus: currentStatus,
      readiness: "not_ready",
      effectiveStatus: "archived",
      archivedAt: now,
      updatedAt: now,
      version,
      etag: `application-platform:${platformId}:${String(version)}`,
    } as Record<string, unknown>;
    return this.auditedWrite(
      async (executor) => {
        const row = await this.updateRecord(
          "platforms",
          this.columns.platforms,
          PLATFORM_FIELDS,
          this.platformsTable(),
          platformId,
          values,
          executor,
          currentStatus,
          "status",
          appId,
          currentVersion(current),
        );
        if (row === undefined) throw conflict("Platform state changed");
        return { result: this.mapPlatform(row), applied: true };
      },
      this.auditEvent("application-platform.archived", platformId, context, { applicationId: appId }),
      async (executor) => this.restorePlatformRow(current, executor),
    );
  }

  async restorePlatform(
    applicationId: string,
    id: string,
    context: ApplicationWriteContext = {},
  ): Promise<ApplicationPlatformRecord> {
    const appId = parseApplicationIdentifier(applicationId);
    const platformId = parseApplicationPlatformIdentifier(id);
    const current = await this.requirePlatform(appId, platformId);
    if (lifecycleStatusOf(current) !== "archived") throw conflict("Only archived platforms can be restored");
    const restoredStatus = current.previousStatus === "disabled" ? "disabled" : "active";
    const now = new Date();
    const version = nextVersion(current.version);
    const values = {
      status: restoredStatus,
      lifecycleStatus: restoredStatus,
      previousStatus: null,
      readiness: restoredStatus === "active" ? "ready" : "not_ready",
      effectiveStatus: restoredStatus,
      archivedAt: null,
      updatedAt: now,
      version,
      etag: `application-platform:${platformId}:${String(version)}`,
    } as Record<string, unknown>;
    return this.auditedWrite(
      async (executor) => {
        const row = await this.updateRecord(
          "platforms",
          this.columns.platforms,
          PLATFORM_FIELDS,
          this.platformsTable(),
          platformId,
          values,
          executor,
          "archived",
          "status",
          appId,
          currentVersion(current),
        );
        if (row === undefined) throw conflict("Platform state changed");
        return { result: this.mapPlatform(row), applied: true };
      },
      this.auditEvent("application-platform.restored", platformId, context, { applicationId: appId }),
      async (executor) => this.restorePlatformRow(current, executor),
    );
  }

  async purgePlatform(
    applicationId: string,
    id: string,
    context: ApplicationWriteContext = {},
  ): Promise<ApplicationPlatformRecord> {
    const appId = parseApplicationIdentifier(applicationId);
    const platformId = parseApplicationPlatformIdentifier(id);
    const current = await this.requirePlatform(appId, platformId);
    if (lifecycleStatusOf(current) !== "archived") throw conflict("Only archived platforms can be purged");
    return this.auditedWrite(
      async (executor) => {
        await this.deletePlatformRow(platformId, executor, appId);
        return { result: current, applied: true };
      },
      this.auditEvent("application-platform.purged", platformId, context, { applicationId: appId }),
      async (executor) => this.restorePlatformRow(current, executor),
    );
  }

  async deletePlatform(
    applicationId: string,
    id: string,
    context: ApplicationWriteContext = {},
  ): Promise<ApplicationPlatformRecord> {
    const appId = parseApplicationIdentifier(applicationId);
    const platformId = parseApplicationPlatformIdentifier(id);
    const current = await this.requirePlatform(appId, platformId);
    return this.auditedWrite(
      async (executor) => {
        await this.deletePlatformRow(platformId, executor, appId);
        return { result: current, applied: true };
      },
      this.auditEvent("application-platform.deleted", platformId, context, { applicationId: appId }),
      async (executor) => this.restorePlatformRow(current, executor),
    );
  }

  async listClients(
    applicationId: string,
    query: ApplicationClientListQuery | NormalizedApplicationClientQuery = {},
  ): Promise<ApplicationPage<ApplicationClientRecord>> {
    const appId = parseApplicationIdentifier(applicationId);
    const normalized = parseApplicationClientListQuery(query);
    const where = this.clientWhere(appId, normalized);
    const total = await this.count(
      `SELECT COUNT(*)::int AS "total" FROM ${this.clientsTable()}${where.text}`,
      where.values,
    );
    const scope = clientScope(appId, normalized);
    const keyset = normalized.cursor === undefined ? undefined : decodeApplicationKeysetCursor(normalized.cursor, `clients:${appId}`, scope, this.tenantId);
    if (keyset !== undefined) this.addKeysetClause("clients", keyset.id, where.values, where.clauses);
    const text = whereText(where.clauses);
    const offset = keyset === undefined ? cursorOffset(`clients:${appId}`, scope, normalized.cursor, normalized.offset) : 0;
    const order = keyset === undefined ? this.quote(this.columns.clients.id) : `${this.quote(this.columns.clients.tenantId)}, ${this.quote(this.columns.clients.id)}`;
    const rows = await this.queryRows(
      `SELECT ${this.select(this.columns.clients, CLIENT_FIELDS)} FROM ${this.clientsTable()}${text} ORDER BY ${order} ASC LIMIT $${where.values.length + 1}${keyset === undefined ? ` OFFSET $${where.values.length + 2}` : ""}`,
      [...where.values, keyset === undefined ? normalized.limit : normalized.limit + 1, ...(keyset === undefined ? [offset] : [])],
    );
    const mapped = rows.slice(0, normalized.limit).map((row) => this.mapClient(row)).filter((record) => this.belongs(record));
    const items = this.secretBindings === undefined ? mapped : await Promise.all(mapped.map((record) => this.enrichClient(record)));
    const hasMore = keyset === undefined ? offset + rows.length < total : rows.length > normalized.limit;
    return this.page(`clients:${appId}`, normalized, items, total, scope, keyset !== undefined, hasMore);
  }

  async getClient(applicationId: string, id: string): Promise<ApplicationClientRecord | undefined> {
    const appId = parseApplicationIdentifier(applicationId);
    const clientRecordId = parseApplicationClientIdentifier(id);
    const directValues: unknown[] = [];
    const directClauses: string[] = [];
    this.addTenantClause("clients", directValues, directClauses);
    directValues.push(clientRecordId);
    directClauses.push(`${this.quote(this.columns.clients.id)} = $${directValues.length}`);
    const directRows = await this.queryRows(
      `SELECT ${this.select(this.columns.clients, CLIENT_FIELDS)} FROM ${this.clientsTable()}${whereText(directClauses)} LIMIT 1`,
      directValues,
    );
    if (directRows[0] !== undefined) {
      const direct = this.mapClient(directRows[0]);
      if (direct.applicationId !== appId || !this.belongs(direct)) return undefined;
      return this.secretBindings === undefined ? direct : this.enrichClient(direct);
    }
    const fallbackValues: unknown[] = [];
    const fallbackClauses: string[] = [];
    this.addTenantClause("clients", fallbackValues, fallbackClauses);
    fallbackValues.push(clientRecordId, appId);
    fallbackClauses.push(`${this.quote(this.columns.clients.clientId)} = $${fallbackValues.length - 1}`);
    fallbackClauses.push(`${this.quote(this.columns.clients.applicationId)} = $${fallbackValues.length}`);
    const fallbackRows = await this.queryRows(
      `SELECT ${this.select(this.columns.clients, CLIENT_FIELDS)} FROM ${this.clientsTable()}${whereText(fallbackClauses)} LIMIT 1`,
      fallbackValues,
    );
    if (fallbackRows[0] === undefined) return undefined;
    const fallbackClient = this.mapClient(fallbackRows[0]);
    if (!this.belongs(fallbackClient)) return undefined;
    return this.secretBindings === undefined ? fallbackClient : this.enrichClient(fallbackClient);
  }

  async listExternalIdentities(
    applicationId: string,
    query: ApplicationExternalIdentityListQuery | NormalizedApplicationExternalIdentityQuery = {},
  ): Promise<ApplicationPage<ApplicationExternalIdentityRecord>> {
    const appId = parseApplicationIdentifier(applicationId);
    const normalized = parseApplicationExternalIdentityListQuery(query);
    const scope = externalIdentityScope(appId, normalized);
    const where = this.externalIdentityWhere(appId, normalized);
    const countRows = await this.queryRows(`SELECT COUNT(*)::int AS "total" FROM ${this.externalIdentitiesTable()}${where.text}`, where.values);
    const total = readCount(countRows[0]?.total);
    const keyset = normalized.cursor === undefined ? undefined : decodeApplicationKeysetCursor(normalized.cursor, `external-identities:${appId}`, scope, this.tenantId);
    if (keyset !== undefined) this.addKeysetClause("externalIdentities", keyset.id, where.values, where.clauses);
    const text = whereText(where.clauses);
    const offset = keyset === undefined ? cursorOffset(`external-identities:${appId}`, scope, normalized.cursor, normalized.offset) : 0;
    const rows = await this.queryRows(
      `SELECT ${this.select(this.columns.externalIdentities, EXTERNAL_IDENTITY_FIELDS as readonly string[])} FROM ${this.externalIdentitiesTable()}${text} ORDER BY ${this.quote(this.columns.externalIdentities.tenantId)}, ${this.quote(this.columns.externalIdentities.id)} ASC LIMIT $${where.values.length + 1}${keyset === undefined ? ` OFFSET $${where.values.length + 2}` : ""}`,
      [...where.values, normalized.limit + 1, ...(keyset === undefined ? [offset] : [])],
    );
    const items = rows.slice(0, normalized.limit).map((row) => this.mapExternalIdentity(row)).filter((record) => this.belongs(record));
    const hasMore = keyset === undefined ? offset + rows.length < total : rows.length > normalized.limit;
    const page: ApplicationPage<ApplicationExternalIdentityRecord> = { items, total, hasMore };
    if (hasMore && items.length > 0) {
      page.nextCursor = encodeApplicationKeysetCursor({
        version: CURSOR_VERSION,
        kind: `external-identities:${appId}`,
        scope,
        tenantId: this.tenantId,
        id: items[items.length - 1].id,
      });
    }
    return page;
  }

  async upsertExternalIdentity(
    applicationId: string,
    input: ApplicationExternalIdentityUpsertInput,
    context: ApplicationWriteContext = {},
  ): Promise<ApplicationExternalIdentityRecord> {
    const appId = parseApplicationIdentifier(applicationId);
    await this.requireApplication(appId);
    const provider = requiredExternalText(input.provider, "provider", 128);
    const subject = requiredExternalText(input.subject, "subject", 1024);
    const platformId = optionalExternalText(input.platformId, "platform id", 512);
    const requestedPlatform = optionalExternalText(input.platform ?? platformId, "platform", 128) ?? "";
    const requestedProviderAppId = optionalExternalText(input.appId ?? input.externalAppId, "provider app id", 512) ?? "";
    const previous = await this.findExternalIdentityForUpsert(appId, provider, subject, requestedPlatform, requestedProviderAppId);
    const platform = requestedPlatform || (typeof previous?.platform === "string" ? previous.platform : typeof previous?.platformId === "string" ? previous.platformId : "");
    const providerAppId = requestedProviderAppId || (typeof previous?.providerAppId === "string" ? previous.providerAppId : typeof previous?.appId === "string" ? previous.appId : typeof previous?.externalAppId === "string" ? previous.externalAppId : "");
    const canonical = externalIdentityCanonicalKey({
      tenantId: this.tenantId,
      applicationId: appId,
      provider,
      platform,
      providerAppId,
      subject,
    });
    const now = new Date();
    const values: unknown[] = [
      randomUUID(),
      this.tenantId,
      appId,
      platformId ?? previous?.platformId ?? null,
      platform,
      provider,
      providerAppId,
      subject,
      optionalExternalText(input.externalAppId ?? input.appId, "external app id", 512) ?? previous?.externalAppId ?? null,
      optionalExternalText(input.openid, "openid", 1024) ?? previous?.openid ?? null,
      optionalExternalText(input.unionid, "unionid", 1024) ?? previous?.unionid ?? null,
      optionalExternalText(input.nickname, "nickname", 256) ?? previous?.nickname ?? null,
      optionalExternalText(input.displayName, "display name", 256) ?? previous?.displayName ?? null,
      optionalExternalText(input.email, "email", 320) ?? previous?.email ?? null,
      optionalExternalText(input.avatarUrl, "avatar url", 2048) ?? previous?.avatarUrl ?? null,
       JSON.stringify(normalizeExternalScopes(input.scopes ?? previous?.scopes)),
       optionalExternalText(input.canonicalUserId, "canonical user id", 512) ?? previous?.canonicalUserId ?? null,
       optionalExternalText(input.linkStatus, "link status", 32) ?? previous?.linkStatus ?? "linked",
       typeof input.emailVerified === "boolean" ? input.emailVerified : previous?.emailVerified ?? false,
       previous?.firstLinkedAt ?? previous?.linkedAt ?? now,
      previous?.linkedAt ?? previous?.firstLinkedAt ?? now,
      now,
      now,
    ];
    const fields = [
      "id",
      "tenantId",
      "applicationId",
      "platformId",
      "platform",
      "provider",
      "providerAppId",
      "subject",
      "externalAppId",
      "openid",
      "unionid",
      "nickname",
      "displayName",
      "email",
  "avatarUrl",
  "scopes",
  "canonicalUserId",
  "linkStatus",
  "emailVerified",
  "firstLinkedAt",
      "linkedAt",
      "lastAuthenticatedAt",
      "updatedAt",
    ];
    const columns = fields.map((field) => this.quote(this.columns.externalIdentities[field as keyof ApplicationSqlExternalIdentityColumns]));
    const updates = fields
      .filter((field) => !["id", "tenantId", "applicationId", "platform", "provider", "providerAppId", "subject", "firstLinkedAt", "linkedAt", "createdAt"].includes(field))
      .map((field) => `${this.quote(this.columns.externalIdentities[field as keyof ApplicationSqlExternalIdentityColumns])} = EXCLUDED.${this.quote(this.columns.externalIdentities[field as keyof ApplicationSqlExternalIdentityColumns])}`);
    updates.push(`${this.quote(this.columns.externalIdentities.version)} = ${this.quote("__idaas_identity_target")}.${this.quote(this.columns.externalIdentities.version)} + 1`);
    const audit = this.auditEvent("application.external_identity.upserted", appId, context, {
      provider,
      platform,
      providerAppId,
      subject,
      canonicalKey: canonical.key,
    });
    return this.auditedWrite(
      async (executor) => {
        const rows = await this.queryRows(
          `INSERT INTO ${this.externalIdentitiesTable()} AS ${this.quote("__idaas_identity_target")} (${columns.join(", ")}) VALUES (${values.map((_value, index) => `$${index + 1}`).join(", ")}) ON CONFLICT (${[
            this.quote(this.columns.externalIdentities.tenantId),
            this.quote(this.columns.externalIdentities.applicationId),
            this.quote(this.columns.externalIdentities.provider),
            this.quote(this.columns.externalIdentities.platform),
            this.quote(this.columns.externalIdentities.providerAppId),
            this.quote(this.columns.externalIdentities.subject),
          ].join(", ")}) DO UPDATE SET ${updates.join(", ")} RETURNING ${this.select(this.columns.externalIdentities, EXTERNAL_IDENTITY_FIELDS as readonly string[])}`,
          values,
          executor,
        );
        if (rows[0] === undefined) throw new Error("External identity upsert failed");
        return { result: this.mapExternalIdentity(rows[0]), applied: true };
      },
      audit,
      async (executor) => {
        if (previous === undefined) {
          await this.deleteExternalIdentityByCanonical(canonical, executor);
          return;
        }
        await this.restoreExternalIdentityRows([previous], executor);
      },
    );
  }

  async findClientByClientId(clientId: string): Promise<ApplicationClientRecord | undefined> {
    const identifier = parseApplicationClientIdentifier(clientId, "oidcClientId");
    const values: unknown[] = [];
    const clauses: string[] = [];
    this.addTenantClause("clients", values, clauses);
    values.push(identifier);
    clauses.push(`LOWER(${this.quote(this.columns.clients.clientId)}) = LOWER($${values.length})`);
    const rows = await this.queryRows(
      `SELECT ${this.select(this.columns.clients, CLIENT_FIELDS)} FROM ${this.clientsTable()}${whereText(clauses)} ORDER BY ${this.quote(this.columns.clients.id)} ASC LIMIT 1`,
      values,
    );
    if (rows[0] === undefined) return undefined;
    const client = this.mapClient(rows[0]);
    if (!this.belongs(client)) return undefined;
    return this.secretBindings === undefined ? client : this.enrichClient(client);
  }

  async createClient(
    applicationId: string,
    input: ApplicationClientCreateRequest & { id?: string },
    context: ApplicationWriteContext = {},
  ): Promise<ApplicationClientRecord> {
    const appId = parseApplicationIdentifier(applicationId);
    const application = await this.requireApplication(appId);
    await this.assertClientIdAvailable(this.activeExecutor(), input.clientId);
    const defaultClientKind = application.applicationType === "native" ? "native" : "web";
    const id = input.id ?? randomUUID();
    const clientIdScope = input.clientIdScope ?? "global";
    if (clientIdScope !== "global") throw invalidRequest("OIDC clientIdScope must be global");
    const now = new Date();
    const values: ApplicationClientRecord = {
      id,
      applicationId: appId,
      tenantId: this.tenantId,
       clientId: input.clientId,
       clientIdScope,
       clientKind: input.clientKind ?? input.clientType ?? defaultClientKind,
       clientType: input.clientType ?? input.clientKind ?? defaultClientKind,
       ...(input.redirectUriPolicy === undefined ? {} : { redirectUriPolicy: input.redirectUriPolicy }),
       ...(input.pkceMethod === undefined ? {} : { pkceMethod: input.pkceMethod }),
       ...(input.consentRequired === undefined ? {} : { consentRequired: input.consentRequired }),
       ...(input.requireExplicitConsent === undefined ? {} : { requireExplicitConsent: input.requireExplicitConsent }),
       status: "active",

      redirectUris: input.redirectUris ?? [],
      postLogoutRedirectUris: input.postLogoutRedirectUris ?? [],
      grantTypes: input.grantTypes ?? ["authorization_code"],
      responseTypes: input.responseTypes ?? ["code"],
      scopes: input.scopes ?? ["openid", "profile", "email"],
      tokenEndpointAuthMethod: input.tokenEndpointAuthMethod ?? "client_secret_basic",
      tokenEndpointAuthSigningAlg: input.tokenEndpointAuthSigningAlg ?? null,
      jwksUri: input.jwksUri ?? null,
      privateKeyRef: input.privateKeyRef ?? null,
      keyId: input.keyId ?? null,
      requirePkce: input.requirePkce ?? true,
      secretRef: this.secretBindings === undefined ? input.secretRef ?? null : null,
      lifecycleStatus: "active",
      readiness: input.secretRef === undefined && input.tokenEndpointAuthMethod !== "private_key_jwt" && input.tokenEndpointAuthMethod !== "none" ? "not_ready" : "ready",
      effectiveStatus: input.secretRef !== undefined || input.tokenEndpointAuthMethod === "private_key_jwt" || input.tokenEndpointAuthMethod === "none" ? "active" : "not_ready",
      version: 1,
      etag: `application-client:${id}:1`,
      secretVersion: input.secretRef === undefined ? 0 : 1,
      createdAt: now,
      updatedAt: now,
      enabledAt: now,
      disabledAt: null,
      archivedAt: null,
      purgedAt: null,
    };
    return this.auditedWrite(
      async (executor) => {
        const row = await this.insertRecord(
          this.columns.clients,
          CLIENT_FIELDS,
          values,
          this.clientsTable(),
          executor,
        );
        return { result: row === undefined ? values : this.mapClient(row), applied: true };
      },
      this.auditEvent("application-client.created", id, context, { applicationId: appId, clientId: input.clientId }),
      async (executor) => this.deleteClientRow(id, executor),
    );
  }

  async updateClient(
    applicationId: string,
    id: string,
    input: ApplicationClientMutationRequest & { id?: string },
    context: ApplicationWriteContext = {},
  ): Promise<ApplicationClientRecord> {
    const appId = parseApplicationIdentifier(applicationId);
    const clientRecordId = parseApplicationClientIdentifier(id);
    const current = await this.requireClient(appId, clientRecordId);
    const storedId = current.id;
    if (input.clientId !== undefined && input.clientId !== current.clientId) {
      await this.assertClientIdAvailable(this.activeExecutor(), input.clientId, storedId);
    }
    const values = clientInputValues(input);
    if (this.secretBindings !== undefined && input.secretRef !== undefined) values.secretRef = null;
    const version = nextVersion(current.version);
    values.updatedAt = new Date();
    values.version = version;
    values.etag = `application-client:${storedId}:${String(version)}`;
    if (input.secretRef !== undefined) values.secretVersion = nextVersion(current.secretVersion);
    const updated = { ...current, ...values } as ApplicationClientRecord;
    updated.readiness = readinessForRecord(updated);
    updated.effectiveStatus = effectiveStatusForRecord(updated);
    values.readiness = updated.readiness;
    values.effectiveStatus = updated.effectiveStatus;
    return this.auditedWrite(
      async (executor) => {
        const row = await this.updateRecord(
          "clients",
          this.columns.clients,
          CLIENT_FIELDS,
          this.clientsTable(),
          storedId,
          values,
          executor,
          undefined,
          undefined,
          appId,
          currentVersion(current),
        );
        if (row === undefined) throw notFound("OIDC client not found");
        return { result: this.mapApplicationClientRow(row), applied: true };
      },
      this.auditEvent("application-client.updated", storedId, context, { applicationId: appId, fields: Object.keys(values).filter((field) => field !== "updatedAt" && field !== "secretRef") }),
      async (executor) => this.restoreClientRow(current, executor),
    );
  }

  async rotateClientSecret(
    applicationId: string,
    id: string,
    input: ApplicationClientRotateSecretRequest,
    context: ApplicationWriteContext = {},
  ): Promise<ApplicationClientRecord> {
    const appId = parseApplicationIdentifier(applicationId);
    const clientRecordId = parseApplicationClientIdentifier(id);
    const current = await this.requireClient(appId, clientRecordId);
    if (input.secretRef === undefined || input.secretRef.length === 0) throw invalidRequest("A new secretRef is required");
    const version = nextVersion(current.version);
    const secretVersion = nextVersion(current.secretVersion);
    const updated = {
      ...current,
      secretRef: this.secretBindings === undefined ? input.secretRef : null,
      secretVersion,
      version,
      etag: `application-client:${current.id}:${String(version)}`,
      updatedAt: new Date(),
    } as ApplicationClientRecord;
    updated.readiness = readinessForRecord(updated);
    updated.effectiveStatus = effectiveStatusForRecord(updated);
    return this.auditedWrite(
      async (executor) => {
        const row = await this.updateRecord(
          "clients",
          this.columns.clients,
          CLIENT_FIELDS,
          this.clientsTable(),
          current.id,
          {
            secretRef: this.secretBindings === undefined ? input.secretRef : null,
            secretVersion,
            version,
            etag: updated.etag,
            readiness: updated.readiness,
            effectiveStatus: updated.effectiveStatus,
            updatedAt: updated.updatedAt,
          },
          executor,
          undefined,
          undefined,
          appId,
          input.expectedVersion === undefined ? currentVersion(current) : Number(input.expectedVersion),
        );
        if (row === undefined) throw conflict("OIDC client state changed");
        return { result: this.mapClient(row), applied: true };
      },
      this.auditEvent("application-client.secret-rotated", current.id, context, { applicationId: appId, secretVersion }),
      async (executor) => this.restoreClientRow(current, executor),
    );
  }

  async rotateApplicationClientSecret(
    applicationId: string,
    id: string,
    input: ApplicationClientRotateSecretRequest,
    context?: ApplicationWriteContext,
  ): Promise<ApplicationClientRecord> {
    return this.rotateClientSecret(applicationId, id, input, context);
  }

  async setClientStatus(
    applicationId: string,
    id: string,
    status: ApplicationClientStatus,
    context: ApplicationWriteContext = {},
  ): Promise<ApplicationClientRecord> {
    const appId = parseApplicationIdentifier(applicationId);
    const clientRecordId = parseApplicationClientIdentifier(id);
    const current = await this.requireClient(appId, clientRecordId);
    const storedId = current.id;
    if (status !== "active" && status !== "disabled") throw invalidRequest("Invalid OIDC client status");
    const currentStatus = lifecycleStatusOf(current);
    if (currentStatus === "archived" || currentStatus === "purged") throw conflict("OIDC client is archived or purged");
    if (currentStatus === status) throw conflict("OIDC client is already in the requested state");
    const now = new Date();
    const version = nextVersion(current.version);
    const updated = { ...current, status, lifecycleStatus: status, version, etag: `application-client:${storedId}:${String(version)}`, updatedAt: now } as ApplicationClientRecord;
    updated.readiness = readinessForRecord(updated);
    updated.effectiveStatus = effectiveStatusForRecord(updated);
    if (status === "active") {
      updated.enabledAt = now;
      updated.disabledAt = null;
    } else {
      updated.disabledAt = now;
      updated.enabledAt = null;
    }
    return this.auditedWrite(
      async (executor) => {
        const row = await this.updateRecord(
          "clients",
          this.columns.clients,
          CLIENT_FIELDS,
          this.clientsTable(),
          storedId,
          { status, lifecycleStatus: status, version, etag: updated.etag, readiness: updated.readiness, effectiveStatus: updated.effectiveStatus, updatedAt: now, enabledAt: updated.enabledAt, disabledAt: updated.disabledAt },
          executor,
          normalizeStatus(current.status),
          "status",
          appId,
          currentVersion(current),
        );
        if (row === undefined) throw conflict("OIDC client state changed");
        return { result: this.mapClient(row), applied: true };
      },
      this.auditEvent(status === "active" ? "application-client.enabled" : "application-client.disabled", storedId, context, { applicationId: appId, status }),
      async (executor) => this.restoreClientRow(current, executor),
    );
  }

  async archiveClient(
    applicationId: string,
    id: string,
    context: ApplicationWriteContext = {},
  ): Promise<ApplicationClientRecord> {
    const appId = parseApplicationIdentifier(applicationId);
    const clientId = parseApplicationClientIdentifier(id);
    const current = await this.requireClient(appId, clientId);
    const currentStatus = lifecycleStatusOf(current);
    if (currentStatus === "archived" || currentStatus === "purged") throw conflict("OIDC client is already archived or purged");
    const now = new Date();
    const version = nextVersion(current.version);
    const values = {
      status: "archived",
      lifecycleStatus: "archived",
      previousStatus: currentStatus,
      readiness: "not_ready",
      effectiveStatus: "archived",
      archivedAt: now,
      updatedAt: now,
      version,
      etag: `application-client:${current.id}:${String(version)}`,
    } as Record<string, unknown>;
    return this.auditedWrite(
      async (executor) => {
        const row = await this.updateRecord(
          "clients",
          this.columns.clients,
          CLIENT_FIELDS,
          this.clientsTable(),
          current.id,
          values,
          executor,
          currentStatus,
          "status",
          appId,
          currentVersion(current),
        );
        if (row === undefined) throw conflict("OIDC client state changed");
        return { result: this.mapClient(row), applied: true };
      },
      this.auditEvent("application-client.archived", current.id, context, { applicationId: appId }),
      async (executor) => this.restoreClientRow(current, executor),
    );
  }

  async restoreClient(
    applicationId: string,
    id: string,
    context: ApplicationWriteContext = {},
  ): Promise<ApplicationClientRecord> {
    const appId = parseApplicationIdentifier(applicationId);
    const clientId = parseApplicationClientIdentifier(id);
    const current = await this.requireClient(appId, clientId);
    if (lifecycleStatusOf(current) !== "archived") throw conflict("Only archived OIDC clients can be restored");
    const restoredStatus = current.previousStatus === "disabled" ? "disabled" : "active";
    const now = new Date();
    const version = nextVersion(current.version);
    const values = {
      status: restoredStatus,
      lifecycleStatus: restoredStatus,
      previousStatus: null,
      readiness: restoredStatus === "active" ? "ready" : "not_ready",
      effectiveStatus: restoredStatus,
      archivedAt: null,
      updatedAt: now,
      version,
      etag: `application-client:${current.id}:${String(version)}`,
    } as Record<string, unknown>;
    return this.auditedWrite(
      async (executor) => {
        const row = await this.updateRecord(
          "clients",
          this.columns.clients,
          CLIENT_FIELDS,
          this.clientsTable(),
          current.id,
          values,
          executor,
          "archived",
          "status",
          appId,
          currentVersion(current),
        );
        if (row === undefined) throw conflict("OIDC client state changed");
        return { result: this.mapClient(row), applied: true };
      },
      this.auditEvent("application-client.restored", current.id, context, { applicationId: appId }),
      async (executor) => this.restoreClientRow(current, executor),
    );
  }

  async purgeClient(
    applicationId: string,
    id: string,
    context: ApplicationWriteContext = {},
  ): Promise<ApplicationClientRecord> {
    const appId = parseApplicationIdentifier(applicationId);
    const clientId = parseApplicationClientIdentifier(id);
    const current = await this.requireClient(appId, clientId);
    if (lifecycleStatusOf(current) !== "archived") throw conflict("Only archived OIDC clients can be purged");
    return this.auditedWrite(
      async (executor) => {
        await this.deleteClientRow(current.id, executor, appId);
        return { result: current, applied: true };
      },
      this.auditEvent("application-client.purged", current.id, context, { applicationId: appId }),
      async (executor) => this.restoreClientRow(current, executor),
    );
  }

  async deleteClient(
    applicationId: string,
    id: string,
    context: ApplicationWriteContext = {},
  ): Promise<ApplicationClientRecord> {
    const appId = parseApplicationIdentifier(applicationId);
    const clientRecordId = parseApplicationClientIdentifier(id);
    const current = await this.requireClient(appId, clientRecordId);
    return this.auditedWrite(
      async (executor) => {
        await this.deleteClientRow(current.id, executor, appId);
        return { result: current, applied: true };
      },
      this.auditEvent("application-client.deleted", current.id, context, { applicationId: appId, clientId: current.clientId }),
      async (executor) => this.restoreClientRow(current, executor),
    );
  }

  async enableApplication(id: string, context: ApplicationWriteContext = {}): Promise<ApplicationRecord> {
    return this.setApplicationStatus(id, "active", context);
  }

  async disableApplication(id: string, context: ApplicationWriteContext = {}): Promise<ApplicationRecord> {
    return this.setApplicationStatus(id, "disabled", context);
  }

  async enablePlatform(applicationId: string, id: string, context: ApplicationWriteContext = {}): Promise<ApplicationPlatformRecord> {
    return this.setPlatformStatus(applicationId, id, "active", context);
  }

  async disablePlatform(applicationId: string, id: string, context: ApplicationWriteContext = {}): Promise<ApplicationPlatformRecord> {
    return this.setPlatformStatus(applicationId, id, "disabled", context);
  }

  async enableClient(applicationId: string, id: string, context: ApplicationWriteContext = {}): Promise<ApplicationClientRecord> {
    return this.setClientStatus(applicationId, id, "active", context);
  }

  async disableClient(applicationId: string, id: string, context: ApplicationWriteContext = {}): Promise<ApplicationClientRecord> {
    return this.setClientStatus(applicationId, id, "disabled", context);
  }

  async listApplicationPlatforms(
    applicationId: string,
    query?: ApplicationPlatformListQuery | NormalizedApplicationPlatformQuery,
  ): Promise<ApplicationPage<ApplicationPlatformRecord>> {
    return this.listPlatforms(applicationId, query);
  }

  async listApplicationClients(
    applicationId: string,
    query?: ApplicationClientListQuery | NormalizedApplicationClientQuery,
  ): Promise<ApplicationPage<ApplicationClientRecord>> {
    return this.listClients(applicationId, query);
  }

  async listOidcClients(
    applicationId: string,
    query?: ApplicationClientListQuery | NormalizedApplicationClientQuery,
  ): Promise<ApplicationPage<ApplicationClientRecord>> {
    return this.listClients(applicationId, query);
  }

  async createApplicationPlatform(
    applicationId: string,
    input: ApplicationPlatformCreateRequest & { id?: string },
    context?: ApplicationWriteContext,
  ): Promise<ApplicationPlatformRecord> {
    return this.createPlatform(applicationId, input, context);
  }

  async createApplicationClient(
    applicationId: string,
    input: ApplicationClientCreateRequest & { id?: string },
    context?: ApplicationWriteContext,
  ): Promise<ApplicationClientRecord> {
    return this.createClient(applicationId, input, context);
  }

  async updateApplicationClient(
    applicationId: string,
    id: string,
    input: ApplicationClientMutationRequest & { id?: string },
    context?: ApplicationWriteContext,
  ): Promise<ApplicationClientRecord> {
    return this.updateClient(applicationId, id, input, context);
  }

  private async listAllPlatforms(applicationId: string): Promise<ApplicationPage<ApplicationPlatformRecord>> {
    const items: ApplicationPlatformRecord[] = [];
    let offset = 0;
    let total = 0;
    do {
      const page = await this.listPlatforms(applicationId, { limit: 100, offset });
      items.push(...page.items);
      total = page.total;
      offset += page.items.length;
      if (page.items.length === 0) break;
    } while (offset < total);
    return { items, total, hasMore: false };
  }

  private async listAllClients(applicationId: string): Promise<ApplicationPage<ApplicationClientRecord>> {
    const items: ApplicationClientRecord[] = [];
    let offset = 0;
    let total = 0;
    do {
      const page = await this.listClients(applicationId, { limit: 100, offset });
      items.push(...page.items);
      total = page.total;
      offset += page.items.length;
      if (page.items.length === 0) break;
    } while (offset < total);
    return { items, total, hasMore: false };
  }

  async issueOpaqueClientSession(input: OpaqueClientSessionIssueInput): Promise<OpaqueClientSessionIssueResult> {
    const applicationId = parseApplicationIdentifier(input.applicationId);
    await this.getApplication(applicationId);
    if (this.clientSessionRepository !== undefined) {
      const result = await this.clientSessionRepository.issue({ ...input, applicationId });
      if (result.record.tenantId !== this.tenantId || result.record.applicationId !== applicationId || result.record.clientKind !== input.clientKind || result.record.userId !== input.userId || result.record.clientId !== input.clientId) throw notFound("Opaque client session not found");
      return result;
    }
    if (input.clientKind !== "mp_weixin" && input.clientKind !== "native") throw invalidRequest("Opaque client session kind is invalid");
    const sessionReference = input.sessionReference === undefined ? randomBytes(32).toString("base64url") : normalizeSqlOpaqueReference(input.sessionReference, "opaque client session");
    const sessionHash = createHash("sha256").update(sessionReference, "utf8").digest("hex");
    const now = new Date();
    const expiresAt = new Date(now.getTime() + opaqueSessionTtlMilliseconds(input.expiresInSeconds));
    const rows = await this.queryRows(
      `INSERT INTO ${this.clientSessionsTable()} (${[
        "id",
        "tenant_id",
        "application_id",
        "client_id",
        "client_kind",
        "session_hash",
        "user_id",
        "status",
        "device_id",
        "binding_hash",
        "created_at",
        "updated_at",
        "expires_at",
      ].map((column) => this.quote(column)).join(", ")}) VALUES ($1, $2, $3, $4, $5, $6, $7, 'active', $8, $9, $10, $10, $11) RETURNING ${this.sessionColumns()}`,
      [
        randomUUID(),
        this.tenantId,
        applicationId,
        input.clientId,
        input.clientKind,
        sessionHash,
        input.userId,
        input.deviceId ?? null,
        input.binding === undefined ? null : createHash("sha256").update(normalizeSqlOpaqueReference(input.binding, "opaque client session"), "utf8").digest("hex"),
        now.toISOString(),
        expiresAt.toISOString(),
      ],
    );
    const record = this.mapOpaqueSessionRow(rows[0] ?? {});
    return {
      session: { sessionReference, clientKind: input.clientKind, expiresAt: record.expiresAt, tokenType: "Bearer" },
      record,
    };
  }

  async findOpaqueClientSession(sessionReference: string): Promise<OpaqueClientSessionRecord | undefined> {
    if (this.clientSessionRepository !== undefined) {
      const record = await this.clientSessionRepository.find(sessionReference);
      if (record?.tenantId !== this.tenantId || record.status !== "active" || record.expiresAt <= new Date().toISOString()) return undefined;
      return record;
    }
    const sessionHash = createHash("sha256").update(normalizeSqlOpaqueReference(sessionReference, "opaque client session"), "utf8").digest("hex");
    const rows = await this.queryRows(
      `SELECT ${this.sessionColumns()} FROM ${this.clientSessionsTable()} WHERE ${this.quote("tenant_id")} = $1 AND ${this.quote("session_hash")} = $2 AND ${this.quote("status")} = 'active' AND ${this.quote("expires_at")} > $3 LIMIT 1`,
      [this.tenantId, sessionHash, new Date().toISOString()],
    );
    if (rows[0] === undefined) return undefined;
    const record = this.mapOpaqueSessionRow(rows[0]);
    if (record.status !== "active" || record.expiresAt <= new Date().toISOString()) return undefined;
    return record;
  }

  async issueWebviewTicket(input: WebviewTicketIssueInput): Promise<WebviewTicketIssueResult> {
    const applicationId = parseApplicationIdentifier(input.applicationId);
    const platformId = parseApplicationPlatformIdentifier(input.platformId);
    await this.getApplication(applicationId);
    await this.getPlatform(applicationId, platformId);
    const redirectUri = normalizeWebviewRedirectUri(input.redirectUri);
    if (this.webviewTicketRepository !== undefined) {
      const result = await this.webviewTicketRepository.issue({ ...input, applicationId, platformId, redirectUri });
      if (result.record.tenantId !== this.tenantId || result.record.applicationId !== applicationId || result.record.platformId !== platformId) throw notFound("Webview ticket not found");
      return result;
    }
    const ticketReference = input.ticketReference === undefined && input.ticket === undefined ? randomBytes(32).toString("base64url") : normalizeSqlOpaqueReference(input.ticketReference ?? input.ticket, "webview ticket");
    const ticketHash = createHash("sha256").update(ticketReference, "utf8").digest("hex");
    const now = new Date();
    const expiresAt = new Date(now.getTime() + webviewTicketTtlMilliseconds(input.expiresInSeconds));
    const rows = await this.queryRows(
      `INSERT INTO ${this.webviewTicketsTable()} (${[
        "id",
        "tenant_id",
        "application_id",
        "platform_id",
        "client_id",
        "ticket_hash",
        "session_hash",
        "binding_hash",
        "redirect_uri",
        "status",
        "created_at",
        "updated_at",
        "expires_at",
      ].map((column) => this.quote(column)).join(", ")}) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'issued', $10, $10, $11) RETURNING ${this.webviewTicketColumns()}`,
      [
        randomUUID(),
        this.tenantId,
        applicationId,
        platformId,
        input.clientId ?? null,
        ticketHash,
        input.sessionReference === undefined ? null : createHash("sha256").update(normalizeSqlOpaqueReference(input.sessionReference, "webview ticket"), "utf8").digest("hex"),
        input.binding === undefined ? null : createHash("sha256").update(normalizeSqlOpaqueReference(input.binding, "opaque client session"), "utf8").digest("hex"),
        redirectUri,
        now.toISOString(),
        expiresAt.toISOString(),
      ],
    );
    const record = this.mapWebviewTicketRow(rows[0] ?? {});
    return {
      ticket: { ticketReference, ticket: ticketReference, clientKind: "webview", redirectUri, expiresAt: record.expiresAt },
      record,
    };
  }

  async consumeWebviewTicket(input: WebviewTicketConsumeRequest): Promise<WebviewTicketRecord | undefined> {
    if (this.webviewTicketRepository !== undefined) {
      const record = await this.webviewTicketRepository.consume(input);
      return record?.tenantId === this.tenantId ? record : undefined;
    }
    const ticketHash = createHash("sha256").update(normalizeSqlOpaqueReference(input.ticketReference, "webview ticket"), "utf8").digest("hex");
    const now = new Date().toISOString();
    const rows = await this.queryRows(
      `UPDATE ${this.webviewTicketsTable()} SET ${this.quote("status")} = 'consumed', ${this.quote("consumed_at")} = $3, ${this.quote("updated_at")} = $3 WHERE ${this.quote("tenant_id")} = $1 AND ${this.quote("ticket_hash")} = $2 AND ${this.quote("status")} = 'issued' AND ${this.quote("expires_at")} > $3 AND (${this.quote("client_id")} IS NULL OR ${this.quote("client_id")} = $4) AND (${this.quote("session_hash")} IS NULL OR ${this.quote("session_hash")} = $5) AND (${this.quote("binding_hash")} IS NULL OR ${this.quote("binding_hash")} = $6) RETURNING ${this.webviewTicketColumns()}`,
      [
        this.tenantId,
        ticketHash,
        now,
        input.clientId ?? null,
        input.sessionReference === undefined ? null : createHash("sha256").update(normalizeSqlOpaqueReference(input.sessionReference, "webview ticket"), "utf8").digest("hex"),
        input.binding === undefined ? null : createHash("sha256").update(normalizeSqlOpaqueReference(input.binding, "opaque client session"), "utf8").digest("hex"),
      ],
    );
    return rows[0] === undefined ? undefined : this.mapWebviewTicketRow(rows[0]);
  }

  async issueOpaqueSession(input: OpaqueClientSessionIssueInput): Promise<OpaqueClientSessionIssueResult> {
    return this.issueOpaqueClientSession(input);
  }

  async findOpaqueSession(sessionReference: string): Promise<OpaqueClientSessionRecord | undefined> {
    return this.findOpaqueClientSession(sessionReference);
  }

  async exchangeWebviewTicket(input: WebviewTicketConsumeRequest): Promise<WebviewTicketRecord | undefined> {
    return this.consumeWebviewTicket(input);
  }

  async issueClientSession(input: OpaqueClientSessionIssueInput): Promise<OpaqueClientSessionIssueResult> {
    return this.issueOpaqueClientSession(input);
  }

  async findClientSession(sessionReference: string): Promise<OpaqueClientSessionRecord | undefined> {
    return this.findOpaqueClientSession(sessionReference);
  }

  async createWebviewTicket(input: WebviewTicketIssueInput): Promise<WebviewTicketIssueResult> {
    return this.issueWebviewTicket(input);
  }

  async redeemWebviewTicket(input: WebviewTicketConsumeRequest): Promise<WebviewTicketRecord | undefined> {
    return this.consumeWebviewTicket(input);
  }

  async isReady(): Promise<boolean> {
    try {
      if (this.clientSessionRepository !== undefined) {
        const readiness = (this.clientSessionRepository as OpaqueClientSessionRepository & { isReady?: () => boolean | Promise<boolean>; ready?: () => boolean | Promise<boolean> }).isReady ?? (this.clientSessionRepository as OpaqueClientSessionRepository & { ready?: () => boolean | Promise<boolean> }).ready;
        if (typeof readiness === "function" && !(await readiness.call(this.clientSessionRepository))) return false;
      }
      if (this.webviewTicketRepository !== undefined) {
        const readiness = (this.webviewTicketRepository as WebviewTicketRepository & { isReady?: () => boolean | Promise<boolean>; ready?: () => boolean | Promise<boolean> }).isReady ?? (this.webviewTicketRepository as WebviewTicketRepository & { ready?: () => boolean | Promise<boolean> }).ready;
        if (typeof readiness === "function" && !(await readiness.call(this.webviewTicketRepository))) return false;
      }
      if (!this.requiredColumnsConfigured()) return false;
      if (this.tenant.requireTransactions && typeof this.executor.transaction !== "function") return false;
      if (this.tenant.requireRls) {
        const role = await this.queryRows(`SELECT r.rolsuper AS "superuser", r.rolbypassrls AS "bypassRls" FROM pg_roles r WHERE r.rolname = current_user`, []);
        if (role[0] !== undefined && (readinessBoolean(role[0].superuser) || readinessBoolean(role[0].bypassRls))) return false;
      }
      await this.queryRows(`SELECT ${this.select(this.columns.applications, APPLICATION_FIELDS)} FROM ${this.applicationsTable()} LIMIT 0`, []);
      await this.queryRows(`SELECT ${this.select(this.columns.platforms, PLATFORM_FIELDS)} FROM ${this.platformsTable()} LIMIT 0`, []);
      await this.queryRows(`SELECT ${this.select(this.columns.clients, CLIENT_FIELDS)} FROM ${this.clientsTable()} LIMIT 0`, []);
      await this.queryRows(`SELECT ${this.select(this.columns.auditEvents, AUDIT_FIELDS as readonly string[])} FROM ${this.auditTable()} LIMIT 0`, []);
      await this.queryRows(`SELECT ${this.select(this.columns.externalIdentities, EXTERNAL_IDENTITY_FIELDS as readonly string[])} FROM ${this.externalIdentitiesTable()} LIMIT 0`, []);
       await this.queryRows(`SELECT 1 FROM ${this.platformLoginStatesTable()} LIMIT 0`, []);
       if (this.requireClientSessions) await this.queryRows(`SELECT 1 FROM ${this.clientSessionsTable()} LIMIT 0`, []);
       if (this.requireWebviewTickets) await this.queryRows(`SELECT 1 FROM ${this.webviewTicketsTable()} LIMIT 0`, []);
       if (this.tenant.requireRls) {

         for (const table of [
           this.tables.applications,
           this.tables.platforms,
           this.tables.clients,
           this.tables.auditEvents,
           this.tables.externalIdentities,
           this.tables.platformLoginStates,
           ...(this.requireClientSessions ? [this.tables.clientSessions] : []),
           ...(this.requireWebviewTickets ? [this.tables.webviewTickets] : []),
         ]) {

          const rls = await this.queryRows(
            `SELECT c.relrowsecurity AS "rls", c.relforcerowsecurity AS "forceRls", EXISTS (SELECT 1 FROM pg_policies p WHERE p.schemaname = n.nspname AND p.tablename = c.relname AND p.qual IS NOT NULL AND p.with_check IS NOT NULL) AS "policy" FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE c.oid = $1::regclass`,
            [table],
          );
          if (!readinessBoolean(rls[0]?.rls) || !readinessBoolean(rls[0]?.forceRls) || (rls[0]?.policy !== undefined && !readinessBoolean(rls[0]?.policy))) return false;
        }
      }
      return true;
    } catch {
      return false;
    }
  }

  async readiness(): Promise<{
    ready: boolean;
    mode: TenantConfig["mode"];
    rls: boolean;
    transactions: boolean;
    requiredColumns: boolean;
    missingColumns: string[];
    context: boolean;
  }> {
    const requiredColumns = this.requiredColumnsConfigured();
    const ready = await this.isReady();
    return {
      ready,
      mode: this.tenant.mode,
      rls: !this.tenant.requireRls || ready,
      transactions: !this.tenant.requireTransactions || typeof this.executor.transaction === "function",
      requiredColumns,
       missingColumns: ready ? [] : requiredColumns ? ["tenant isolation"] : [
         ...this.missingRequiredColumns(),
         ...(this.requireClientSessions ? ["client sessions"] : []),
         ...(this.requireWebviewTickets ? ["webview tickets"] : []),
       ],

      context: !this.tenant.requireRls || this.supportsTransactions(),
    };
  }

  async withTransaction<T>(operation: (() => Promise<T>) | ((executor: ApplicationSqlExecutor) => Promise<T>)): Promise<T> {
    if (typeof this.executor.transaction !== "function") {
      throw new Error("Application repository transaction is required");
    }
    const invoke = async (executor: ApplicationSqlExecutor): Promise<T> => {
      if (operation.length > 0) return operation(executor);
      return (operation as () => Promise<T>)();
    };
    const active = this.transactionContext.getStore();
    if (active !== undefined) return this.transactionContext.run(active, () => this.withTenantContext(() => invoke(active)));
    const shared = getTenantTransactionExecutor(this.executor) as ApplicationSqlExecutor | undefined;
    if (shared !== undefined) return this.transactionContext.run(shared, () => this.withTenantContext(() => invoke(shared)));
    return this.executor.transaction(async (executor) => runWithTenantTransaction(this.executor, executor as unknown as TenantSqlExecutor, () => this.transactionContext.run(executor, () => this.withTenantContext(() => invoke(executor)))));
  }

  async withTenantContext<T>(operation: (executor: ApplicationSqlExecutor) => Promise<T>): Promise<T> {
    const active = (this.transactionContext.getStore() ?? getTenantTransactionExecutor(this.executor)) as ApplicationSqlExecutor | undefined;
    if (active !== undefined) {
      this.scopedExecutors.add(active);
      try {
        if (this.tenant.requireRls) await this.setTenantContext(active);
        return await operation(active);
      } finally {
        this.scopedExecutors.delete(active);
      }
    }
    if (!this.tenant.requireRls || typeof this.executor.transaction !== "function") {
      if (this.tenant.requireRls) throw new Error("Tenant context requires a transaction");
      return operation(this.executor);
    }
    return this.executor.transaction(async (executor) => {
      this.scopedExecutors.add(executor);
      try {
        await this.setTenantContext(executor);
        return await operation(executor);
      } finally {
        this.scopedExecutors.delete(executor);
      }
    });
  }

  async setTenantContext(executor: ApplicationSqlExecutor = this.transactionContext.getStore() ?? getTenantTransactionExecutor(this.executor) ?? this.executor): Promise<void> {
    if (!this.tenant.requireRls) return;
    await executor.query("SELECT set_config('app.tenant_id', $1, true)", [this.tenantId]);
  }

  private async enrichPlatform(platform: ApplicationPlatformRecord): Promise<ApplicationPlatformRecord> {
    const resolution = await this.secretBindings?.resolve("application-platform", platform.id, "platform-secret");
    if (resolution === undefined && this.secretBindings === undefined) return platform;
    const result = { ...platform } as ApplicationPlatformRecord & Record<string, unknown>;
    delete result.secretRef;
    if (this.secretBindings !== undefined) {
      for (const key of ["componentAppSecretRef", "componentVerifyTicketRef", "componentAccessTokenRef", "authorizerRefreshTokenRef", "authorizerAccessTokenRef", "componentTicketRef"]) delete result[key];
      if (result.componentBinding !== null && typeof result.componentBinding === "object" && !Array.isArray(result.componentBinding)) {
        for (const key of ["componentAppSecretRef", "componentVerifyTicketRef", "componentAccessTokenRef", "authorizerRefreshTokenRef", "authorizerAccessTokenRef", "componentTicketRef"]) delete (result.componentBinding as unknown as Record<string, unknown>)[key];
      }
    }
    result.credentialConfigured = resolution !== undefined;
    result.secretStatus = resolution?.binding.status ?? "not_configured";
    result.secretVersion = resolution?.binding.version ?? 0;
    const status = lifecycleStatusOf(result);
    result.readiness = status === "active" && resolution !== undefined ? "ready" : "not_ready";
    result.effectiveStatus = status === "archived" || status === "purged" ? status : status === "active" && resolution !== undefined ? "active" : "not_ready";
    return result;
  }

  private async enrichClient(client: ApplicationClientRecord): Promise<ApplicationClientRecord> {
    const resolution = await this.secretBindings?.resolve("application-client", client.id, "oidc-client-secret");
    if (resolution === undefined && this.secretBindings === undefined) return client;
    const result = { ...client } as ApplicationClientRecord & Record<string, unknown>;
    delete result.secretRef;
    const privateKey = client.tokenEndpointAuthMethod === "private_key_jwt";
    const publicClient = client.tokenEndpointAuthMethod === "none";
    result.hasSecret = resolution !== undefined && !publicClient && !privateKey;
    result.secretStatus = privateKey || publicClient ? "not_required" : resolution?.binding.status ?? "not_configured";
    result.secretVersion = resolution?.binding.version ?? 0;
    const status = normalizeStatus(result.status);
    result.readiness = status === "active" && (resolution !== undefined || privateKey || publicClient) ? "ready" : status === "archived" || status === "purged" ? "not_ready" : "not_ready";
    result.effectiveStatus = result.readiness === "ready" ? "active" : status === "archived" || status === "purged" ? status : "not_ready";
    return result;
  }

  private auditEvent(
    event: string,
    targetId: string,
    context: ApplicationWriteContext,
    detail: Record<string, unknown>,
  ): ApplicationAuditEvent {
    const now = new Date();
    return {
      tenantId: this.tenantId,
      event,
      action: event,
      actorId: contextValue(context.actorId),
      targetId,
      requestId: contextValue(context.requestId),
      ipAddress: contextValue(context.ipAddress),
      userAgent: contextValue(context.userAgent),
      outcome: "success",
      detail: sanitizeAuditDetail(detail) ?? {},
      occurredAt: now,
      createdAt: now,
    };
  }

  async addAuditEvent(event: ApplicationAuditEvent): Promise<ApplicationAuditEvent> {
    if (this.tenant.requireRls) return this.withTenantContext((executor) => this.insertAudit(event, executor));
    return this.insertAudit(event);
  }

  async appendAuditEvent(event: ApplicationAuditEvent): Promise<ApplicationAuditEvent> {
    return this.addAuditEvent(event);
  }

  private async requireApplication(id: string): Promise<ApplicationRecord> {
    const result = await this.getApplication(id);
    if (!result) throw notFound("Application not found");
    return result;
  }

  private async requirePlatform(applicationId: string, id: string): Promise<ApplicationPlatformRecord> {
    const result = await this.getPlatform(applicationId, id);
    if (!result) throw notFound("Application platform not found");
    return result;
  }

  private async requireClient(applicationId: string, id: string): Promise<ApplicationClientRecord> {
    const result = await this.getClient(applicationId, id);
    if (!result) throw notFound("OIDC client not found");
    return result;
  }

  private async assertSlugAvailable(
    executor: ApplicationSqlExecutor,
    slug: string,
    exceptId?: string,
  ): Promise<void> {
    const values: unknown[] = [];
    const clauses: string[] = [];
    this.addTenantClause("applications", values, clauses);
    values.push(slug.toLowerCase());
    clauses.push(`LOWER(${this.quote(this.columns.applications.slug)}) = $${values.length}`);
    if (exceptId !== undefined) {
      values.push(exceptId);
      clauses.push(`${this.quote(this.columns.applications.id)} <> $${values.length}`);
    }
    const rows = await this.queryRows(
      `SELECT ${this.quote(this.columns.applications.id)} FROM ${this.applicationsTable()}${whereText(clauses)} LIMIT 1`,
      values,
      executor,
    );
    if (rows.length > 0) throw conflict("Application slug already exists");
  }

  private async assertClientIdAvailable(
    executor: ApplicationSqlExecutor,
    clientId: string,
    exceptId?: string,
  ): Promise<void> {
    const values: unknown[] = [];
    const clauses: string[] = [];
    this.addTenantClause("clients", values, clauses);
    values.push(clientId.toLowerCase());
    clauses.push(`LOWER(${this.quote(this.columns.clients.clientId)}) = $${values.length}`);
    if (exceptId !== undefined) {
      values.push(exceptId);
      clauses.push(`${this.quote(this.columns.clients.id)} <> $${values.length}`);
    }
    const rows = await this.queryRows(
      `SELECT ${this.quote(this.columns.clients.id)} FROM ${this.clientsTable()}${whereText(clauses)} LIMIT 1`,
      values,
      executor,
    );
    if (rows.length > 0) throw conflict("OIDC clientId already exists");
  }

  private async insertRecord(
    columns: Record<string, string | null>,
    fields: readonly string[],
    values: Record<string, unknown>,
    tableName: string,
    executor: ApplicationSqlExecutor,
  ): Promise<SqlRecord | undefined> {
    const entries = fields.flatMap((field) => {
      const column = columns[field];
      if (typeof column !== "string") return [];
      return [{ field, column, value: storageValue(field, values[field]) }];
    });
    if (entries.length === 0) throw new TypeError("No SQL columns configured");
    const placeholders = entries.map((_entry, index) => `$${index + 1}`);
    const returning = this.select(columns, fields);
    const rows = await this.queryRows(
      `INSERT INTO ${tableName} (${entries.map((entry) => this.quote(entry.column)).join(", ")}) VALUES (${placeholders.join(", ")}) RETURNING ${returning}`,
      entries.map((entry) => entry.value),
      executor,
    );
    return rows[0];
  }

  private async updateRecord(
    table: keyof NormalizedColumns,
    columns: Record<string, string | null>,
    fields: readonly string[],
    tableName: string,
    id: string,
    values: Record<string, unknown>,
    executor: ApplicationSqlExecutor,
    expectedStatus?: string,
    statusField?: string,
    applicationId?: string,
    expectedVersion?: number,
  ): Promise<SqlRecord | undefined> {
    const entries = Object.entries(values).flatMap(([field, value]) => {
      const column = columns[field];
      if (typeof column !== "string") return [];
      return [{ field, column, value: storageValue(field, value) }];
    });
    if (entries.length === 0) throw invalidRequest("No application fields to update");
    const whereValues: unknown[] = [];
    const clauses: string[] = [];
    this.addTenantClause(table, whereValues, clauses);
    whereValues.push(id);
    clauses.push(`${this.quote(columns.id)} = $${whereValues.length}`);
    if (applicationId !== undefined) {
      whereValues.push(applicationId);
      clauses.push(`${this.quote(columns.applicationId)} = $${whereValues.length}`);
    }
    if (expectedStatus !== undefined && statusField !== undefined) {
      whereValues.push(expectedStatus);
      clauses.push(`LOWER(COALESCE(${this.quote(columns[statusField])}, 'active')) = LOWER($${whereValues.length})`);
    }
    if (expectedVersion !== undefined) {
      whereValues.push(expectedVersion);
      clauses.push(`${this.quote(columns.version)} = $${whereValues.length}`);
    }
    const versionColumn = columns.version;
    const versionEntryIndex = entries.findIndex((entry) => entry.field === "version");
    const setEntries = entries
      .filter((entry) => entry.field !== "version")
      .map((entry, index) => `${this.quote(entry.column)} = $${whereValues.length + index + 1}`);
    const setValues = entries.filter((entry) => entry.field !== "version").map((entry) => entry.value);
    if (typeof versionColumn === "string") {
      if (versionEntryIndex < 0) {
        setEntries.push(`${this.quote(versionColumn)} = COALESCE(${this.quote(versionColumn)}, 0) + 1`);
      } else {
        const versionEntry = entries[versionEntryIndex];
        setEntries.push(`${this.quote(versionEntry.column)} = $${whereValues.length + setValues.length + 1}`);
        setValues.push(versionEntry.value);
      }
    }
    if (setEntries.length === 0) throw invalidRequest("No application fields to update");
    const returning = this.select(columns, fields);
    const rows = await this.queryRows(
      `UPDATE ${tableName} SET ${setEntries.join(", ")} WHERE ${clauses.join(" AND ")} RETURNING ${returning}`,
      [...whereValues, ...setValues],
      executor,
    );
    return rows[0];
  }

  private async auditedWrite<T>(
    write: (executor: ApplicationSqlExecutor) => Promise<{ result: T; applied: boolean }>,
    audit: ApplicationAuditEvent,
    rollback: (executor: ApplicationSqlExecutor) => Promise<void>,
  ): Promise<T> {
    if (this.tenant.requireTransactions && !this.supportsTransactions()) {
      throw new Error("Tenant-scoped writes require a transaction");
    }
    const finish = async (result: T): Promise<T> => {
      if (this.secretBindings === undefined || result === null || typeof result !== "object") return result;
      const value = result as T & Record<string, unknown>;
      if (typeof value.id !== "string" || typeof value.applicationId !== "string") return result;
      if (typeof value.type === "string") return this.enrichPlatform(value as unknown as ApplicationPlatformRecord) as Promise<T>;
      if (typeof value.clientId === "string") return this.enrichClient(value as unknown as ApplicationClientRecord) as Promise<T>;
      return result;
    };
    const active = this.transactionContext.getStore() ?? (getTenantTransactionExecutor(this.executor) as ApplicationSqlExecutor | undefined);
    if (active !== undefined) {
      this.scopedExecutors.add(active);
      try {
        if (this.tenant.requireRls) await this.setTenantContext(active);
        const result = await write(active);
        await this.insertAudit(audit, active);
        return finish(result.result);
      } finally {
        this.scopedExecutors.delete(active);
      }
    }
    if (this.supportsTransactions()) {
      return this.executor.transaction!(async (executor) => {
        this.scopedExecutors.add(executor);
        try {
          if (this.tenant.requireRls) await this.setTenantContext(executor);
          const result = await write(executor);
          await this.insertAudit(audit, executor);
          return finish(result.result);
        } finally {
          this.scopedExecutors.delete(executor);
        }
      });
    }
    let applied = false;
    try {
      const result = await write(this.executor);
      applied = result.applied;
      await this.insertAudit(audit, this.executor);
      return finish(result.result);
    } catch (error) {
      if (applied) {
        try {
          await rollback(this.executor);
        } catch (rollbackError) {
          throw new ControlPlaneSqlRollbackError(error, rollbackError);
        }
      }
      throw error;
    }
  }

  private async insertAudit(
    event: ApplicationAuditEvent,
    executor: ApplicationSqlExecutor = this.transactionContext.getStore() ?? getTenantTransactionExecutor(this.executor) ?? this.executor,
  ): Promise<ApplicationAuditEvent> {
    const id = typeof event.id === "string" && event.id.length > 0 ? event.id : randomUUID();
    const now = new Date();
    const valueByField: Record<string, unknown> = {
      id,
      tenantId: this.tenantId,
      event: event.event,
      action: event.action ?? event.event,
      actorId: event.actorId ?? null,
      targetId: event.targetId ?? null,
      requestId: event.requestId ?? null,
      outcome: event.outcome ?? "success",
      ipAddress: event.ipAddress ?? null,
      userAgent: event.userAgent ?? null,
      detail: safeJson(sanitizeAuditDetail(event.detail ?? {}) ?? {}),
      version: readNumber(event.version) ?? 1,
      occurredAt: event.occurredAt ?? now,
      createdAt: event.createdAt ?? now,
    };
    const fields = AUDIT_FIELDS.filter((field) => this.columns.auditEvents[field] !== null);
    const values = fields.map((field) => valueByField[field]);
    const columns = fields.map((field) => this.quote(this.columns.auditEvents[field] as string));
    const placeholders = values.map((_value, index) => `$${index + 1}`);
    const count = await this.queryAffected(
      `INSERT INTO ${this.auditTable()} (${columns.join(", ")}) VALUES (${placeholders.join(", ")}) RETURNING ${this.quote(this.columns.auditEvents.id)}`,
      values,
      executor,
    );
    if (count !== 1) throw new Error("Application SQL audit write failed");
    return { ...event, id, tenantId: this.tenantId, detail: sanitizeAuditDetail(event.detail ?? {}) ?? {} };
  }

  private async queryRows(
    text: string,
    values: readonly unknown[],
    executor: ApplicationSqlExecutor = this.transactionContext.getStore() ?? getTenantTransactionExecutor(this.executor) ?? this.executor,
  ): Promise<SqlRecord[]> {
    if (this.tenant.requireRls && executor === this.executor && !this.scopedExecutors.has(executor)) {
      if (typeof this.executor.transaction !== "function") throw new Error("Tenant context requires a transaction");
      return this.withTenantContext((scoped) => this.queryRows(text, values, scoped));
    }
    let result: unknown;
    try {
      result = await executor.query(text, [...values]);
    } catch (error) {
      if (isUniqueViolation(error)) throw conflict("Resource already exists");
      throw sqlQueryError(error);
    }
    const rows = resultRows(result);
    if (rows === undefined) throw new Error("Application SQL result failed");
    return rows.map((row) => {
      if (!isRecord(row)) throw new Error("Application SQL row failed");
      return row;
    });
  }

  private async queryAffected(
    text: string,
    values: readonly unknown[],
    executor: ApplicationSqlExecutor = this.transactionContext.getStore() ?? getTenantTransactionExecutor(this.executor) ?? this.executor,
  ): Promise<number> {
    let result: unknown;
    try {
      result = await executor.query(text, [...values]);
    } catch (error) {
      if (isUniqueViolation(error)) throw conflict("Resource already exists");
      throw sqlQueryError(error);
    }
    if (isRecord(result) && typeof result.rowCount === "number" && Number.isSafeInteger(result.rowCount) && result.rowCount >= 0) return result.rowCount;
    if (isRecord(result) && typeof result.rowCount === "bigint" && result.rowCount >= 0n && Number.isSafeInteger(Number(result.rowCount))) return Number(result.rowCount);
    const rows = resultRows(result);
    if (rows !== undefined) return rows.length;
    throw new Error("Application SQL result failed");
  }

  private async count(text: string, values: readonly unknown[]): Promise<number> {
    const rows = await this.queryRows(text, values);
    const raw = rows[0]?.total ?? rows[0]?.count;
    if (typeof raw === "number" && Number.isSafeInteger(raw) && raw >= 0) return raw;
    if (typeof raw === "bigint" && raw >= 0n && Number.isSafeInteger(Number(raw))) return Number(raw);
    if (typeof raw === "string" && /^\d+$/u.test(raw)) return Number(raw);
    return rows.length;
  }

  private page<T extends { id?: string; tenantId?: string }>(
    kind: string,
    query: { cursor?: string; limit: number; offset?: number },
    items: T[],
    total: number,
    scope: string,
    keyset = false,
    hasMoreOverride?: boolean,
  ): ApplicationPage<T> {
    const offset = keyset ? 0 : cursorOffset(kind, scope, query.cursor, query.offset);
    const page: ApplicationPage<T> = {
      items,
      hasMore: hasMoreOverride ?? offset + items.length < total,
      total,
    };
    if (page.hasMore) {
      const last = items[items.length - 1];
      if (last?.id !== undefined) {
        page.nextCursor = encodeApplicationKeysetCursor({
          version: CURSOR_VERSION,
          kind,
          scope,
          tenantId: last.tenantId ?? this.tenantId,
          id: last.id,
        });
      } else {
        page.nextCursor = encodeApplicationCursor({ version: CURSOR_VERSION, kind, offset: offset + items.length, scope });
      }
    }
    return page;
  }

  private addKeysetClause(
    table: keyof NormalizedColumns,
    id: string,
    values: unknown[],
    clauses: string[],
  ): void {
    const tenantColumn = this.columns[table].tenantId;
    if (tenantColumn === null) throw new Error("Tenant-qualified keyset cursor requires a tenant column");
    values.push(this.tenantId, id);
    clauses.push(`(${this.quote(tenantColumn)}, ${this.quote(this.columns[table].id)}) > ($${values.length - 1}, $${values.length})`);
  }

  private lifecycleExpression(table: "applications" | "platforms" | "clients"): string {
    const columns = this.columns[table];
    const status = this.quote(columns.status);
    const lifecycle = columns.lifecycleStatus === null ? null : this.quote(columns.lifecycleStatus);
    return `LOWER(COALESCE(${lifecycle ?? status}, ${status}, 'active'))`;
  }

  private readinessExpression(table: "applications" | "platforms" | "clients"): string {
    const columns = this.columns[table];
    const lifecycle = this.lifecycleExpression(table);
    if (table === "applications") {
      const name = this.quote(columns.name);
      const slug = this.quote(columns.slug);
      return `CASE WHEN ${lifecycle} = 'active' AND BTRIM(COALESCE(${name}, '')) <> '' AND BTRIM(COALESCE(${slug}, '')) <> '' THEN 'ready' ELSE 'not_ready' END`;
    }
    if (table === "platforms") {
      const readinessColumn = this.quote(columns.readiness);
      if (this.secretBindings !== undefined) {
        return `CASE WHEN ${lifecycle} = 'active' AND LOWER(COALESCE(${readinessColumn}, 'not_ready')) = 'ready' THEN 'ready' ELSE 'not_ready' END`;
      }
       const secret = this.quote(columns.secretRef);
       const componentSecret = this.quote(columns.componentAppSecretRef);
       return `CASE WHEN ${lifecycle} = 'active' AND (NULLIF(BTRIM(COALESCE(${secret}, '')), '') IS NOT NULL OR NULLIF(BTRIM(COALESCE(${componentSecret}, '')), '') IS NOT NULL) THEN 'ready' ELSE 'not_ready' END`;

    }
    const readinessColumn = this.quote(columns.readiness);
    if (this.secretBindings !== undefined) {
      return `CASE WHEN ${lifecycle} = 'active' AND LOWER(COALESCE(${readinessColumn}, 'not_ready')) = 'ready' THEN 'ready' ELSE 'not_ready' END`;
    }
    const method = this.quote(columns.tokenEndpointAuthMethod);
    const secret = this.quote(columns.secretRef);
    return `CASE WHEN ${lifecycle} = 'active' AND (LOWER(COALESCE(${method}, 'none')) IN ('none', 'private_key_jwt') OR NULLIF(BTRIM(COALESCE(${secret}, '')), '') IS NOT NULL) THEN 'ready' ELSE 'not_ready' END`;
  }

  private effectiveStatusExpression(table: "applications" | "platforms" | "clients"): string {
    const lifecycle = this.lifecycleExpression(table);
    const readiness = this.readinessExpression(table);
    return `CASE WHEN ${lifecycle} IN ('disabled', 'archived', 'purged') THEN ${lifecycle} WHEN ${readiness} = 'ready' THEN ${lifecycle} ELSE 'not_ready' END`;
  }

  private applicationWhere(query: { status?: string; search?: string; q?: string; applicationType?: string; readiness?: string; effectiveStatus?: string }): { text: string; values: unknown[]; clauses: string[] } {
    const values: unknown[] = [];
    const clauses: string[] = [];
    this.addTenantClause("applications", values, clauses);
    if (query.status !== undefined) {
      values.push(query.status);
      clauses.push(`${this.lifecycleExpression("applications")} = LOWER($${values.length})`);
    }
    if (query.applicationType !== undefined) {
      values.push(query.applicationType);
      clauses.push(`LOWER(COALESCE(${this.quote(this.columns.applications.applicationType)}, 'web')) = LOWER($${values.length})`);
    }
    if (query.readiness !== undefined) {
      values.push(query.readiness);
      clauses.push(`LOWER(${this.readinessExpression("applications")}) = LOWER($${values.length})`);
    }
    if (query.effectiveStatus !== undefined) {
      values.push(query.effectiveStatus);
      clauses.push(`LOWER(${this.effectiveStatusExpression("applications")}) = LOWER($${values.length})`);
    }
    const search = query.search ?? query.q;
    if (search !== undefined) {
      const searchColumns = ["id", "name", "slug", "description"]
        .map((field) => this.columns.applications[field])
        .filter((column): column is string => column !== null);
      if (searchColumns.length > 0) {
        values.push(`%${search}%`);
        const parameter = `$${values.length}`;
        clauses.push(`(${searchColumns.map((column) => `LOWER(COALESCE(${this.quote(column)}, '')) LIKE LOWER(${parameter})`).join(" OR ")})`);
      }
    }
    return { text: whereText(clauses), values, clauses };
  }

  private platformWhere(applicationId: string, query: { status?: string; search?: string; q?: string; readiness?: string; effectiveStatus?: string }): { text: string; values: unknown[]; clauses: string[] } {
    const values: unknown[] = [];
    const clauses: string[] = [];
    this.addTenantClause("platforms", values, clauses);
    values.push(applicationId);
    clauses.push(`${this.quote(this.columns.platforms.applicationId)} = $${values.length}`);
    if (query.status !== undefined) {
      values.push(query.status);
      clauses.push(`${this.lifecycleExpression("platforms")} = LOWER($${values.length})`);
    }
    if (query.readiness !== undefined) {
      values.push(query.readiness);
      clauses.push(`LOWER(${this.readinessExpression("platforms")}) = LOWER($${values.length})`);
    }
    if (query.effectiveStatus !== undefined) {
      values.push(query.effectiveStatus);
      clauses.push(`LOWER(${this.effectiveStatusExpression("platforms")}) = LOWER($${values.length})`);
    }
    const search = query.search ?? query.q;
    if (search !== undefined) {
       const searchColumns = ["id", "type", "externalAppId", "displayName", "loginMode", "scope", "componentAppId", "authorizedAppId", "authorizerAppId"]

        .map((field) => this.columns.platforms[field])
        .filter((column): column is string => column !== null);
      if (searchColumns.length > 0) {
        values.push(`%${search}%`);
        const parameter = `$${values.length}`;
        clauses.push(`(${searchColumns.map((column) => `LOWER(COALESCE(${this.quote(column)}, '')) LIKE LOWER(${parameter})`).join(" OR ")})`);
      }
    }
    return { text: whereText(clauses), values, clauses };
  }

  private clientWhere(applicationId: string, query: { status?: string; search?: string; q?: string; readiness?: string; effectiveStatus?: string; clientKind?: string }): { text: string; values: unknown[]; clauses: string[] } {
    const values: unknown[] = [];
    const clauses: string[] = [];
    this.addTenantClause("clients", values, clauses);
    values.push(applicationId);
    clauses.push(`${this.quote(this.columns.clients.applicationId)} = $${values.length}`);
    if (query.status !== undefined) {
      values.push(query.status);
      clauses.push(`${this.lifecycleExpression("clients")} = LOWER($${values.length})`);
    }
    if (query.readiness !== undefined) {
      values.push(query.readiness);
      clauses.push(`LOWER(${this.readinessExpression("clients")}) = LOWER($${values.length})`);
    }
     if (query.effectiveStatus !== undefined) {
       values.push(query.effectiveStatus);
       clauses.push(`LOWER(${this.effectiveStatusExpression("clients")}) = LOWER($${values.length})`);
     }
     if (query.clientKind !== undefined && this.columns.clients.clientKind !== null) {
       values.push(query.clientKind);
       clauses.push(`LOWER(COALESCE(${this.quote(this.columns.clients.clientKind)}, 'web')) = LOWER($${values.length})`);
     }
     const search = query.search ?? query.q;

    if (search !== undefined) {
       const searchColumns = ["id", "clientId", "clientKind", "clientType", "tokenEndpointAuthMethod"]

        .map((field) => this.columns.clients[field])
        .filter((column): column is string => column !== null);
      if (searchColumns.length > 0) {
        values.push(`%${search}%`);
        const parameter = `$${values.length}`;
        clauses.push(`(${searchColumns.map((column) => `LOWER(COALESCE(${this.quote(column)}, '')) LIKE LOWER(${parameter})`).join(" OR ")})`);
      }
    }
    return { text: whereText(clauses), values, clauses };
  }

  private externalIdentityWhere(
    applicationId: string,
    query: { search?: string; q?: string; provider?: string; platformId?: string },
  ): { text: string; values: unknown[]; clauses: string[] } {
    const values: unknown[] = [this.tenantId, applicationId];
    const clauses = [
      `${this.quote(this.columns.externalIdentities.tenantId)} = $1`,
      `${this.quote(this.columns.externalIdentities.applicationId)} = $2`,
    ];
    if (query.provider !== undefined) {
      values.push(query.provider);
      clauses.push(`${this.quote(this.columns.externalIdentities.provider)} = $${values.length}`);
    }
    if (query.platformId !== undefined) {
      values.push(query.platformId);
      clauses.push(`${this.quote(this.columns.externalIdentities.platformId)} = $${values.length}`);
    }
    const search = query.search ?? query.q;
    if (search !== undefined) {
      values.push(`%${search}%`);
      const parameter = `$${values.length}`;
      clauses.push(`(${[
        this.columns.externalIdentities.id,
         this.columns.externalIdentities.subject,
         this.columns.externalIdentities.platform,
         this.columns.externalIdentities.providerAppId,
         this.columns.externalIdentities.openid,
        this.columns.externalIdentities.unionid,
        this.columns.externalIdentities.nickname,
        this.columns.externalIdentities.displayName,
        this.columns.externalIdentities.email,
      ].map((column) => `LOWER(COALESCE(${this.quote(column)}, '')) LIKE LOWER(${parameter})`).join(" OR ")})`);
    }
    return { text: whereText(clauses), values, clauses };
  }

  private addTenantClause(
    table: keyof NormalizedColumns,
    values: unknown[],
    clauses: string[],
  ): void {
    const column = this.columns[table].tenantId;
    if (column === null) return;
    values.push(this.tenantId);
    clauses.push(`${this.quote(column)} = $${values.length}`);
  }

  private select<T extends object>(columns: T, fields: readonly (keyof T & string)[]): string {
    return fields.flatMap((field) => {
      const column = columns[field];
      return typeof column === "string" ? [`${this.quote(column)} AS ${this.quote(field)}`] : [];
    }).join(", ");
  }

  private mapApplication(row: SqlRecord): ApplicationRecord {
    const value = (key: string): unknown => rowValue(row, key);
    const application: ApplicationRecord = {
      id: requiredString(value("id"), "application"),
      tenantId: this.rowTenant(row, "applications"),
      applicationType: textValue(value("applicationType")) ?? "web",
      name: requiredString(value("name"), "application"),
      slug: requiredString(value("slug"), "application"),
      status: normalizeStatus(value("status")),
      lifecycleStatus: textValue(value("lifecycleStatus")) ?? normalizeStatus(value("status")),
      readiness: normalizeReadiness(value("readiness")),
      effectiveStatus: textValue(value("effectiveStatus")),
      version: readNumber(value("version")) ?? 1,
      etag: textValue(value("etag")),
    };
    assignText(application, "description", value("description"));
    assignText(application, "previousStatus", value("previousStatus"));
    assignDate(application, "createdAt", value("createdAt"));
    assignDate(application, "updatedAt", value("updatedAt"));
    assignDate(application, "enabledAt", value("enabledAt"));
    assignDate(application, "disabledAt", value("disabledAt"));
    assignDate(application, "archivedAt", value("archivedAt"));
    assignDate(application, "purgedAt", value("purgedAt"));
    application.readiness = readinessForRecord(application);
    application.effectiveStatus = effectiveStatusForRecord(application);
    return application;
  }

  private mapPlatform(row: SqlRecord): ApplicationPlatformRecord {
    const value = (key: string): unknown => rowValue(row, key);
    const platform: ApplicationPlatformRecord = {
      id: requiredString(value("id"), "application platform"),
      applicationId: requiredString(value("applicationId"), "application platform"),
      tenantId: this.rowTenant(row, "platforms"),
      type: requiredString(value("type"), "application platform"),
      redirectUris: jsonArray(value("redirectUris")),
      lifecycleStatus: textValue(value("lifecycleStatus")) ?? normalizeStatus(value("status")),
      readiness: normalizeReadiness(value("readiness")),
      effectiveStatus: textValue(value("effectiveStatus")),
      version: readNumber(value("version")) ?? 1,
      etag: textValue(value("etag")),
      secretVersion: readNumber(value("secretVersion")) ?? 0,
      status: normalizeStatus(value("status")),
    };
    assignText(platform, "externalAppId", value("externalAppId"));
    assignText(platform, "displayName", value("displayName"));
    assignText(platform, "loginMode", value("loginMode"));
    assignText(platform, "scope", value("scope"));
    const scopes = jsonArray(value("scopes"));
    if (scopes.length > 0) platform.scopes = scopes;
     assignText(platform, "endpointUrl", value("endpointUrl"));
     assignText(platform, "secretRef", value("secretRef"));
     assignText(platform, "componentAppId", value("componentAppId"));
     assignText(platform, "componentAppSecretRef", value("componentAppSecretRef"));
     assignText(platform, "componentVerifyTicketRef", value("componentVerifyTicketRef"));
     assignText(platform, "componentAccessTokenRef", value("componentAccessTokenRef"));
     assignText(platform, "authorizedAppId", value("authorizedAppId"));
     assignText(platform, "authorizerAppId", value("authorizerAppId"));
     assignText(platform, "authorizerRefreshTokenRef", value("authorizerRefreshTokenRef"));
     assignText(platform, "authorizerAccessTokenRef", value("authorizerAccessTokenRef"));
     assignText(platform, "componentTicketRef", value("componentTicketRef"));
     assignDate(platform, "componentTicketExpiresAt", value("componentTicketExpiresAt"));
     assignText(platform, "componentBindingStatus", value("componentBindingStatus"));
     const componentBindingVersion = readNumber(value("componentBindingVersion"));
     if (componentBindingVersion !== undefined) platform.componentBindingVersion = componentBindingVersion;
     assignText(platform, "componentScope", value("componentScope"));
     if (typeof platform.componentAppId === "string" && platform.componentAppId.length > 0) {
       platform.componentBinding = {
         componentAppId: platform.componentAppId,
         ...(platform.authorizedAppId === undefined ? {} : { authorizedAppId: platform.authorizedAppId }),
         ...(platform.authorizerAppId === undefined ? {} : { authorizerAppId: platform.authorizerAppId }),
         ...(platform.componentAppSecretRef === undefined ? {} : { componentAppSecretRef: platform.componentAppSecretRef }),
         ...(platform.componentVerifyTicketRef === undefined ? {} : { componentVerifyTicketRef: platform.componentVerifyTicketRef }),
         ...(platform.componentAccessTokenRef === undefined ? {} : { componentAccessTokenRef: platform.componentAccessTokenRef }),
         ...(platform.authorizerRefreshTokenRef === undefined ? {} : { authorizerRefreshTokenRef: platform.authorizerRefreshTokenRef }),
         ...(platform.authorizerAccessTokenRef === undefined ? {} : { authorizerAccessTokenRef: platform.authorizerAccessTokenRef }),
         ...(platform.componentTicketRef === undefined ? {} : { componentTicketRef: platform.componentTicketRef }),
         ...(platform.componentTicketExpiresAt === undefined ? {} : { componentTicketExpiresAt: platform.componentTicketExpiresAt }),
         ...(platform.componentBindingStatus === undefined ? {} : { status: platform.componentBindingStatus }),
         ...(platform.componentBindingVersion === undefined ? {} : { version: platform.componentBindingVersion }),
         ...(platform.componentScope === undefined ? {} : { scope: platform.componentScope }),
       } as unknown as NonNullable<ApplicationPlatformRecord["componentBinding"]>;
     }
     assignDate(platform, "createdAt", value("createdAt"));

    assignDate(platform, "updatedAt", value("updatedAt"));
    assignDate(platform, "enabledAt", value("enabledAt"));
    assignDate(platform, "disabledAt", value("disabledAt"));
    assignDate(platform, "archivedAt", value("archivedAt"));
    assignDate(platform, "purgedAt", value("purgedAt"));
    platform.readiness = readinessForRecord(platform);
    platform.effectiveStatus = effectiveStatusForRecord(platform);
    return platform;
  }

  private mapClient(row: SqlRecord): ApplicationClientRecord {
    const value = (key: string): unknown => rowValue(row, key);
    const client: ApplicationClientRecord = {
      id: requiredString(value("id"), "OIDC client"),
      applicationId: requiredString(value("applicationId"), "OIDC client"),
      tenantId: this.rowTenant(row, "clients"),
      clientId: requiredString(value("clientId"), "OIDC client"),
      clientIdScope: (textValue(value("clientIdScope")) ?? "global") as "global",
      status: normalizeStatus(value("status")),
      redirectUris: jsonArray(value("redirectUris")),
      postLogoutRedirectUris: jsonArray(value("postLogoutRedirectUris")),
      grantTypes: jsonArray(value("grantTypes")),
      responseTypes: jsonArray(value("responseTypes")),
      scopes: jsonArray(value("scopes")),
      tokenEndpointAuthMethod: textValue(value("tokenEndpointAuthMethod")) ?? "client_secret_basic",
      tokenEndpointAuthSigningAlg: textValue(value("tokenEndpointAuthSigningAlg")),
      jwksUri: textValue(value("jwksUri")),
      privateKeyRef: textValue(value("privateKeyRef")),
      keyId: textValue(value("keyId")),
       requirePkce: booleanValue(value("requirePkce")) ?? true,
       clientKind: (textValue(value("clientKind")) ?? textValue(value("clientType")) ?? "web") as ApplicationClientRecord["clientKind"],
       clientType: (textValue(value("clientType")) ?? textValue(value("clientKind")) ?? "web") as ApplicationClientRecord["clientType"],
       ...(textValue(value("redirectUriPolicy")) === undefined ? {} : { redirectUriPolicy: textValue(value("redirectUriPolicy")) as ApplicationClientRecord["redirectUriPolicy"] }),
       ...(textValue(value("pkceMethod")) === undefined ? {} : { pkceMethod: textValue(value("pkceMethod")) as ApplicationClientRecord["pkceMethod"] }),
       ...(booleanValue(value("consentRequired")) === undefined ? {} : { consentRequired: booleanValue(value("consentRequired")) }),
       lifecycleStatus: textValue(value("lifecycleStatus")) ?? normalizeStatus(value("status")),

      readiness: normalizeReadiness(value("readiness")),
      effectiveStatus: textValue(value("effectiveStatus")),
      version: readNumber(value("version")) ?? 1,
      etag: textValue(value("etag")),
      secretVersion: readNumber(value("secretVersion")) ?? 0,
    };
    assignText(client, "secretRef", value("secretRef"));
    assignDate(client, "createdAt", value("createdAt"));
    assignDate(client, "updatedAt", value("updatedAt"));
    assignDate(client, "enabledAt", value("enabledAt"));
    assignDate(client, "disabledAt", value("disabledAt"));
    assignDate(client, "archivedAt", value("archivedAt"));
    assignDate(client, "purgedAt", value("purgedAt"));
    client.readiness = readinessForRecord(client);
    client.effectiveStatus = effectiveStatusForRecord(client);
    return client;
  }

  private mapApplicationClientRow(row: SqlRecord): ApplicationClientRecord {
    return this.mapClient(row);
  }

  private mapExternalIdentity(row: SqlRecord): ApplicationExternalIdentityRecord {
    const value = (key: string): unknown => rowValue(row, key);
    const id = requiredString(value("id"), "external identity");
    const applicationId = requiredString(value("applicationId"), "external identity");
    const provider = requiredString(value("provider"), "external identity");
    const subject = requiredString(value("subject"), "external identity");
    const identity: ApplicationExternalIdentityRecord = {
      id,
      applicationId,
      tenantId: this.rowTenant(row, "externalIdentities"),
      provider,
      subject,
      version: readNumber(value("version")) ?? 1,
    };
    assignText(identity, "platformId", value("platformId"));
    const platform = textValue(value("platform")) ?? textValue(value("platformId")) ?? "";
    const providerAppId = textValue(value("providerAppId")) ?? textValue(value("externalAppId")) ?? "";
    (identity as Record<string, unknown>).platform = platform;
    (identity as Record<string, unknown>).providerAppId = providerAppId;
    assignText(identity, "externalAppId", value("externalAppId"));
    assignText(identity, "openid", value("openid"));
    assignText(identity, "unionid", value("unionid"));
    assignText(identity, "nickname", value("nickname"));
    assignText(identity, "displayName", value("displayName"));
    assignText(identity, "email", value("email"));
    assignText(identity, "avatarUrl", value("avatarUrl"));
     const scopes = jsonArray(value("scopes"));
     if (scopes.length > 0) identity.scopes = scopes;
     const canonicalUserId = textValue(value("canonicalUserId"));
     if (canonicalUserId !== undefined) identity.canonicalUserId = canonicalUserId;
     const linkStatus = textValue(value("linkStatus"));
     if (linkStatus !== undefined) identity.linkStatus = linkStatus;
     const emailVerified = booleanValue(value("emailVerified"));
     if (emailVerified !== undefined) identity.emailVerified = emailVerified;
     const linkedAt = value("linkedAt");
    const firstLinkedAt = value("firstLinkedAt") ?? linkedAt;
    assignDate(identity, "firstLinkedAt", firstLinkedAt);
    assignDate(identity, "linkedAt", linkedAt);
    assignDate(identity, "lastAuthenticatedAt", value("lastAuthenticatedAt"));
    assignDate(identity, "createdAt", value("createdAt"));
    assignDate(identity, "updatedAt", value("updatedAt"));
    return identity;
  }

  private belongs(record: { tenantId?: string }): boolean {
    return record.tenantId === this.tenantId;
  }

  private rowTenant(row: SqlRecord, table: keyof NormalizedColumns): string {
    if (this.columns[table].tenantId === null) return this.tenantId;
    const tenantId = textValue(rowValue(row, "tenantId"));
    if (tenantId === undefined) throw new Error("Application SQL row is missing tenant scope");
    return tenantId;
  }

  private requiredColumnsConfigured(): boolean {
    return this.missingRequiredColumns().length === 0;
  }

  private missingRequiredColumns(): string[] {
    const required = Object.entries(APPLICATION_MANAGEMENT_REQUIRED_COLUMNS) as Array<[keyof NormalizedColumns, readonly string[]]>;
    const missing: string[] = [];
    for (const [table, fields] of required) {
      for (const field of fields) {
        if (this.columns[table][field] === null || this.columns[table][field] === undefined) missing.push(`${table}.${field}`);
      }
    }
    return missing;
  }

  private activeExecutor(): ApplicationSqlExecutor {
    return this.transactionContext.getStore() ?? (getTenantTransactionExecutor(this.executor) as ApplicationSqlExecutor | undefined) ?? this.executor;
  }

  private supportsTransactions(): boolean {
    return typeof this.executor.transaction === "function";
  }

  private applicationsTable(): string {
    return this.quote(this.tables.applications);
  }

  private platformsTable(): string {
    return this.quote(this.tables.platforms);
  }

  private clientsTable(): string {
    return this.quote(this.tables.clients);
  }

  private auditTable(): string {
    return this.quote(this.tables.auditEvents);
  }

  private externalIdentitiesTable(): string {
    return this.quote(this.tables.externalIdentities);
  }

  private platformLoginStatesTable(): string {
    return this.quote(this.tables.platformLoginStates);
  }

  private clientSessionsTable(): string {
    return this.quote(this.tables.clientSessions);
  }

  private webviewTicketsTable(): string {
    return this.quote(this.tables.webviewTickets);
  }

  private sessionColumns(): string {
    return ["id", "tenant_id", "application_id", "client_id", "client_kind", "session_hash", "user_id", "status", "device_id", "binding_hash", "created_at", "updated_at", "last_used_at", "expires_at", "revoked_at"].map((column) => this.quote(column)).join(", ");
  }

  private webviewTicketColumns(): string {
    return ["id", "tenant_id", "application_id", "platform_id", "client_id", "ticket_hash", "session_hash", "binding_hash", "redirect_uri", "status", "created_at", "updated_at", "consumed_at", "expires_at", "revoked_at"].map((column) => this.quote(column)).join(", ");
  }

  private mapOpaqueSessionRow(row: SqlRecord): OpaqueClientSessionRecord {
    const clientKind = rowValue(row, "clientKind");
    const status = rowValue(row, "status");
    if (clientKind !== "mp_weixin" && clientKind !== "native") throw new Error("Invalid SQL opaque client session row");
    if (status !== "active" && status !== "expired" && status !== "revoked") throw new Error("Invalid SQL opaque client session row");
    return {
      id: requiredString(rowValue(row, "id"), "opaque client session"),
      tenantId: requiredString(rowValue(row, "tenantId") ?? this.tenantId, "opaque client session"),
      applicationId: requiredString(rowValue(row, "applicationId"), "opaque client session"),
      clientId: requiredString(rowValue(row, "clientId"), "opaque client session"),
      clientKind,
      sessionHash: requiredString(rowValue(row, "sessionHash"), "opaque client session"),
      userId: requiredString(rowValue(row, "userId"), "opaque client session"),
      status,
      ...(rowValue(row, "deviceId") === undefined || rowValue(row, "deviceId") === null ? {} : { deviceId: requiredString(rowValue(row, "deviceId"), "opaque client session") }),
      ...(rowValue(row, "bindingHash") === undefined || rowValue(row, "bindingHash") === null ? {} : { bindingHash: requiredString(rowValue(row, "bindingHash"), "opaque client session") }),
      createdAt: requiredDateText(rowValue(row, "createdAt"), "opaque client session"),
      ...(rowValue(row, "updatedAt") === undefined || rowValue(row, "updatedAt") === null ? {} : { updatedAt: requiredDateText(rowValue(row, "updatedAt"), "opaque client session") }),
      ...(rowValue(row, "lastUsedAt") === undefined || rowValue(row, "lastUsedAt") === null ? {} : { lastUsedAt: requiredDateText(rowValue(row, "lastUsedAt"), "opaque client session") }),
      expiresAt: requiredDateText(rowValue(row, "expiresAt"), "opaque client session"),
      ...(rowValue(row, "revokedAt") === undefined || rowValue(row, "revokedAt") === null ? {} : { revokedAt: requiredDateText(rowValue(row, "revokedAt"), "opaque client session") }),
    };
  }

  private mapWebviewTicketRow(row: SqlRecord): WebviewTicketRecord {
    const status = rowValue(row, "status");
    if (status !== "issued" && status !== "consumed" && status !== "expired" && status !== "revoked") throw new Error("Invalid SQL webview ticket row");
    return {
      id: requiredString(rowValue(row, "id"), "webview ticket"),
      tenantId: requiredString(rowValue(row, "tenantId") ?? this.tenantId, "webview ticket"),
      applicationId: requiredString(rowValue(row, "applicationId"), "webview ticket"),
      platformId: requiredString(rowValue(row, "platformId"), "webview ticket"),
      ...(rowValue(row, "clientId") === undefined || rowValue(row, "clientId") === null ? {} : { clientId: requiredString(rowValue(row, "clientId"), "webview ticket") }),
      ticketHash: requiredString(rowValue(row, "ticketHash"), "webview ticket"),
      ...(rowValue(row, "sessionHash") === undefined || rowValue(row, "sessionHash") === null ? {} : { sessionHash: requiredString(rowValue(row, "sessionHash"), "webview ticket") }),
      ...(rowValue(row, "bindingHash") === undefined || rowValue(row, "bindingHash") === null ? {} : { bindingHash: requiredString(rowValue(row, "bindingHash"), "webview ticket") }),
      redirectUri: normalizeWebviewRedirectUri(rowValue(row, "redirectUri")),
      status,
      createdAt: requiredDateText(rowValue(row, "createdAt"), "webview ticket"),
      ...(rowValue(row, "updatedAt") === undefined || rowValue(row, "updatedAt") === null ? {} : { updatedAt: requiredDateText(rowValue(row, "updatedAt"), "webview ticket") }),
      ...(rowValue(row, "consumedAt") === undefined || rowValue(row, "consumedAt") === null ? {} : { consumedAt: requiredDateText(rowValue(row, "consumedAt"), "webview ticket") }),
      expiresAt: requiredDateText(rowValue(row, "expiresAt"), "webview ticket"),
      ...(rowValue(row, "revokedAt") === undefined || rowValue(row, "revokedAt") === null ? {} : { revokedAt: requiredDateText(rowValue(row, "revokedAt"), "webview ticket") }),
    };
  }

  private quote(value: string | null): string {
    return quoteApplicationSqlIdentifier(value);
  }

  private async restoreApplicationRow(id: string, value: ApplicationRecord, executor: ApplicationSqlExecutor): Promise<void> {
    await this.restoreRow("applications", this.columns.applications, APPLICATION_FIELDS, this.applicationsTable(), id, value, executor);
  }

  private async restorePlatformRow(value: ApplicationPlatformRecord, executor: ApplicationSqlExecutor): Promise<void> {
    await this.restoreRow("platforms", this.columns.platforms, PLATFORM_FIELDS, this.platformsTable(), value.id, value, executor);
  }

  private async restoreClientRow(value: ApplicationClientRecord, executor: ApplicationSqlExecutor): Promise<void> {
    await this.restoreRow("clients", this.columns.clients, CLIENT_FIELDS, this.clientsTable(), value.id, value, executor);
  }

  private async restoreRow(
    table: keyof NormalizedColumns,
    columns: Record<string, string | null>,
    fields: readonly string[],
    tableName: string,
    id: string,
    value: Record<string, unknown>,
    executor: ApplicationSqlExecutor,
  ): Promise<void> {
    const entries = fields.flatMap((field) => {
      const column = columns[field];
      return typeof column === "string" ? [{ column, value: storageValue(field, value[field]) }] : [];
    });
    const whereValues: unknown[] = [];
    const clauses: string[] = [];
    this.addTenantClause(table, whereValues, clauses);
    whereValues.push(id);
    clauses.push(`${this.quote(columns.id)} = $${whereValues.length}`);
    const setEntries = entries.map((entry, index) => `${this.quote(entry.column)} = $${whereValues.length + index + 1}`);
    const count = await this.queryAffected(
      `UPDATE ${tableName} SET ${setEntries.join(", ")}${whereText(clauses)}`,
      [...whereValues, ...entries.map((entry) => entry.value)],
      executor,
    );
    if (count !== 1) throw new Error("Application SQL rollback did not affect a row");
  }

  private async findExternalIdentityForUpsert(
    applicationId: string,
    provider: string,
    subject: string,
    platform: string,
    providerAppId: string,
  ): Promise<ApplicationExternalIdentityRecord | undefined> {
    const values: unknown[] = [this.tenantId, applicationId, provider, subject, platform, providerAppId];
    const clauses = [
      `${this.quote(this.columns.externalIdentities.tenantId)} = $1`,
      `${this.quote(this.columns.externalIdentities.applicationId)} = $2`,
      `${this.quote(this.columns.externalIdentities.provider)} = $3`,
      `${this.quote(this.columns.externalIdentities.subject)} = $4`,
      `${this.quote(this.columns.externalIdentities.platform)} = $5`,
      `${this.quote(this.columns.externalIdentities.providerAppId)} = $6`,
    ];
    const rows = await this.queryRows(
      `SELECT ${this.select(this.columns.externalIdentities, EXTERNAL_IDENTITY_FIELDS as readonly string[])} FROM ${this.externalIdentitiesTable()} WHERE ${clauses.join(" AND ")} ORDER BY ${this.quote(this.columns.externalIdentities.id)} ASC LIMIT 1`,
      values,
    );
    return rows[0] === undefined ? undefined : this.mapExternalIdentity(rows[0]);
  }

  private async findExternalIdentityByCanonical(
    canonical: ReturnType<typeof externalIdentityCanonicalKey>,
  ): Promise<ApplicationExternalIdentityRecord | undefined> {
    const values: unknown[] = [canonical.tenantId, canonical.applicationId, canonical.provider, canonical.platform, canonical.providerAppId, canonical.subject];
    const rows = await this.queryRows(
      `SELECT ${this.select(this.columns.externalIdentities, EXTERNAL_IDENTITY_FIELDS as readonly string[])} FROM ${this.externalIdentitiesTable()} WHERE ${this.quote(this.columns.externalIdentities.tenantId)} = $1 AND ${this.quote(this.columns.externalIdentities.applicationId)} = $2 AND ${this.quote(this.columns.externalIdentities.provider)} = $3 AND ${this.quote(this.columns.externalIdentities.platform)} = $4 AND ${this.quote(this.columns.externalIdentities.providerAppId)} = $5 AND ${this.quote(this.columns.externalIdentities.subject)} = $6 LIMIT 1`,
      values,
    );
    return rows[0] === undefined ? undefined : this.mapExternalIdentity(rows[0]);
  }

  private async deleteExternalIdentityByCanonical(
    canonical: ReturnType<typeof externalIdentityCanonicalKey>,
    executor: ApplicationSqlExecutor,
  ): Promise<void> {
    await this.queryAffected(
      `DELETE FROM ${this.externalIdentitiesTable()} WHERE ${this.quote(this.columns.externalIdentities.tenantId)} = $1 AND ${this.quote(this.columns.externalIdentities.applicationId)} = $2 AND ${this.quote(this.columns.externalIdentities.provider)} = $3 AND ${this.quote(this.columns.externalIdentities.platform)} = $4 AND ${this.quote(this.columns.externalIdentities.providerAppId)} = $5 AND ${this.quote(this.columns.externalIdentities.subject)} = $6`,
      [canonical.tenantId, canonical.applicationId, canonical.provider, canonical.platform, canonical.providerAppId, canonical.subject],
      executor,
    );
  }

  private async listAllExternalIdentities(applicationId: string): Promise<ApplicationExternalIdentityRecord[]> {
    const values: unknown[] = [this.tenantId, applicationId];
    const rows = await this.queryRows(
      `SELECT ${this.select(this.columns.externalIdentities, EXTERNAL_IDENTITY_FIELDS as readonly string[])} FROM ${this.externalIdentitiesTable()} WHERE ${this.quote(this.columns.externalIdentities.tenantId)} = $1 AND ${this.quote(this.columns.externalIdentities.applicationId)} = $2 ORDER BY ${this.quote(this.columns.externalIdentities.id)} ASC`,
      values,
    );
    return rows.map((row) => this.mapExternalIdentity(row)).filter((record) => this.belongs(record));
  }

  private async deleteExternalIdentityRows(applicationId: string, executor: ApplicationSqlExecutor): Promise<void> {
    await this.queryAffected(
      `DELETE FROM ${this.externalIdentitiesTable()} WHERE ${this.quote(this.columns.externalIdentities.tenantId)} = $1 AND ${this.quote(this.columns.externalIdentities.applicationId)} = $2`,
      [this.tenantId, applicationId],
      executor,
    );
  }

  private async restoreExternalIdentityRows(
    records: readonly ApplicationExternalIdentityRecord[],
    executor: ApplicationSqlExecutor,
  ): Promise<void> {
    for (const record of records) {
      const fields = [
        "id",
        "tenantId",
        "applicationId",
        "platformId",
        "platform",
        "provider",
        "providerAppId",
        "subject",
        "externalAppId",
        "openid",
        "unionid",
        "nickname",
        "displayName",
        "email",
        "avatarUrl",
       "scopes",
       "canonicalUserId",
       "linkStatus",
       "emailVerified",
       "firstLinkedAt",
        "linkedAt",
        "lastAuthenticatedAt",
        "version",
        "createdAt",
        "updatedAt",
      ];
      const values = fields.map((field) => storageValue(field, record[field as keyof ApplicationExternalIdentityRecord]));
      const columns = fields.map((field) => this.quote(this.columns.externalIdentities[field as keyof ApplicationSqlExternalIdentityColumns]));
      await executor.query(
        `INSERT INTO ${this.externalIdentitiesTable()} (${columns.join(", ")}) VALUES (${values.map((_value, index) => `$${index + 1}`).join(", ")}) ON CONFLICT (${this.quote(this.columns.externalIdentities.tenantId)}, ${this.quote(this.columns.externalIdentities.id)}) DO UPDATE SET ${fields.filter((field) => field !== "id" && field !== "tenantId" && field !== "createdAt").map((field) => `${this.quote(this.columns.externalIdentities[field as keyof ApplicationSqlExternalIdentityColumns])} = EXCLUDED.${this.quote(this.columns.externalIdentities[field as keyof ApplicationSqlExternalIdentityColumns])}`).join(", ")}`,
        values,
      );
    }
  }

  private async deletePlatformRow(id: string, executor: ApplicationSqlExecutor, applicationId?: string): Promise<void> {
    const values: unknown[] = [];
    const clauses: string[] = [];
    this.addTenantClause("platforms", values, clauses);
    values.push(id);
    clauses.push(`${this.quote(this.columns.platforms.id)} = $${values.length}`);
    if (applicationId !== undefined) {
      values.push(applicationId);
      clauses.push(`${this.quote(this.columns.platforms.applicationId)} = $${values.length}`);
    }
    const count = await this.queryAffected(`DELETE FROM ${this.platformsTable()}${whereText(clauses)}`, values, executor);
    if (count !== 1) throw notFound("Application platform not found");
  }

  private async deleteClientRow(id: string, executor: ApplicationSqlExecutor, applicationId?: string): Promise<void> {
    const values: unknown[] = [];
    const clauses: string[] = [];
    this.addTenantClause("clients", values, clauses);
    values.push(id);
    clauses.push(`${this.quote(this.columns.clients.id)} = $${values.length}`);
    if (applicationId !== undefined) {
      values.push(applicationId);
      clauses.push(`${this.quote(this.columns.clients.applicationId)} = $${values.length}`);
    }
    const count = await this.queryAffected(`DELETE FROM ${this.clientsTable()}${whereText(clauses)}`, values, executor);
    if (count !== 1) throw notFound("OIDC client not found");
  }
}

export { SqlApplicationRepository as ApplicationSqlRepository };
export { SqlApplicationRepository as PostgresApplicationRepository };
export { SqlApplicationRepository as PostgreSQLApplicationRepository };

function assertNoApplicationDedicatedFallback(options: ApplicationSqlRepositoryOptions): void {
  const mode = options.tenant?.mode ?? options.tenantConfig?.mode ?? options.tenantMode ?? options.mode;
  const normalized = typeof mode === "string" ? mode.trim().toLowerCase() : "fixed";
  if (normalized === "dedicated" && (options.allowSharedFallback === true || options.sharedExecutor !== undefined || options.fallbackExecutor !== undefined)) {
    throw new TypeError("Dedicated tenant mode cannot use a shared pool fallback");
  }
}

function normalizeOptions(
  input: SqlRepositoryInput,
  secondOptions: SqlRepositorySecondOptions,
): ApplicationSqlRepositoryOptions {
  if (typeof input === "function") return { ...secondOptions, query: input };
  if (isExecutor(input) && !hasRepositoryOptionProperties(input)) return { ...secondOptions, executor: input };
  return { ...input, ...secondOptions };
}

function hasRepositoryOptionProperties(value: object): boolean {
  return [
    "tenantId",
    "tenant",
    "tenantConfig",
    "tenantMode",
    "mode",
    "requireRls",
    "requireTransactions",
    "requireClientSessions",
    "requireWebviewTickets",
    "tenantColumn",
    "schema",
    "sharedExecutor",
    "dedicatedExecutor",
    "fallbackExecutor",
    "allowSharedFallback",
    "secretBindings",
    "tables",
    "tableNames",
    "applicationTable",
    "application",
    "applicationPlatforms",
    "applicationPlatformsTable",
    "platformTable",
    "applicationPlatformTable",
    "platform",
    "clientTable",
    "applicationClientTable",
    "applicationClients",
    "applicationClientsTable",
    "client",
    "auditTable",
    "auditEventsTable",
    "externalIdentitiesTable",
    "applicationExternalIdentitiesTable",
    "externalIdentityTable",
    "applicationIdentityTable",
    "platformLoginStateTable",
    "platformLoginStatesTable",
    "platformLoginState",
    "platformLoginStates",
    "columns",
    "columnNames",
    "applicationsColumns",
    "platformsColumns",
    "applicationPlatformsColumns",
    "clientsColumns",
    "applicationClientsColumns",
    "auditEventsColumns",
    "externalIdentitiesColumns",
    "applicationExternalIdentitiesColumns",
    "clientSessionRepository",
    "webviewTicketRepository",
    "clientSessionTable",
    "clientSessionsTable",
    "opaqueClientSessionTable",
    "opaqueClientSessionsTable",
    "webviewTicketTable",
    "webviewTicketsTable",
    "clientTicketTable",
    "clientTicketsTable",
  ].some((key) => Object.prototype.hasOwnProperty.call(value, key));
}

function normalizeExecutor(options: ApplicationSqlRepositoryOptions, mode: TenantMode): ApplicationSqlExecutor {
  if (options.executor && typeof options.executor.query === "function") return options.executor;
  if (typeof options.query === "function") return { query: options.query };
  if (mode === "shared" && options.sharedExecutor && typeof options.sharedExecutor.query === "function") return options.sharedExecutor;
  if (mode === "dedicated" && options.dedicatedExecutor && typeof options.dedicatedExecutor.query === "function") return options.dedicatedExecutor;
  throw new TypeError("An application SQL query executor is required");
}

function normalizeTenantId(value: unknown): string {
  if (value === undefined) return DEFAULT_TENANT_ID;
  if (typeof value !== "string") throw new TypeError("tenantId must be a string");
  const normalized = value.trim();
  if (normalized.length === 0 || normalized.length > 256 || /[\u0000-\u001f\u007f]/u.test(normalized)) throw new TypeError("Invalid tenantId");
  return normalized;
}

function normalizeTables(options: ApplicationSqlRepositoryOptions): NormalizedTables {
  const tables = {
    ...DEFAULT_TABLES,
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
    ...(options.tableNames?.applicationClients === undefined ? {} : { clients: options.tableNames.applicationClients }),
    ...(options.applicationTable === undefined ? {} : { applications: options.applicationTable }),
    ...(options.application === undefined ? {} : { applications: options.application }),
    ...(options.applicationPlatforms === undefined ? {} : { platforms: options.applicationPlatforms }),
    ...(options.applicationPlatformsTable === undefined ? {} : { platforms: options.applicationPlatformsTable }),
    ...(options.platformTable === undefined ? {} : { platforms: options.platformTable }),
    ...(options.applicationPlatformTable === undefined ? {} : { platforms: options.applicationPlatformTable }),
    ...(options.platform === undefined ? {} : { platforms: options.platform }),
    ...(options.clientTable === undefined ? {} : { clients: options.clientTable }),
    ...(options.applicationClientTable === undefined ? {} : { clients: options.applicationClientTable }),
    ...(options.applicationClients === undefined ? {} : { clients: options.applicationClients }),
    ...(options.applicationClientsTable === undefined ? {} : { clients: options.applicationClientsTable }),
    ...(options.client === undefined ? {} : { clients: options.client }),
    ...(options.auditTable === undefined ? {} : { auditEvents: options.auditTable }),
    ...(options.auditEventsTable === undefined ? {} : { auditEvents: options.auditEventsTable }),
     externalIdentities: options.externalIdentitiesTable ?? options.applicationExternalIdentitiesTable ?? options.externalIdentityTable ?? options.applicationIdentityTable ?? options.tables?.externalIdentities ?? options.tables?.applicationExternalIdentities ?? options.tableNames?.externalIdentities ?? options.tableNames?.applicationExternalIdentities ?? DEFAULT_TABLES.externalIdentities,
     platformLoginStates: options.platformLoginStateTable ?? options.platformLoginStatesTable ?? options.platformLoginState ?? options.platformLoginStates ?? options.tables?.platformLoginStates ?? options.tables?.platformLoginState ?? options.tableNames?.platformLoginStates ?? options.tableNames?.platformLoginState ?? DEFAULT_TABLES.platformLoginStates,
     clientSessions: options.clientSessionTable ?? options.clientSessionsTable ?? options.opaqueClientSessionTable ?? options.opaqueClientSessionsTable ?? options.tables?.clientSessions ?? options.tables?.opaqueClientSessions ?? options.tableNames?.clientSessions ?? options.tableNames?.opaqueClientSessions ?? DEFAULT_TABLES.clientSessions,
     webviewTickets: options.webviewTicketTable ?? options.webviewTicketsTable ?? options.clientTicketTable ?? options.clientTicketsTable ?? options.tables?.webviewTickets ?? options.tables?.clientTickets ?? options.tableNames?.webviewTickets ?? options.tableNames?.clientTickets ?? DEFAULT_TABLES.webviewTickets,
   };
  const schema = normalizeTenantConfig({
    ...(options.tenant ?? {}),
    ...(options.tenantConfig ?? {}),
    ...(options.tenantMode === undefined ? {} : { mode: options.tenantMode }),
    ...(options.mode === undefined ? {} : { mode: options.mode }),
    ...(options.tenantId === undefined ? {} : { tenantId: options.tenantId }),
    ...(options.tenantColumn === undefined ? {} : { tenantColumn: options.tenantColumn }),
    ...(options.schema === undefined ? {} : { schema: options.schema }),
    ...(options.requireRls === undefined ? {} : { requireRls: options.requireRls }),
    ...(options.requireTransactions === undefined ? {} : { requireTransactions: options.requireTransactions }),
  }).schema;
  return {
    applications: qualifyTenantTable(validateApplicationSqlIdentifier(tables.applications, "applications table"), schema),
    platforms: qualifyTenantTable(validateApplicationSqlIdentifier(tables.platforms, "platforms table"), schema),
    clients: qualifyTenantTable(validateApplicationSqlIdentifier(tables.clients, "clients table"), schema),
    auditEvents: qualifyTenantTable(validateApplicationSqlIdentifier(tables.auditEvents, "audit events table"), schema),
    externalIdentities: qualifyTenantTable(validateApplicationSqlIdentifier(tables.externalIdentities, "external identities table"), schema),
     platformLoginStates: qualifyTenantTable(validateApplicationSqlIdentifier(tables.platformLoginStates ?? tables.platformLoginState ?? DEFAULT_TABLES.platformLoginStates, "platform login states table"), schema),
     clientSessions: qualifyTenantTable(validateApplicationSqlIdentifier(tables.clientSessions, "client sessions table"), schema),
     webviewTickets: qualifyTenantTable(validateApplicationSqlIdentifier(tables.webviewTickets, "webview tickets table"), schema),

  };
}

function normalizeColumns(options: ApplicationSqlRepositoryOptions, tenantColumn = "tenant_id"): NormalizedColumns {
  const columns: NormalizedColumns = {
    applications: mergeColumns(DEFAULT_COLUMNS.applications, options.columns?.applications, options.columns?.application, options.columnNames?.applications, options.columnNames?.application, options.applicationsColumns),
    platforms: mergeColumns(DEFAULT_COLUMNS.platforms, options.columns?.platforms, options.columns?.applicationPlatform, options.columns?.applicationPlatforms, options.columnNames?.platforms, options.columnNames?.applicationPlatform, options.columnNames?.applicationPlatforms, options.platformsColumns, options.applicationPlatformsColumns),
    clients: mergeColumns(DEFAULT_COLUMNS.clients, options.columns?.clients, options.columns?.applicationClient, options.columns?.applicationClients, options.columnNames?.clients, options.columnNames?.applicationClient, options.columnNames?.applicationClients, options.clientsColumns, options.applicationClientsColumns),
    auditEvents: mergeColumns(DEFAULT_COLUMNS.auditEvents, options.columns?.auditEvents, options.columns?.audit, options.columnNames?.auditEvents, options.columnNames?.audit, options.auditEventsColumns),
    externalIdentities: mergeColumns(DEFAULT_COLUMNS.externalIdentities, options.columns?.externalIdentities, options.columns?.applicationExternalIdentities, options.columnNames?.externalIdentities, options.columnNames?.applicationExternalIdentities, options.externalIdentitiesColumns, options.applicationExternalIdentitiesColumns),
  };
  if (options.tenantColumn !== undefined) {
    const configuredTenantColumn = options.tenantColumn === null
      ? null
      : validateConfiguredSqlColumn(options.tenantColumn, "tenantColumn");
    columns.applications.tenantId = configuredTenantColumn;
    columns.platforms.tenantId = configuredTenantColumn;
    columns.clients.tenantId = configuredTenantColumn;
    columns.auditEvents.tenantId = configuredTenantColumn;
    columns.externalIdentities.tenantId = configuredTenantColumn;
  } else if (tenantColumn !== "tenant_id") {
    const configuredTenantColumn = validateConfiguredSqlColumn(tenantColumn, "tenantColumn");
    columns.applications.tenantId = configuredTenantColumn;
    columns.platforms.tenantId = configuredTenantColumn;
    columns.clients.tenantId = configuredTenantColumn;
    columns.auditEvents.tenantId = configuredTenantColumn;
    columns.externalIdentities.tenantId = configuredTenantColumn;
  }
  for (const table of ["applications", "platforms", "clients", "auditEvents", "externalIdentities"] as const) {
    if (columns[table].tenantId === null || columns[table].tenantId === undefined) {
      throw new TypeError(`Tenant-qualified application persistence requires ${table}.tenantId`);
    }
  }
  return columns;
}

function mergeColumns<T extends object>(
  base: T,
  ...sources: Array<Partial<T> | undefined>
): T {
  const output: Record<string, string | null> = { ...base } as Record<string, string | null>;
  for (const source of sources) {
    if (!source) continue;
    for (const [key, value] of Object.entries(source)) {
      if (value === null) output[key] = null;
      else if (typeof value === "string") output[key] = validateConfiguredSqlColumn(value, key);
    }
  }
  return output as T;
}

function validateConfiguredSqlColumn(value: string, field: string): string {
  const normalized = value.replace(/[-_]/g, "").toLowerCase();
  if (["secret", "clientsecret", "token", "accesstoken", "refreshtoken", "idtoken"].includes(normalized)) {
    throw new TypeError(`Sensitive SQL column name for ${field} is not allowed`);
  }
  return validateApplicationSqlIdentifier(value, `column ${field}`);
}

export function validateApplicationSqlIdentifier(value: unknown, field = "identifier"): string {
  if (typeof value !== "string") throw new TypeError(`${field} must be a string`);
  const normalized = value.trim();
  if (normalized !== value) throw new TypeError(`Invalid SQL identifier for ${field}`);
  const segments = normalized.split(".");
  if (segments.length < 1 || segments.length > 2 || segments.some((segment) => !/^[A-Za-z_][A-Za-z0-9_]*$/u.test(segment) || segment.length > 63)) {
    throw new TypeError(`Invalid SQL identifier for ${field}`);
  }
  return segments.join(".");
}

export function quoteApplicationSqlIdentifier(value: unknown, field = "identifier"): string {
  return validateApplicationSqlIdentifier(value, field).split(".").map((segment) => `"${segment}"`).join(".");
}

function isExecutor(value: unknown): value is ApplicationSqlExecutor {
  return isRecord(value) && typeof value.query === "function";
}

function resultRows(value: unknown): unknown[] | undefined {
  if (Array.isArray(value)) return value;
  if (!isRecord(value)) return undefined;
  return Array.isArray(value.rows) ? value.rows : undefined;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function normalizeSqlOpaqueReference(value: unknown, kind: string): string {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]{16,512}$/u.test(value)) throw new Error(`Invalid ${kind} reference`);
  return value;
}

function opaqueSessionTtlMilliseconds(value: number | undefined): number {
  const seconds = value ?? 60 * 60 * 24 * 30;
  if (!Number.isSafeInteger(seconds) || seconds < 60 || seconds > 60 * 60 * 24 * 365) throw new Error("Invalid opaque client session lifetime");
  return seconds * 1000;
}

function webviewTicketTtlMilliseconds(value: number | undefined): number {
  const seconds = value ?? 5 * 60;
  if (!Number.isSafeInteger(seconds) || seconds < 30 || seconds > 15 * 60) throw new Error("Invalid webview ticket lifetime");
  return seconds * 1000;
}

function requiredDateText(value: unknown, kind: string): string {
  const date = value instanceof Date ? value : new Date(typeof value === "string" || typeof value === "number" ? value : NaN);
  if (Number.isNaN(date.getTime())) throw new Error(`Invalid SQL ${kind} date`);
  return date.toISOString();
}

function isApplicationLoopbackHost(hostname: string): boolean {
  return hostname === "localhost" || hostname === "127.0.0.1" || hostname === "[::1]";
}

function normalizeWebviewRedirectUri(value: unknown): string {
  if (typeof value !== "string" || value.length === 0 || value.length > 2048 || value !== value.trim() || /[\u0000-\u001f\u007f\s\\]/u.test(value)) throw new Error("Invalid SQL webview ticket redirect URI");
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error("Invalid SQL webview ticket redirect URI");
  }
  if (
    (parsed.protocol !== "https:" && parsed.protocol !== "http:") ||
    (parsed.protocol !== "https:" && !isApplicationLoopbackHost(parsed.hostname)) ||
    parsed.username !== "" ||
    parsed.password !== "" ||
    parsed.hash !== "" ||
    parsed.hostname.length === 0
  ) throw new Error("Invalid SQL webview ticket redirect URI");
  return value;
}

function requiredString(value: unknown, kind: string): string {
  if (typeof value !== "string" || value.trim().length === 0) throw new Error(`Invalid SQL ${kind} row`);
  return value;
}

function rowValue(row: SqlRecord, key: string): unknown {
  const snake = key.replace(/[A-Z]/gu, (letter) => `_${letter.toLowerCase()}`);
  for (const candidate of [key, snake]) {
    if (Object.prototype.hasOwnProperty.call(row, candidate)) return row[candidate];
  }
  return undefined;
}

function requiredExternalText(value: unknown, field: string, maxLength: number): string {
  if (typeof value !== "string") throw new Error(`Invalid external identity ${field}`);
  const normalized = value.trim();
  if (normalized.length === 0 || normalized.length > maxLength || /[\u0000-\u001f\u007f]/u.test(normalized)) {
    throw new Error(`Invalid external identity ${field}`);
  }
  return normalized;
}

function optionalExternalText(value: unknown, field: string, maxLength: number): string | null {
  if (value === undefined || value === null || value === "") return null;
  return requiredExternalText(value, field, maxLength);
}

function normalizeExternalScopes(value: readonly string[] | undefined): string[] {
  return [...new Set((value ?? []).map((item) => requiredExternalText(item, "scope", 128)))].sort();
}

function textValue(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  const normalized = value.trim();
  return normalized.length > 0 && !/[\u0000-\u001f\u007f]/u.test(normalized) ? normalized : undefined;
}

function assignText<T extends object>(target: T, key: string, value: unknown): void {
  const normalized = textValue(value);
  if (normalized !== undefined) (target as Record<string, unknown>)[key] = normalized;
}

function assignDate<T extends object>(target: T, key: string, value: unknown): void {
  if (value instanceof Date) {
    if (!Number.isNaN(value.getTime())) (target as Record<string, unknown>)[key] = new Date(value.getTime());
    return;
  }
  if (typeof value === "string" && value.length <= 128 && !Number.isNaN(new Date(value).getTime())) {
    (target as Record<string, unknown>)[key] = value;
  }
}

function jsonArray(value: unknown): string[] {
  if (Array.isArray(value)) return value.filter((item): item is string => typeof item === "string");
  if (typeof value !== "string" || value.trim().length === 0) return [];
  try {
    const parsed: unknown = JSON.parse(value);
    return Array.isArray(parsed) ? parsed.filter((item): item is string => typeof item === "string") : [];
  } catch {
    return [];
  }
}

function booleanValue(value: unknown): boolean | undefined {
  if (typeof value === "boolean") return value;
  if (value === "true") return true;
  if (value === "false") return false;
  return undefined;
}

function readCount(value: unknown): number {
  return readNumber(value) ?? 0;
}

function readNumber(value: unknown): number | undefined {
  if (typeof value === "number" && Number.isSafeInteger(value)) return value;
  if (typeof value === "bigint" && value >= 0n && Number.isSafeInteger(Number(value))) return Number(value);
  if (typeof value === "string" && /^\d+$/u.test(value)) {
    const parsed = Number(value);
    return Number.isSafeInteger(parsed) ? parsed : undefined;
  }
  return undefined;
}

function nextVersion(value: unknown): number {
  const current = readNumber(value) ?? 0;
  return current < 1 ? 1 : current + 1;
}

function currentVersion(value: { version?: unknown }): number {
  return readNumber(value.version) ?? 1;
}

function normalizeReadiness(value: unknown): "ready" | "not_ready" | "unknown" | undefined {
  if (value === "ready" || value === "not_ready" || value === "unknown") return value;
  if (typeof value === "string") return "unknown";
  return undefined;
}

function readinessForRecord(record: {
  status?: unknown;
  lifecycleStatus?: unknown;
  name?: unknown;
  slug?: unknown;
  type?: unknown;
  clientId?: unknown;
  secretRef?: unknown;
  credentialConfigured?: unknown;
  hasSecret?: unknown;
   tokenEndpointAuthMethod?: unknown;
   componentAppId?: unknown;
   componentAppSecretRef?: unknown;
   componentBinding?: unknown;
   readiness?: unknown;

}): "ready" | "not_ready" {
  const status = lifecycleStatusOf(record);
  if (status !== "active") return "not_ready";
  if ("name" in record || "slug" in record) {
    return typeof record.name === "string" && record.name.trim().length > 0 && typeof record.slug === "string" && record.slug.trim().length > 0 ? "ready" : "not_ready";
  }
  if (record.tokenEndpointAuthMethod === "private_key_jwt" || record.tokenEndpointAuthMethod === "none") return "ready";
  if ("componentAppId" in record || "componentAppSecretRef" in record || "componentBinding" in record) {
    return record.credentialConfigured === true || record.hasSecret === true || textValue(record.componentAppSecretRef) !== undefined || record.componentBinding !== undefined ? "ready" : "not_ready";
  }
  if ("type" in record || "clientId" in record) {
    return record.credentialConfigured === true || record.hasSecret === true || textValue(record.secretRef) !== undefined ? "ready" : "not_ready";
  }
  return "ready";
}

function effectiveStatusForRecord(record: { status?: unknown; lifecycleStatus?: unknown; name?: unknown; slug?: unknown; type?: unknown; clientId?: unknown; secretRef?: unknown; credentialConfigured?: unknown; hasSecret?: unknown; tokenEndpointAuthMethod?: unknown; readiness?: unknown }): string {
  const status = lifecycleStatusOf(record);
  if (status === "archived" || status === "purged") return status;
  return readinessForRecord(record) === "ready" ? status : "not_ready";
}

function readinessBoolean(value: unknown): boolean {
  return value === true || value === "true" || value === 1 || value === "1";
}

function storageValue(field: string, value: unknown): unknown {
  if (["scopes", "redirectUris", "postLogoutRedirectUris", "grantTypes", "responseTypes"].includes(field)) {
    return JSON.stringify(Array.isArray(value) ? value : []);
  }
  return value;
}

function platformComponentSqlValues(input: {
  componentAppId?: string | null;
  componentAppSecretRef?: string | null;
  componentVerifyTicketRef?: string | null;
  componentAccessTokenRef?: string | null;
  authorizedAppId?: string | null;
  authorizerAppId?: string | null;
  authorizerRefreshTokenRef?: string | null;
  authorizerAccessTokenRef?: string | null;
  componentTicketRef?: string | null;
  componentTicketExpiresAt?: string | null;
  componentBindingStatus?: string | null;
  componentBindingVersion?: string | number | null;
  componentScope?: string | null;
  componentBinding?: unknown;
}): Record<string, unknown> {
  return Object.fromEntries(Object.entries(input).filter(([key]) => key.startsWith("component") || key === "authorizedAppId" || key === "authorizerAppId" || key === "authorizerRefreshTokenRef" || key === "authorizerAccessTokenRef").filter(([, value]) => value !== undefined));
}

function stripSqlComponentSecrets(value: Record<string, unknown>): void {
  for (const key of ["componentAppSecretRef", "componentVerifyTicketRef", "componentAccessTokenRef", "authorizerRefreshTokenRef", "authorizerAccessTokenRef", "componentTicketRef"]) delete value[key];
}

function platformInputValues(input: ApplicationPlatformMutationRequest): Record<string, unknown> {
  const values: Record<string, unknown> = {};
  if (input.type !== undefined) values.type = input.type;
  if (input.externalAppId !== undefined) values.externalAppId = input.externalAppId;
  if (input.displayName !== undefined) values.displayName = input.displayName;
  if (input.loginMode !== undefined) values.loginMode = input.loginMode;
  if (input.scope !== undefined) values.scope = input.scope;
  if (input.redirectUris !== undefined) values.redirectUris = input.redirectUris;
  if (input.endpointUrl !== undefined) values.endpointUrl = input.endpointUrl;
  if (input.secretRef !== undefined) values.secretRef = input.secretRef;
  Object.assign(values, platformComponentSqlValues(input));
  return values;
}

function clientInputValues(input: ApplicationClientMutationRequest): Record<string, unknown> {
  const values: Record<string, unknown> = {};
  if (input.clientId !== undefined) values.clientId = input.clientId;
  if (input.clientKind !== undefined) values.clientKind = input.clientKind;
  if (input.clientType !== undefined) values.clientType = input.clientType;
  if (input.redirectUriPolicy !== undefined) values.redirectUriPolicy = input.redirectUriPolicy;
  if (input.pkceMethod !== undefined) values.pkceMethod = input.pkceMethod;
  if (input.consent !== undefined) values.consent = input.consent;
  if (input.consentRequired !== undefined) values.consentRequired = input.consentRequired;
  if (input.requireExplicitConsent !== undefined) values.requireExplicitConsent = input.requireExplicitConsent;
  if (input.rpClient !== undefined) values.rpClient = input.rpClient;
  if (input.clientIdScope !== undefined) {
    if (input.clientIdScope !== "global") throw invalidRequest("OIDC clientIdScope must be global");
    values.clientIdScope = "global";
  }
  if (input.redirectUris !== undefined) values.redirectUris = input.redirectUris;
  if (input.postLogoutRedirectUris !== undefined) values.postLogoutRedirectUris = input.postLogoutRedirectUris;
  if (input.grantTypes !== undefined) values.grantTypes = input.grantTypes;
  if (input.responseTypes !== undefined) values.responseTypes = input.responseTypes;
  if (input.scopes !== undefined) values.scopes = input.scopes;
  if (input.tokenEndpointAuthMethod !== undefined) values.tokenEndpointAuthMethod = input.tokenEndpointAuthMethod;
  if (input.tokenEndpointAuthSigningAlg !== undefined) values.tokenEndpointAuthSigningAlg = input.tokenEndpointAuthSigningAlg;
  if (input.jwksUri !== undefined) values.jwksUri = input.jwksUri;
  if (input.privateKeyRef !== undefined) values.privateKeyRef = input.privateKeyRef;
  if (input.keyId !== undefined) values.keyId = input.keyId;
  if (input.requirePkce !== undefined) values.requirePkce = input.requirePkce;
  if (input.secretRef !== undefined) values.secretRef = input.secretRef;
  return values;
}

function normalizeStatus(value: unknown): ApplicationStatus {
  if (value === undefined || value === null || value === "") return "active";
  if (value === "active" || value === "disabled" || value === "archived" || value === "purged") return value;
  return "unknown" as ApplicationStatus;
}

function lifecycleStatusOf(record: { status?: unknown; lifecycleStatus?: unknown }): ApplicationStatus {
  const lifecycle = record.lifecycleStatus;
  if (lifecycle === "active" || lifecycle === "disabled" || lifecycle === "archived" || lifecycle === "purged") {
    return lifecycle;
  }
  return normalizeStatus(record.status);
}

export interface ApplicationKeysetCursor {
  version: number;
  kind: string;
  scope: string;
  tenantId: string;
  id: string;
  offset?: number;
}

export function encodeApplicationKeysetCursor(payload: ApplicationKeysetCursor): string {
  return Buffer.from(JSON.stringify(payload), "utf8").toString("base64url");
}

export function decodeApplicationKeysetCursor(
  cursor: string,
  kind: string,
  scope: string,
  tenantId: string,
): ApplicationKeysetCursor | undefined {
  try {
    const parsed = JSON.parse(Buffer.from(cursor, "base64url").toString("utf8")) as Partial<ApplicationKeysetCursor>;
    if (
      parsed.version !== CURSOR_VERSION ||
      parsed.kind !== kind ||
      parsed.scope !== scope ||
      parsed.tenantId !== tenantId ||
      typeof parsed.id !== "string" ||
      parsed.id.length === 0
    ) {
      if (parsed.version === CURSOR_VERSION && typeof parsed.offset === "number") return undefined;
      throw new Error("invalid keyset cursor");
    }
    return {
      version: CURSOR_VERSION,
      kind,
      scope,
      tenantId,
      id: parsed.id,
    };
  } catch {
    throw invalidRequest("Invalid pagination cursor", { field: "cursor" });
  }
}

function cursorOffset(
  kind: string,
  scope: string,
  cursor: string | undefined,
  offset: number | undefined,
): number {
  return cursor === undefined ? offset ?? 0 : decodeApplicationCursor(cursor, kind, scope);
}

function externalIdentityScope(applicationId: string, query: { search?: string; q?: string; provider?: string; platformId?: string }): string {
  return JSON.stringify([applicationId, query.search ?? query.q ?? "", query.provider ?? "", query.platformId ?? ""]);
}

function applicationScope(query: { search?: string; q?: string; status?: string; applicationType?: string; readiness?: string; effectiveStatus?: string }): string {
  return JSON.stringify([query.search ?? query.q ?? "", query.status ?? "", query.applicationType ?? "", query.readiness ?? "", query.effectiveStatus ?? ""]);
}

function platformScope(applicationId: string, query: { search?: string; q?: string; status?: string; readiness?: string; effectiveStatus?: string }): string {
  return JSON.stringify([applicationId, query.search ?? query.q ?? "", query.status ?? "", query.readiness ?? "", query.effectiveStatus ?? ""]);
}

function clientScope(applicationId: string, query: { search?: string; q?: string; status?: string; readiness?: string; effectiveStatus?: string; clientKind?: string }): string {
  return JSON.stringify([applicationId, query.search ?? query.q ?? "", query.status ?? "", query.readiness ?? "", query.effectiveStatus ?? "", query.clientKind ?? ""]);
}

function whereText(clauses: readonly string[]): string {
  return clauses.length === 0 ? "" : ` WHERE ${clauses.join(" AND ")}`;
}

function contextValue(value: unknown): string | undefined {
  return textValue(value);
}

function safeJson(value: unknown): string {
  try {
    return JSON.stringify(value) ?? "null";
  } catch {
    return "{}";
  }
}

function isUniqueViolation(value: unknown): boolean {
  if (!isRecord(value)) return false;
  if (value.code === "23505") return true;
  const message = typeof value.message === "string" ? value.message.toLowerCase() : "";
  return message.includes("unique") || message.includes("duplicate");
}

function sqlQueryError(cause: unknown): Error {
  const error = new Error("Application SQL query failed");
  Object.defineProperty(error, "cause", {
    configurable: true,
    enumerable: false,
    value: cause,
    writable: false,
  });
  return error;
}
