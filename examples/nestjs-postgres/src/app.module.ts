import "reflect-metadata";
import { createHmac, randomBytes, randomUUID } from "node:crypto";
import { Module } from "@nestjs/common";
import {
  ExplicitPlatformIdentityLinker,
  buildRoleGraph,
  buildTableMap,
  createPlatformSessionIssuerBridge,
  createPostgresPlatformLoginStateStore,
  createWechatComponentAccessTokenResolver,
  createWechatOfficialAccountAdapter,
  createWechatOpenPlatformAdapter,
  type PlatformBetterAuthAccount,
  type PlatformIdentity,
  type WechatComponentAccountBindingInput,
  type WechatApplicationSecretResolverInput,
  type PlatformIdentityCreateUserInput,
  type PlatformIdentityLinkResult,
  type PlatformIdentityLinkAccountInput,
  type PlatformIdentityLinkStore,
  type PlatformPublicUser,
  type PlatformSessionIssueInput,
  type PlatformSessionIssueResult,
} from "@getbrick/idaas-core";
import {
  ApplicationManagementModule,
  ControlPlaneModule,
  InMemoryControlPlaneRepository,
  createApplicationPlatformIdentitySessionBoundary,
  createApplicationPlatformWebviewTicketService,
  createOpaqueClientSessionIssuer,
  getTenantTransactionExecutor,
  type ApplicationPlatformHostTransaction,
  type OpaqueHostSessionIssueResult,
  type TenantSqlExecutor,
} from "@getbrick/idaas-control-plane";
import { GetbrickOidcModule } from "@getbrick/idaas-nestjs";
import { OidcPlatformLoginController } from "./oidc-platform-login.js";
import { idaas } from "../getbrick.config.js";
import {
  applicationOidcClientStore,
  applicationRepository,
   applicationSqlExecutor,
   PostgresOpaqueClientSessionStore,
   auth,
  identityRepository,
  oidcAdapter,
  oidcClientSecrets,
  secretBindingRepository,
  tenantRepository,
  findOidcUser,
} from "./auth.js";

const controlPlaneRepository = new InMemoryControlPlaneRepository({
  users: [
    {
      id: "example-user",
      name: "Example User",
      email: "user@example.com",
      role: "user",
    },
  ],
});

const platformTables = buildTableMap(idaas.tables);
const platformStateSqlExecutor: TenantSqlExecutor = {
  query: (text, values) => {
    const executor = getTenantTransactionExecutor(applicationSqlExecutor) ?? applicationSqlExecutor;
    return executor.query(text, values);
  },
  transaction: applicationSqlExecutor.transaction === undefined
    ? undefined
    : <T>(callback: (executor: TenantSqlExecutor) => Promise<T>) => applicationSqlExecutor.transaction!(callback),
};
const platformStateStore = createPostgresPlatformLoginStateStore(platformStateSqlExecutor, {
  tableName: "gb_idaas_platform_login_state",
  tenantId: applicationRepository.tenantId,
  initializeSchema: false,
});
const componentAdapters = createComponentAdapters();
const identityLinker = new ExplicitPlatformIdentityLinker(createHostIdentityStore());
const hostSecret = process.env.BETTER_AUTH_SECRET ?? process.env.IDAAS_SECRET ?? (typeof auth.options.secret === "string" ? auth.options.secret : undefined);
const sessionResponses = new Map<string, Response>();
const opaqueClientSessionStore = new PostgresOpaqueClientSessionStore({
  executor: applicationSqlExecutor,
  namespace: "getbrick-example",
  encryptionKey: hostSecret ?? (typeof auth.options.secret === "string" ? auth.options.secret : randomBytes(32).toString("hex")),
});
const webviewTicketService = createApplicationPlatformWebviewTicketService();
const identitySessionBoundary = createApplicationPlatformIdentitySessionBoundary();
const hostTransaction: ApplicationPlatformHostTransaction = (operation) => {
  if (typeof applicationSqlExecutor.transaction !== "function") throw new Error("host platform transactions are not configured");
  return applicationSqlExecutor.transaction(operation);
};
const webSessionIssuer = createPlatformSessionIssuerBridge(issueHostWebSession);
const platformSessionIssuer = createOpaqueClientSessionIssuer({
  store: opaqueClientSessionStore,
  host: {
    issue: issueHostClientSession,
    refresh: refreshHostClientSession,
    revoke: revokeHostClientSession,
  },
  webSessionIssuer,
});

@Module({
  controllers: [OidcPlatformLoginController],
  imports: [
    ControlPlaneModule.forRoot({
      auth,
      profile: idaas.profile,
      rbac: buildRoleGraph(idaas),
      repository: controlPlaneRepository,
      readiness: async () => {
        if (!(await applicationRepository.isReady())) return false;
        if (!(await tenantRepository.isReady())) return false;
        if (!(await identityRepository.isReady())) return false;
        if (!(await secretBindingRepository.isReady())) return false;
         if (!(await platformStateStore.ready())) return false;
         if (!(await opaqueClientSessionStore.ready())) return false;
         if (!(await webviewTicketService.ready())) return false;
         await oidcAdapter.ready();
        return true;
      },
    }),
    ApplicationManagementModule.forRoot({
      auth,
      profile: idaas.profile,
      rbac: buildRoleGraph(idaas),
      repository: applicationRepository,
      tenantRepository,
      identityRepository,
      secretBindingRepository,
       platformAuth: {
          adapters: componentAdapters,
          stateStore: platformStateStore,
         identityLinker,
         sessionIssuer: platformSessionIssuer,
         sessionService: platformSessionIssuer,
         webviewTicketService,
         identitySessionBoundary,
         hostTransaction,
         requireOpaqueClientSession: true,
         resolveHostContext,
        resolveSecret: async (secretRef) => {
          const secretNames: Record<string, string> = {
            "env:WECHAT_OFFICIAL_SECRET": "WECHAT_OFFICIAL_SECRET",
            "env:WECHAT_OPEN_PLATFORM_SECRET": "WECHAT_OPEN_PLATFORM_SECRET",
            "env:WECHAT_MINI_PROGRAM_SECRET": "WECHAT_MINI_PROGRAM_SECRET",
            "env:WECHAT_MINI_SECRET": "WECHAT_MINI_SECRET",
          };
          const secretName = secretNames[secretRef];
          const value = secretName === undefined ? undefined : process.env[secretName];
          if (!value) throw new Error("application platform secret is not configured");
          return value;
        },
      },
    }),
    GetbrickOidcModule.forRoot({
      auth,
      config: idaas,
      findUser: findOidcUser,
      adapter: oidcAdapter,
       clientStore: applicationOidcClientStore,
       clientSecrets: oidcClientSecrets,
       ...(idaas.profile === "production" ? {} : { consentResolver: async () => true }),
     }),
  ],
})
export class AppModule {}

export {
  identityLinker as platformIdentityLinker,
  platformSessionIssuer,
  platformSessionIssuer as platformSessionIssuerBridge,
  platformStateStore,
  componentAdapters,
  opaqueClientSessionStore,
  webviewTicketService,
  identitySessionBoundary,
  hostTransaction,
};

function createComponentAdapters() {
  const componentAppId = readOptionalEnvironment("WECHAT_COMPONENT_APP_ID");
  const componentAppSecret = readOptionalEnvironment("WECHAT_COMPONENT_APP_SECRET");
  const componentVerifyTicket = readOptionalEnvironment("WECHAT_COMPONENT_VERIFY_TICKET");
  if (componentAppId === undefined || componentAppSecret === undefined || componentVerifyTicket === undefined) return [];
  const componentAccessTokenResolver = createWechatComponentAccessTokenResolver({
    componentAppId,
    componentAppSecret: () => readOptionalEnvironment("WECHAT_COMPONENT_APP_SECRET") ?? componentAppSecret,
    componentVerifyTicket: () => readOptionalEnvironment("WECHAT_COMPONENT_VERIFY_TICKET") ?? componentVerifyTicket,
  });
  const resolveBinding = async (input: { componentAppId: string; authorizedAppId: string }): Promise<WechatComponentAccountBindingInput | undefined> => {
    if (input.componentAppId !== componentAppId) return undefined;
    const applications = await applicationRepository.listApplications({ limit: 1000 });
    for (const application of applications.items) {
      const platforms = await applicationRepository.listPlatforms(application.id, { limit: 1000 });
      const platform = platforms.items.find((item) =>
        item.componentAppId === componentAppId &&
        (item.authorizedAppId === input.authorizedAppId || item.authorizerAppId === input.authorizedAppId),
      );
      if (platform !== undefined) {
        return {
          componentAppId,
          authorizedAppId: input.authorizedAppId,
        };
      }
    }
    return undefined;
  };
  const resolveAppSecret = async (input: WechatApplicationSecretResolverInput): Promise<string> => {
    if (input.componentAppId !== componentAppId) throw new Error("component binding is invalid");
    const value = readOptionalEnvironment("WECHAT_COMPONENT_AUTHORIZED_APP_SECRET") ?? readOptionalEnvironment("WECHAT_AUTHORIZED_APP_SECRET");
    if (value === undefined) throw new Error("authorized account secret is not configured");
    return value;
  };
  return [
    createWechatOfficialAccountAdapter({
      componentAppId,
      componentAccessTokenResolver,
      resolveBinding,
    }),
    createWechatOpenPlatformAdapter({
      componentAppId,
      componentAccessTokenResolver,
      resolveBinding,
      resolveAppSecret,
    }),
  ];
}

function readOptionalEnvironment(name: string): string | undefined {
  const value = process.env[name];
  return typeof value === "string" && value.trim().length > 0 ? value.trim() : undefined;
}

type HostIdentityContext = {
  tenantId: string;
  applicationId: string;
  platformId: string;
  identity: PlatformIdentity;
  identityKey?: string;
};

type HostAuth = {
  options?: {
    secret?: string;
    baseURL?: string;
    advanced?: { cookiePrefix?: string; useSecureCookies?: boolean };
  };
  api: {
    signUpEmail(input: {
      body: { email: string; password: string; name: string; image?: string };
      asResponse?: boolean;
    }): Promise<unknown>;
     getSession(input: { headers: Headers; query?: { disableCookieCache?: boolean; disableRefresh?: boolean } }): Promise<unknown>;
    signOut(input: { headers: Headers; asResponse?: boolean }): Promise<unknown>;
    revokeSession(input: { headers: Headers; body: { token: string } }): Promise<unknown>;
  };
};

function createHostIdentityStore(): PlatformIdentityLinkStore {
  return {
    async findByIdentity(identityKey: string, context?: HostIdentityContext): Promise<PlatformIdentityLinkResult | undefined> {
      const rows = await queryRows(
        `SELECT a."providerId", a."accountId", a."userId", u.name, u.email, u."emailVerified", u.image FROM ${quoted(platformTables.account)} a INNER JOIN ${quoted(platformTables.user)} u ON u.id = a."userId" WHERE a."providerId" = $1 AND a."accountId" = $2 LIMIT 1`,
        [identityKey, context?.identity.subject ?? ""],
      );
      const row = rows[0];
      return row === undefined ? undefined : hostLinkResult(row, context);
    },
    async findByEmail(email: string, context?: HostIdentityContext): Promise<PlatformIdentityLinkResult | undefined> {
      if (context === undefined || typeof context.tenantId !== "string" || typeof context.applicationId !== "string") return undefined;
      const scopePrefix = `${encodeURIComponent(context.tenantId)}|${encodeURIComponent(context.applicationId)}|`;
      const rows = await queryRows(
        `SELECT u.id, u.name, u.email, u."emailVerified", u.image FROM ${quoted(platformTables.user)} u WHERE LOWER(u.email) = LOWER($1) AND EXISTS (SELECT 1 FROM ${quoted(platformTables.account)} a WHERE a."userId" = u.id AND LEFT(a."providerId", LENGTH($2)) = $2) LIMIT 1`,
        [email, scopePrefix],
      );
      const row = rows[0];
      if (row === undefined) return undefined;
      const user = hostUserResult(row);
      return { userId: user.id, user };
    },
    async createUser(input: PlatformIdentityCreateUserInput): Promise<PlatformIdentityLinkResult> {
      const user = await createHostUser(input);
      if (typeof user.id !== "string") throw new Error("host user creation returned no user id");
      const userId = user.id;
      try {
        const linkedUserId = await insertHostAccount(input, userId, input.identityKey);
        if (linkedUserId !== userId) {
          if (hostSecret === undefined) sessionResponses.delete(userId);
          await removeHostUser(userId);
          return {
            userId: linkedUserId,
            user: await findHostUser(linkedUserId),
            account: hostAccount(input),
            accountId: input.identity.subject,
            created: false,
          };
        }
        return {
          userId,
          user: hostUserFromInput(input, userId),
          account: hostAccount(input),
          accountId: input.identity.subject,
        };
      } catch (error) {
        await removeHostUser(userId);
        throw error;
      }
    },
    async linkIdentity(input: PlatformIdentityLinkAccountInput): Promise<PlatformIdentityLinkResult> {
      await insertHostAccount(input, input.userId, input.identityKey);
      return {
        userId: input.userId,
        user: await findHostUser(input.userId),
        account: hostAccount(input),
        accountId: input.identity.subject,
      };
    },
  };
}

async function insertHostAccount(
  input: PlatformIdentityCreateUserInput | PlatformIdentityLinkAccountInput,
  userId: string,
  identityKey: string,
): Promise<string> {
  return inTransaction(async (executor) => {
    await executor.query("SELECT pg_advisory_xact_lock(hashtext($1))", [identityKey]);
    const existing = await queryRows(
      `SELECT "providerId", "accountId", "userId" FROM ${quoted(platformTables.account)} WHERE "providerId" = $1 AND "accountId" = $2 LIMIT 1`,
      [identityKey, input.identity.subject],
      executor,
    );
    if (existing[0] !== undefined) {
      if (existing[0].userId !== userId) {
        if ("userId" in input) throw new Error("platform identity is linked to another user");
        return String(existing[0].userId);
      }
      return userId;
    }
    const user = await queryRows(
      `SELECT id FROM ${quoted(platformTables.user)} WHERE id = $1 LIMIT 1`,
      [userId],
      executor,
    );
    if (user[0] === undefined) throw new Error("platform identity target user does not exist");
    await executor.query(
      `INSERT INTO ${quoted(platformTables.account)} (id, "accountId", "providerId", "userId", scope, "createdAt", "updatedAt") VALUES ($1, $2, $3, $4, $5, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`,
      [randomUUID(), input.identity.subject, identityKey, userId, input.identity.scopes.join(" ")],
    );
    return userId;
  });
}

async function createHostUser(input: PlatformIdentityCreateUserInput): Promise<Record<string, unknown>> {
  const hostAuth = auth as unknown as HostAuth;
  const responseValue = await hostAuth.api.signUpEmail({
    body: {
      email: input.projection.betterAuthUser.email,
      password: `${randomBytes(32).toString("base64url")}Aa1!`,
      name: input.projection.betterAuthUser.name,
      ...(input.projection.betterAuthUser.image === undefined ? {} : { image: input.projection.betterAuthUser.image }),
    },
    asResponse: true,
  });
  const response = asResponse(responseValue);
  const body = await readResponseBody(response);
  if (!isRecord(body.user) || typeof body.user.id !== "string") throw new Error("host user creation returned no user");
  if (hostSecret === undefined) sessionResponses.set(body.user.id, response);
  return body.user;
}

function hostUserFromInput(input: PlatformIdentityCreateUserInput, userId: string): PlatformPublicUser {
  return {
    id: userId,
    name: input.projection.betterAuthUser.name,
    email: input.projection.publicEmail,
    emailVerified: input.projection.betterAuthUser.emailVerified,
    ...(input.projection.publicUser.image === undefined ? {} : { image: input.projection.publicUser.image }),
  };
}

function hostUserResult(row: Record<string, unknown>): PlatformPublicUser & { id: string } {
  const id = typeof row.id === "string" ? row.id : typeof row.userId === "string" ? row.userId : "";
  const email = typeof row.email === "string" && !row.email.endsWith("@placeholder.invalid") ? row.email : null;
  return {
    id,
    name: typeof row.name === "string" ? row.name : "Platform user",
    email,
    emailVerified: row.emailVerified === true || row.emailVerified === "true",
    ...(typeof row.image === "string" ? { image: row.image } : {}),
  };
}

function hostLinkResult(row: Record<string, unknown>, context?: HostIdentityContext): PlatformIdentityLinkResult {
  const user = hostUserResult(row);
  return {
    userId: user.id,
    ...(context === undefined ? {} : { tenantId: context.tenantId, applicationId: context.applicationId }),
    user,
    account: {
      providerId: typeof row.providerId === "string" ? row.providerId : "",
      accountId: typeof row.accountId === "string" ? row.accountId : "",
      platform: context?.identity.platform ?? (typeof row.providerId === "string" ? row.providerId : ""),
      appId: context?.identity.appId ?? "",
      scopes: context?.identity.scopes === undefined ? [] : [...context.identity.scopes],
      ...(context === undefined ? {} : { tenantId: context.tenantId, applicationId: context.applicationId, providerAppId: context.identity.appId, identityKey: context.identityKey }),
    },
    accountId: typeof row.accountId === "string" ? row.accountId : "",
  };
}

function hostAccount(input: PlatformIdentityCreateUserInput): PlatformBetterAuthAccount {
  return {
    providerId: input.identityKey,
    accountId: input.identity.subject,
    platform: input.identity.platform,
    appId: input.identity.appId,
    scopes: [...input.identity.scopes],
    tenantId: input.projection.tenantId,
    applicationId: input.projection.applicationId,
    providerAppId: input.identity.appId,
    identityKey: input.identityKey,
  };
}

async function findHostUser(userId: string): Promise<PlatformPublicUser | undefined> {
  const rows = await queryRows(
    `SELECT id, name, email, "emailVerified", image FROM ${quoted(platformTables.user)} WHERE id = $1 LIMIT 1`,
    [userId],
  );
  return rows[0] === undefined ? undefined : hostUserResult(rows[0]);
}

async function removeHostUser(userId: string): Promise<void> {
  await inTransaction(async (executor) => {
    await executor.query(`DELETE FROM ${quoted(platformTables.session)} WHERE "userId" = $1`, [userId]);
    await executor.query(`DELETE FROM ${quoted(platformTables.account)} WHERE "userId" = $1`, [userId]);
    await executor.query(`DELETE FROM ${quoted(platformTables.user)} WHERE id = $1`, [userId]);
  });
}

async function resolveHostContext(request: unknown): Promise<{ userId?: string; identityLinkingPolicy?: { mode: "link_existing"; userId: string } }> {
  const value = isRecord(request) ? request : undefined;
  const headers = new Headers();
  for (const [key, entry] of Object.entries(value?.headers ?? {})) {
    if (typeof entry === "string") headers.set(key, entry);
    else if (Array.isArray(entry)) for (const item of entry) if (typeof item === "string") headers.append(key, item);
  }
  try {
    const session = await (auth as unknown as HostAuth).api.getSession({ headers });
    const user = isRecord(session) && isRecord(session.user) ? session.user : undefined;
    if (typeof user?.id !== "string") return {};
    return { userId: user.id, identityLinkingPolicy: { mode: "link_existing", userId: user.id } };
  } catch {
    return {};
  }
}

async function inTransaction<T>(operation: (executor: TenantSqlExecutor) => Promise<T>): Promise<T> {
  const active = getTenantTransactionExecutor(applicationSqlExecutor);
  if (active !== undefined) return operation(active);
  if (typeof applicationSqlExecutor.transaction !== "function") {
    throw new Error("host platform identity writes require a transaction");
  }
  return applicationSqlExecutor.transaction(operation);
}

async function queryRows(text: string, values: unknown[], executor: TenantSqlExecutor = getTenantTransactionExecutor(applicationSqlExecutor) ?? applicationSqlExecutor): Promise<Record<string, unknown>[]> {
  const result = await executor.query(text, values);
  if (Array.isArray(result)) return result.filter(isRecord);
  return isRecord(result) && Array.isArray(result.rows) ? result.rows.filter(isRecord) : [];
}

function asResponse(value: unknown): Response {
  if (value instanceof Response) return value;
  return new Response(JSON.stringify(value), { status: 200, headers: { "content-type": "application/json" } });
}

async function readResponseBody(response: Response): Promise<Record<string, unknown>> {
  try {
    const value = JSON.parse(await response.clone().text()) as unknown;
    return isRecord(value) ? value : {};
  } catch {
    return {};
  }
}

async function issueHostWebSession(input: PlatformSessionIssueInput): Promise<PlatformSessionIssueResult | Response> {
  const response = sessionResponses.get(input.userId);
  if (hostSecret === undefined && response !== undefined) {
    sessionResponses.delete(input.userId);
    return responseWithoutBody(response);
  }
  const session = await findHostSession(input.userId, response);
  if (session === undefined) {
    if (input.created !== true) return new Response(null, { status: 204 });
    throw new Error("host session issuer is unavailable");
  }
  return hostSessionCookieResponse(session.token, session.expiresAt);
}

async function issueHostClientSession(input: PlatformSessionIssueInput): Promise<OpaqueHostSessionIssueResult> {
  const response = sessionResponses.get(input.userId);
  const session = await findHostSession(input.userId, response);
  if (session === undefined) throw new Error("host session issuer is unavailable");
  if (response !== undefined) sessionResponses.delete(input.userId);
  return {
    hostSessionToken: session.token,
    expiresAt: dateValue(session.expiresAt),
  };
}

async function refreshHostClientSession(input: { record: { hostSessionToken: string; userId: string; expiresAt: number }; runtimeRequest?: unknown }): Promise<OpaqueHostSessionIssueResult> {
  const headers = hostSessionHeaders(input.record.hostSessionToken);
  const value = await (auth as unknown as HostAuth).api.getSession({
    headers,
    query: { disableCookieCache: true, disableRefresh: false },
  });
  if (!isRecord(value) || !isRecord(value.session)) throw new Error("host session is unavailable");
  const token = typeof value.session.token === "string" ? value.session.token : input.record.hostSessionToken;
  const expiresAt = value.session.expiresAt ?? new Date(input.record.expiresAt).toISOString();
  return { hostSessionToken: token, expiresAt: dateValue(expiresAt), userId: input.record.userId };
}

async function revokeHostClientSession(input: { record: { hostSessionToken: string; userId: string }; runtimeRequest?: unknown }): Promise<void> {
  const hostAuth = auth as unknown as HostAuth;
  try {
    await hostAuth.api.revokeSession({
      headers: hostSessionHeaders(input.record.hostSessionToken),
      body: { token: input.record.hostSessionToken },
    });
  } catch {
    await inTransaction(async (executor) => {
      await executor.query(`DELETE FROM ${quoted(platformTables.session)} WHERE "userId" = $1 AND token = $2`, [input.record.userId, input.record.hostSessionToken]);
    });
  }
}

async function findHostSession(userId: string, response: Response | undefined): Promise<{ token: string; expiresAt: unknown } | undefined> {
  if (response !== undefined) {
    const body = await readResponseBody(response);
    if (typeof body.token === "string") {
      const expiresAt = typeof body.expiresAt === "string" || body.expiresAt instanceof Date || typeof body.expiresAt === "number" ? body.expiresAt : undefined;
      if (expiresAt !== undefined) return { token: body.token, expiresAt };
    }
  }
  const rows = await queryRows(
    `SELECT token, "expiresAt" FROM ${quoted(platformTables.session)} WHERE "userId" = $1 AND "expiresAt" > CURRENT_TIMESTAMP ORDER BY "createdAt" DESC LIMIT 1`,
    [userId],
  );
  const row = rows[0];
  return row === undefined || typeof row.token !== "string" ? undefined : { token: row.token, expiresAt: row.expiresAt };
}

function hostSessionCookieResponse(token: string, expiresAt: unknown): Response {
  if (hostSecret === undefined) throw new Error("BETTER_AUTH_SECRET is required for host sessions");
  const expiry = dateValue(expiresAt);
  const maxAge = Math.max(1, Math.floor((new Date(expiry).getTime() - Date.now()) / 1000));
  const signature = createHmac("sha256", hostSecret).update(token).digest("base64");
  const options = (auth as unknown as HostAuth).options;
  const prefix = typeof options?.advanced?.cookiePrefix === "string" ? options.advanced.cookiePrefix : "better-auth";
  const baseUrl = typeof options?.baseURL === "string" ? options.baseURL : undefined;
  const secure = options?.advanced?.useSecureCookies ?? (baseUrl?.startsWith("https://") ?? false);
  const name = `${secure ? "__Secure-" : ""}${prefix}.session_token`;
  const cookie = `${name}=${encodeURIComponent(`${token}.${signature}`)}; Max-Age=${maxAge}; Path=/; HttpOnly${secure ? "; Secure" : ""}; SameSite=Lax`;
  return new Response(null, { status: 204, headers: { "Set-Cookie": cookie } });
}

function hostSessionHeaders(token: string): Headers {
  if (hostSecret === undefined) return new Headers();
  const options = (auth as unknown as HostAuth).options;
  const prefix = typeof options?.advanced?.cookiePrefix === "string" ? options.advanced.cookiePrefix : "better-auth";
  const baseUrl = typeof options?.baseURL === "string" ? options.baseURL : undefined;
  const secure = options?.advanced?.useSecureCookies ?? (baseUrl?.startsWith("https://") ?? false);
  const name = `${secure ? "__Secure-" : ""}${prefix}.session_token`;
  const signature = createHmac("sha256", hostSecret).update(token).digest("base64");
  return new Headers({ cookie: `${name}=${encodeURIComponent(`${token}.${signature}`)}` });
}

function responseWithoutBody(response: Response): Response {
  const headers = new Headers();
  response.headers.forEach((value, key) => {
    if (key.toLowerCase() === "set-cookie" || key.toLowerCase() === "content-length") return;
    headers.set(key, value);
  });
  const cookies = response.headers.getSetCookie?.() ?? [];
  for (const cookie of cookies) headers.append("set-cookie", cookie);
  return new Response(null, { status: 204, headers });
}

function dateValue(value: unknown): string {
  const date = value instanceof Date ? value : new Date(typeof value === "string" || typeof value === "number" ? value : String(value));
  if (!Number.isFinite(date.getTime())) throw new Error("host session expiry is invalid");
  return date.toISOString();
}

function quoted(value: string): string {
  return value.split(".").map((part) => `"${part.replace(/"/gu, '""')}"`).join(".");
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
