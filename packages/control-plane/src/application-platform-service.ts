import { createHash, randomBytes } from "node:crypto";
import {
  ApplicationPlatformAdapterRegistry,
   ApplicationPlatformError,
   assertRegisteredPlatformRedirectUri,
   assertPlatformLoginReturnTo,
   createPlatformLoginFlow,
  sanitizePlatformIdentity,
  toSafeApplicationPlatformError,
  createWechatMiniProgramAdapter,
  createWechatOfficialAccountAdapter,
  createWechatOpenPlatformAdapter,
  isRfc8252PrivateUseRedirectUri,
  type ApplicationPlatformAuthAdapter,
  type ApplicationPlatformCodeExchangeInput,
  type ApplicationPlatformType,
  type PlatformIdentity,
  type PlatformIdentityLinker,
  type PlatformIdentityLinkingPolicy,
  type PlatformLoginBindingInput,
  type PlatformLoginFlow,
  type PlatformLoginHostContext,
  type PlatformLoginResult,
  type PlatformLoginStartResult,
  type PlatformLoginStateManager,
  type PlatformLoginStateStore,
  type PlatformSessionIssueInput,
  type PlatformSessionIssueResult,
  type PlatformSessionIssuerBridge,
  normalizePlatformSessionIssueResult,
} from "@getbrick/idaas-core";
import type { ApplicationStatus } from "@getbrick/idaas-contracts";
import type { SecretBindingRepository } from "./secret-binding.js";
import type {
  ApplicationPlatformRecord,
  ApplicationRepository,
  OpaqueClientSessionRepository,
  WebviewTicketRepository,
} from "./application-types.js";

type ApplicationPlatformAdapter = Omit<ApplicationPlatformAuthAdapter, "type"> & { readonly type: string };

export type ApplicationPlatformClient = "web" | "native" | "mini_program" | "mp_weixin" | "webview";
export type ApplicationPlatformOpaqueClient = Exclude<ApplicationPlatformClient, "web">;
export type OpaqueClientSessionClient = ApplicationPlatformOpaqueClient;
export type PlatformOpaqueClient = ApplicationPlatformOpaqueClient;

export interface OpaqueClientSessionRecord {
  sessionReference: string;
  userId: string;
  tenantId?: string;
  applicationId: string;
  platformId: string;
  identityKey?: string;
  client: ApplicationPlatformOpaqueClient;
  hostSessionToken: string;
  createdAt: number;
  expiresAt: number;
  updatedAt: number;
  revokedAt?: number;
}

export interface OpaqueClientSessionCreateInput {
  sessionReference?: string;
  userId: string;
  tenantId?: string;
  applicationId: string;
  platformId: string;
  identityKey?: string;
  client: ApplicationPlatformOpaqueClient;
  hostSessionToken: string;
  expiresAt: number;
  createdAt?: number;
}

export interface OpaqueClientSessionStore {
  create(input: OpaqueClientSessionCreateInput): Promise<OpaqueClientSessionRecord>;
  get(sessionReference: string): Promise<OpaqueClientSessionRecord | undefined>;
  findActive?(input: {
    userId: string;
    tenantId?: string;
    applicationId: string;
    platformId: string;
    identityKey?: string;
    client: ApplicationPlatformOpaqueClient;
  }): Promise<OpaqueClientSessionRecord | undefined>;
  rotate(sessionReference: string, update: { hostSessionToken?: string; expiresAt: number; client?: ApplicationPlatformOpaqueClient }): Promise<OpaqueClientSessionRecord>;
  revoke(sessionReference: string): Promise<boolean>;
  ready?(): boolean | Promise<boolean>;
}

export interface OpaqueHostSessionIssueResult {
  hostSessionToken: string;
  userId?: string;
  expiresAt: string | number | Date;
  response?: Response;
}

export interface OpaqueHostSessionRefreshInput {
  record: OpaqueClientSessionRecord;
  runtimeRequest?: unknown;
}

export interface OpaqueHostSessionRevokeInput {
  record: OpaqueClientSessionRecord;
  runtimeRequest?: unknown;
}

export interface OpaqueHostSessionAdapter {
  issue(input: PlatformSessionIssueInput): Promise<OpaqueHostSessionIssueResult>;
  refresh?(input: OpaqueHostSessionRefreshInput): Promise<OpaqueHostSessionIssueResult>;
  revoke?(input: OpaqueHostSessionRevokeInput): Promise<void>;
}

export interface OpaqueClientSessionResult {
  sessionReference: string;
  expiresAt: string;
  userId: string;
  applicationId: string;
  platformId: string;
  client: ApplicationPlatformOpaqueClient;
  identityKey?: string;
  refreshed?: boolean;
  revoked?: boolean;
}

export interface OpaqueClientSessionIssuerOptions {
  store: OpaqueClientSessionStore;
  host: OpaqueHostSessionAdapter;
  now?: () => number;
  webSessionIssuer?: PlatformSessionIssuerBridge;
}

export class InMemoryOpaqueClientSessionStore implements OpaqueClientSessionStore {
  private readonly records = new Map<string, OpaqueClientSessionRecord>();
  private readonly now: () => number;

  constructor(options: { now?: () => number } = {}) {
    this.now = options.now ?? Date.now;
  }

  async create(input: OpaqueClientSessionCreateInput): Promise<OpaqueClientSessionRecord> {
    const now = this.now();
    const sessionReference = normalizeOpaqueReference(input.sessionReference ?? createOpaqueReference("session"));
    if (this.records.has(sessionReference)) throw new ApplicationPlatformError("session_reference_collision", "Client session reference could not be created");
    const createdAt = input.createdAt ?? now;
    const record = normalizeOpaqueRecord({
      sessionReference,
      userId: input.userId,
      tenantId: input.tenantId,
      applicationId: input.applicationId,
      platformId: input.platformId,
      identityKey: input.identityKey,
      client: input.client,
      hostSessionToken: input.hostSessionToken,
      createdAt,
      expiresAt: input.expiresAt,
      updatedAt: now,
    });
    this.records.set(sessionReference, record);
    return cloneOpaqueRecord(record);
  }

  async get(sessionReference: string): Promise<OpaqueClientSessionRecord | undefined> {
    const value = this.records.get(normalizeOpaqueReference(sessionReference));
    if (value === undefined || value.revokedAt !== undefined || value.expiresAt <= this.now()) return undefined;
    return cloneOpaqueRecord(value);
  }

  async findActive(input: {
    userId: string;
    tenantId?: string;
    applicationId: string;
    platformId: string;
    identityKey?: string;
    client: ApplicationPlatformOpaqueClient;
  }): Promise<OpaqueClientSessionRecord | undefined> {
    const now = this.now();
    const value = [...this.records.values()].find((record) =>
      record.userId === input.userId &&
      (input.tenantId === undefined || record.tenantId === input.tenantId) &&
      record.applicationId === input.applicationId &&
      record.platformId === input.platformId &&
      record.client === input.client &&
      (input.identityKey === undefined || record.identityKey === input.identityKey) &&
      record.revokedAt === undefined &&
      record.expiresAt > now,
    );
    return value === undefined ? undefined : cloneOpaqueRecord(value);
  }

  async rotate(sessionReference: string, update: { hostSessionToken?: string; expiresAt: number; client?: ApplicationPlatformOpaqueClient }): Promise<OpaqueClientSessionRecord> {
    const normalized = normalizeOpaqueReference(sessionReference);
    const current = this.records.get(normalized);
    if (current === undefined || current.revokedAt !== undefined || current.expiresAt <= this.now()) throw new ApplicationPlatformError("session_not_found", "Client session is unavailable");
    const now = this.now();
    const rotated: OpaqueClientSessionRecord = {
      ...current,
      sessionReference: createOpaqueReference("session"),
      client: update.client ?? current.client,
      ...(update.hostSessionToken === undefined ? {} : { hostSessionToken: update.hostSessionToken }),
      expiresAt: update.expiresAt,
      updatedAt: now,
    };
    this.records.delete(normalized);
    this.records.set(rotated.sessionReference, rotated);
    return cloneOpaqueRecord(rotated);
  }

  async revoke(sessionReference: string): Promise<boolean> {
    const normalized = normalizeOpaqueReference(sessionReference);
    const current = this.records.get(normalized);
    if (current === undefined) return false;
    this.records.delete(normalized);
    return true;
  }

  async ready(): Promise<boolean> {
    return true;
  }
}

export class OpaqueClientSessionIssuer implements PlatformSessionIssuerBridge {
  private readonly store: OpaqueClientSessionStore;
  private readonly host: OpaqueHostSessionAdapter;
  private readonly now: () => number;
  private readonly webSessionIssuer?: PlatformSessionIssuerBridge;

  constructor(options: OpaqueClientSessionIssuerOptions) {
    if (!options || typeof options.store?.create !== "function" || typeof options.store.get !== "function" || typeof options.store.rotate !== "function" || typeof options.store.revoke !== "function" || typeof options.host?.issue !== "function") {
      throw new ApplicationPlatformError("invalid_session_issuer", "Opaque client session issuer is invalid");
    }
    this.store = options.store;
    this.host = options.host;
    this.now = options.now ?? Date.now;
    this.webSessionIssuer = options.webSessionIssuer;
  }

  async issue(input: PlatformSessionIssueInput): Promise<PlatformSessionIssueResult> {
    const client = normalizeClient(input.client);
    if (client === "web") {
      if (this.webSessionIssuer === undefined) throw new ApplicationPlatformError("invalid_session_issuer", "Web session issuer is not configured");
      return normalizePlatformSessionIssueResult(await this.webSessionIssuer.issue(input));
    }
    const identityKey = readIdentityKey(input);
    const existing = this.store.findActive === undefined ? undefined : await this.store.findActive({
      userId: input.userId,
      tenantId: input.tenantId,
      applicationId: input.applicationId,
      platformId: input.platformId,
      identityKey,
      client,
    });
    if (existing !== undefined) return opaqueResult(existing);
    let issued: OpaqueHostSessionIssueResult;
    try {
      issued = await this.host.issue(input);
    } catch (error) {
      if (error instanceof ApplicationPlatformError) throw error;
      throw new ApplicationPlatformError("session_issue_failed", "Client session could not be issued");
    }
    if (issued.response !== undefined) throw new ApplicationPlatformError("invalid_session_issuer_result", "Opaque client sessions cannot use a response");
    const expiresAt = dateTimestamp(issued.expiresAt);
    if (!Number.isSafeInteger(expiresAt) || expiresAt <= this.now()) throw new ApplicationPlatformError("session_issue_failed", "Host session expiry is invalid");
    const record = await this.store.create({
      userId: input.userId,
      ...(input.tenantId === undefined ? {} : { tenantId: input.tenantId }),
      applicationId: input.applicationId,
      platformId: input.platformId,
      ...(identityKey === undefined ? {} : { identityKey }),
      client,
      hostSessionToken: issued.hostSessionToken,
      expiresAt,
      createdAt: this.now(),
    });
    return opaqueResult(record);
  }

  async refresh(input: { sessionReference: string; runtimeRequest?: unknown; client?: ApplicationPlatformOpaqueClient }): Promise<OpaqueClientSessionResult> {
    const targetClient = input.client === undefined ? undefined : normalizeClient(input.client);
    if (targetClient === "web") throw new ApplicationPlatformError("invalid_session_reference", "Only opaque client sessions can be refreshed");
    const record = await this.store.get(input.sessionReference);
    if (record === undefined) throw new ApplicationPlatformError("session_not_found", "Client session is unavailable");
    if (this.host.refresh === undefined) return opaqueResult(record);
    let refreshed: OpaqueHostSessionIssueResult;
    try {
      refreshed = await this.host.refresh({ record, runtimeRequest: input.runtimeRequest });
    } catch (error) {
      if (error instanceof ApplicationPlatformError) throw error;
      throw new ApplicationPlatformError("session_refresh_failed", "Client session could not be refreshed");
    }
    const expiresAt = dateTimestamp(refreshed.expiresAt);
    if (!Number.isSafeInteger(expiresAt) || expiresAt <= this.now()) throw new ApplicationPlatformError("session_refresh_failed", "Host session expiry is invalid");
    const rotated = await this.store.rotate(record.sessionReference, {
      hostSessionToken: refreshed.hostSessionToken,
      expiresAt,
      ...(targetClient === undefined ? {} : { client: targetClient }),
    });
    return { ...opaqueResult(rotated), refreshed: true };
  }

  async logout(input: { sessionReference: string; runtimeRequest?: unknown }): Promise<OpaqueClientSessionResult> {
    return this.revoke(input, false);
  }

  async revoke(input: { sessionReference: string; runtimeRequest?: unknown }, force = true): Promise<OpaqueClientSessionResult> {
    const record = await this.store.get(input.sessionReference);
    if (record === undefined) {
      if (force) throw new ApplicationPlatformError("session_not_found", "Client session is unavailable");
      return {
        sessionReference: normalizeOpaqueReference(input.sessionReference),
        expiresAt: new Date(0).toISOString(),
        userId: "",
        applicationId: "",
        platformId: "",
        client: "native",
        revoked: true,
      };
    }
    if (this.host.revoke !== undefined) {
      try {
        await this.host.revoke({ record, runtimeRequest: input.runtimeRequest });
      } catch (error) {
        if (error instanceof ApplicationPlatformError) throw error;
        throw new ApplicationPlatformError("session_revoke_failed", "Client session could not be revoked");
      }
    }
    await this.store.revoke(record.sessionReference);
    return { ...opaqueResult(record), revoked: true };
  }

  async get(sessionReference: string | ApplicationPlatformSessionRequest): Promise<OpaqueClientSessionResult | undefined> {
    const reference = typeof sessionReference === "string" ? sessionReference : sessionReference.sessionReference;
    const record = await this.store.get(reference);
    return record === undefined ? undefined : opaqueResult(record);
  }

  async refreshSession(input: { sessionReference: string; runtimeRequest?: unknown; client?: ApplicationPlatformOpaqueClient }): Promise<OpaqueClientSessionResult> {
    return this.refresh(input);
  }

  async logoutSession(input: { sessionReference: string; runtimeRequest?: unknown }): Promise<OpaqueClientSessionResult> {
    return this.logout(input);
  }

  async revokeSession(input: { sessionReference: string; runtimeRequest?: unknown }): Promise<OpaqueClientSessionResult> {
    return this.revoke(input);
  }
}

export function createOpaqueClientSessionIssuer(options: OpaqueClientSessionIssuerOptions): OpaqueClientSessionIssuer {
  return new OpaqueClientSessionIssuer(options);
}

export const createOpaquePlatformSessionIssuer = createOpaqueClientSessionIssuer;
export const createApplicationPlatformOpaqueSessionIssuer = createOpaqueClientSessionIssuer;

export interface ApplicationPlatformSessionRequest {
  sessionReference: string;
  client?: ApplicationPlatformClient;
  clientKind?: ApplicationPlatformClient;
  clientType?: ApplicationPlatformClient;
  clientId?: string;
  userId?: string;
  redirectUri?: string;
  binding?: string;
  ttlSeconds?: number;
  runtimeRequest?: unknown;
}

export interface ApplicationPlatformSessionService {
  refresh(input: ApplicationPlatformSessionRequest): Promise<OpaqueClientSessionResult> | OpaqueClientSessionResult;
  logout(input: ApplicationPlatformSessionRequest): Promise<OpaqueClientSessionResult> | OpaqueClientSessionResult;
  revoke(input: ApplicationPlatformSessionRequest): Promise<OpaqueClientSessionResult> | OpaqueClientSessionResult;
  get?(input: ApplicationPlatformSessionRequest): Promise<OpaqueClientSessionResult | undefined> | OpaqueClientSessionResult | undefined;
}

export interface ApplicationPlatformWebviewTicketIssueInput {
  sessionReference: string;
  userId?: string;
  client?: ApplicationPlatformClient;
  clientKind?: ApplicationPlatformClient;
  clientType?: ApplicationPlatformClient;
  clientId?: string;
  applicationId?: string;
  platformId?: string;
  redirectUri?: string;
  binding?: string;
  ttlSeconds?: number;
}

export interface ApplicationPlatformWebviewTicket {
  ticket: string;
  ticketReference?: string;
  expiresAt: string;
  sessionReference?: string;
  applicationId?: string;
  platformId?: string;
  client?: ApplicationPlatformClient;
  clientKind?: "webview";
  redirectUri?: string;
}

export interface ApplicationPlatformWebviewTicketService {
  issue(input: ApplicationPlatformWebviewTicketIssueInput): Promise<ApplicationPlatformWebviewTicket> | ApplicationPlatformWebviewTicket;
  consume(input: { ticket: string; sessionReference?: string; binding?: string; clientId?: string; runtimeRequest?: unknown }): Promise<ApplicationPlatformWebviewTicket | undefined> | ApplicationPlatformWebviewTicket | undefined;
  revoke?(ticket: string): Promise<boolean> | boolean;
  ready?(): boolean | Promise<boolean>;
}

export interface ApplicationPlatformWebviewTicketServiceLike {
  issue?: ApplicationPlatformWebviewTicketService["issue"];
  create?: ApplicationPlatformWebviewTicketService["issue"];
  issueTicket?: ApplicationPlatformWebviewTicketService["issue"];
  consume?: ApplicationPlatformWebviewTicketService["consume"];
  redeem?: ApplicationPlatformWebviewTicketService["consume"];
  exchange?: ApplicationPlatformWebviewTicketService["consume"];
  revoke?: ApplicationPlatformWebviewTicketService["revoke"];
  ready?: ApplicationPlatformWebviewTicketService["ready"];
}

export class InMemoryApplicationPlatformWebviewTicketService implements ApplicationPlatformWebviewTicketService {
  readonly persistent = false;
  private readonly tickets = new Map<string, ApplicationPlatformWebviewTicket>();
  private readonly bindings = new Map<string, string>();
  private readonly clientIds = new Map<string, string>();
  private readonly now: () => number;
  private readonly maxEntries: number;

  constructor(options: { now?: () => number; maxEntries?: number } = {}) {
    this.now = options.now ?? Date.now;
    this.maxEntries = options.maxEntries ?? 10_000;
    if (!Number.isSafeInteger(this.maxEntries) || this.maxEntries < 1 || this.maxEntries > 100_000) throw new ApplicationPlatformError("invalid_webview_ticket", "Webview ticket store capacity is invalid");
  }

  issue(input: ApplicationPlatformWebviewTicketIssueInput): ApplicationPlatformWebviewTicket {
    const sessionReference = normalizeOpaqueReference(input.sessionReference);
    const ttlSeconds = input.ttlSeconds === undefined ? 300 : input.ttlSeconds;
    if (!Number.isSafeInteger(ttlSeconds) || ttlSeconds < 30 || ttlSeconds > 900) throw new ApplicationPlatformError("invalid_webview_ticket", "Webview ticket lifetime is invalid");
    const now = this.now();
    for (const [ticketKey, existing] of this.tickets) {
      if (Date.parse(existing.expiresAt) <= now) {
        this.tickets.delete(ticketKey);
        this.bindings.delete(ticketKey);
        this.clientIds.delete(ticketKey);
      }
    }
    if (this.tickets.size >= this.maxEntries) throw new ApplicationPlatformError("webview_ticket_store_full", "Webview ticket store is full");
    const ticketReference = createOpaqueReference("ticket");
    const ticket: ApplicationPlatformWebviewTicket = {
      ticket: ticketReference,
      ticketReference,
      expiresAt: new Date(now + ttlSeconds * 1000).toISOString(),
      sessionReference,
      ...(input.applicationId === undefined ? {} : { applicationId: input.applicationId }),
      ...(input.platformId === undefined ? {} : { platformId: input.platformId }),
      ...(input.client === undefined ? {} : { client: normalizeClient(input.clientKind ?? input.client) }),
      clientKind: "webview",
      ...(input.redirectUri === undefined ? {} : { redirectUri: input.redirectUri }),
    };
     this.tickets.set(ticket.ticket, ticket);
     if (input.binding !== undefined) this.bindings.set(ticket.ticket, createHash("sha256").update(normalizeOpaqueReference(input.binding)).digest("hex"));
     if (input.clientId !== undefined) this.clientIds.set(ticket.ticket, normalizeOpaqueText(input.clientId, "client", 512));
     return { ...ticket };
  }

  consume(input: { ticket: string; sessionReference?: string; binding?: string; clientId?: string }): ApplicationPlatformWebviewTicket | undefined {
    const ticket = normalizeOpaqueReference(input.ticket);
    const current = this.tickets.get(ticket);
    if (current === undefined) return undefined;
    if (input.sessionReference !== undefined && current.sessionReference !== normalizeOpaqueReference(input.sessionReference)) return undefined;
    if (input.sessionReference === undefined && current.sessionReference !== undefined) return undefined;
    const expectedClientId = this.clientIds.get(ticket);
    if (expectedClientId !== undefined && input.clientId === undefined) return undefined;
    if (input.clientId !== undefined && expectedClientId !== normalizeOpaqueText(input.clientId, "client", 512)) return undefined;
    const expectedBinding = this.bindings.get(ticket);
    if (expectedBinding !== undefined && input.binding === undefined) return undefined;
    if (input.binding !== undefined) {
      const actualBinding = createHash("sha256").update(normalizeOpaqueReference(input.binding)).digest("hex");
      if (expectedBinding === undefined || expectedBinding !== actualBinding) return undefined;
    }
    this.tickets.delete(ticket);
    this.bindings.delete(ticket);
    this.clientIds.delete(ticket);
    if (Date.parse(current.expiresAt) <= this.now()) return undefined;
    return { ...current };
  }

  revoke(ticket: string): boolean {
    const normalized = normalizeOpaqueReference(ticket);
    this.bindings.delete(normalized);
    this.clientIds.delete(normalized);
    return this.tickets.delete(normalized);
  }

  ready(): boolean {
    return true;
  }
}

export function createApplicationPlatformWebviewTicketService(options: { now?: () => number; maxEntries?: number } = {}): InMemoryApplicationPlatformWebviewTicketService {
  return new InMemoryApplicationPlatformWebviewTicketService(options);
}

export const createWebviewTicketService = createApplicationPlatformWebviewTicketService;
export const InMemoryWebviewTicketService = InMemoryApplicationPlatformWebviewTicketService;

export interface ApplicationPlatformIdentitySessionBoundary {
  run<T>(operation: () => Promise<T>, context?: ApplicationPlatformIdentitySessionBoundaryContext): Promise<T>;
}

export interface ApplicationPlatformIdentitySessionBoundaryContext {
  tenantId: string;
  applicationId: string;
  platformId: string;
  client: ApplicationPlatformClient;
  state: string;
  binding: string;
  code?: string;
}

export type ApplicationPlatformHostTransaction = <T>(operation: () => Promise<T>) => Promise<T>;

export interface ApplicationPlatformIdentitySessionBoundaryOptions {
  ttlMs?: number;
  maxEntries?: number;
  now?: () => number;
}

export class InMemoryApplicationPlatformIdentitySessionBoundary implements ApplicationPlatformIdentitySessionBoundary {
  readonly persistent = false;
  private readonly entries = new Map<string, { promise: Promise<unknown>; expiresAt: number }>();
  private readonly ttlMs: number;
  private readonly maxEntries: number;
  private readonly now: () => number;

  constructor(options: ApplicationPlatformIdentitySessionBoundaryOptions = {}) {
    const ttlMs = options.ttlMs ?? 10 * 60 * 1000;
    const maxEntries = options.maxEntries ?? 10_000;
    if (!Number.isSafeInteger(ttlMs) || ttlMs < 1_000 || ttlMs > 60 * 60 * 1000) throw new ApplicationPlatformError("invalid_platform_login_configuration", "Identity session boundary lifetime is invalid");
    if (!Number.isSafeInteger(maxEntries) || maxEntries < 1 || maxEntries > 100_000) throw new ApplicationPlatformError("invalid_platform_login_configuration", "Identity session boundary capacity is invalid");
    this.ttlMs = ttlMs;
    this.maxEntries = maxEntries;
    this.now = options.now ?? Date.now;
  }

  async run<T>(operation: () => Promise<T>, context?: ApplicationPlatformIdentitySessionBoundaryContext): Promise<T> {
    const key = boundaryKey(context);
    if (key === undefined) return operation();
    const now = this.clock();
    this.removeExpired(now);
    const current = this.entries.get(key);
    if (current !== undefined && current.expiresAt > now) return current.promise as Promise<T>;
    if (this.entries.size >= this.maxEntries) return operation();
    const promise = Promise.resolve().then(operation);
    this.entries.set(key, { promise, expiresAt: now + this.ttlMs });
    try {
      return await promise;
    } finally {
      if (this.entries.get(key)?.promise === promise) this.entries.delete(key);
    }
  }

  private removeExpired(now: number): void {
    for (const [key, entry] of this.entries) {
      if (entry.expiresAt <= now) this.entries.delete(key);
    }
  }

  private clock(): number {
    const value = this.now();
    if (!Number.isSafeInteger(value) || value < 0) throw new ApplicationPlatformError("invalid_platform_login_configuration", "Identity session boundary clock is invalid");
    return value;
  }
}

export function createApplicationPlatformIdentitySessionBoundary(options: ApplicationPlatformIdentitySessionBoundaryOptions = {}): InMemoryApplicationPlatformIdentitySessionBoundary {
  return new InMemoryApplicationPlatformIdentitySessionBoundary(options);
}

export const createIdentitySessionBoundary = createApplicationPlatformIdentitySessionBoundary;

export interface ApplicationPlatformCredentials {
  appId: string;
  appSecret?: string;
}

export type ApplicationPlatformCredentialResolver = (
  platform: ApplicationPlatformRecord,
) => ApplicationPlatformCredentials | Promise<ApplicationPlatformCredentials>;

export interface ApplicationPlatformLoginOptions {
  stateStore?: PlatformLoginStateStore;
  stateManager?: PlatformLoginStateManager;
  identityLinker: PlatformIdentityLinker;
  sessionIssuer: PlatformSessionIssuerBridge;
  sessionService?: ApplicationPlatformSessionService;
  clientSessionService?: ApplicationPlatformSessionService;
  clientSessionRepository?: OpaqueClientSessionRepository;
  webviewTicketRepository?: WebviewTicketRepository;
  webviewTicketService?: ApplicationPlatformWebviewTicketService | ApplicationPlatformWebviewTicketServiceLike;
  identitySessionBoundary?: ApplicationPlatformIdentitySessionBoundary;
  hostTransaction?: ApplicationPlatformHostTransaction;
  requireOpaqueClientSession?: boolean;
  stateTtlMs?: number;
  stateTtlSeconds?: number;
  stateExpiresInSeconds?: number;
  requireSessionBinding?: boolean;
  now?: () => number;
  randomState?: () => string;
  resolveHostContext?: (request: unknown) => PlatformLoginHostContext | undefined | Promise<PlatformLoginHostContext | undefined>;
  hostContext?: PlatformLoginHostContext;
  allowRequestedUserId?: boolean;
}

export interface ApplicationPlatformAuthServiceOptions {
  resolveCredentials?: ApplicationPlatformCredentialResolver;
  resolveSecret?: (secretRef: string) => string | Promise<string>;
  secretBindings?: SecretBindingRepository;
  adapters?: readonly ApplicationPlatformAdapter[];
  registry?: ApplicationPlatformAdapterRegistry;
  login?: ApplicationPlatformLoginOptions;
  loginFlow?: ApplicationPlatformLoginOptions;
  platformLogin?: ApplicationPlatformLoginOptions;
  stateStore?: PlatformLoginStateStore;
  stateManager?: PlatformLoginStateManager;
  identityLinker?: PlatformIdentityLinker;
  sessionIssuer?: PlatformSessionIssuerBridge;
  sessionService?: ApplicationPlatformSessionService;
  clientSessionService?: ApplicationPlatformSessionService;
  clientSessionRepository?: OpaqueClientSessionRepository;
  webviewTicketRepository?: WebviewTicketRepository;
  webviewTicketService?: ApplicationPlatformWebviewTicketService | ApplicationPlatformWebviewTicketServiceLike;
  identitySessionBoundary?: ApplicationPlatformIdentitySessionBoundary;
  hostTransaction?: ApplicationPlatformHostTransaction;
  transaction?: ApplicationPlatformHostTransaction;
  requireOpaqueClientSession?: boolean;
  stateTtlMs?: number;
  stateTtlSeconds?: number;
  stateExpiresInSeconds?: number;
  requireSessionBinding?: boolean;
  stateNow?: () => number;
  randomState?: () => string;
  resolveHostContext?: (request: unknown) => PlatformLoginHostContext | undefined | Promise<PlatformLoginHostContext | undefined>;
  hostContext?: PlatformLoginHostContext;
  allowRequestedUserId?: boolean;
}

export interface ApplicationPlatformAuthorizationRequest {
  redirectUri: string;
  state: string;
  scope?: string;
  client?: ApplicationPlatformClient;
  clientKind?: ApplicationPlatformClient;
  clientType?: ApplicationPlatformClient;
}

export interface ApplicationPlatformLoginRequest {
  redirectUri: string;
  returnTo?: string;
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
}

export interface ApplicationPlatformCallbackRequest {
  state: string;
  code?: string;
  authorizationCode?: string;
  error?: string | null;
  errorDescription?: string;
  redirectUri?: string;
  flowBinding?: string;
  browser?: PlatformLoginBindingInput;
  binding?: PlatformLoginBindingInput;
  browserId?: string;
  browserBinding?: string;
  sessionId?: string;
  sessionBinding?: string;
  client?: ApplicationPlatformClient;
  clientKind?: ApplicationPlatformClient;
  clientType?: ApplicationPlatformClient;
}

export interface ApplicationPlatformWebviewCallbackRequest {
  state: string;
  code?: string;
  authorizationCode?: string;
  error?: string | null;
  errorDescription?: string;
  redirectUri?: string;
  flowBinding: string;
}

export interface ApplicationPlatformPublicLoginRequest {
  redirectUri: string;
  returnTo?: string;
  scope?: string;
  flowBinding?: string;
  client?: ApplicationPlatformClient;
  clientKind?: ApplicationPlatformClient;
  clientType?: ApplicationPlatformClient;
}

export interface ApplicationPlatformWebviewLoginRequest extends Omit<ApplicationPlatformPublicLoginRequest, "returnTo"> {
  flowBinding: string;
}

export interface ApplicationPlatformWebviewStartResult extends PlatformLoginStartResult {
  client: "webview";
}

export interface ApplicationPlatformNativeLoginRequest extends Omit<ApplicationPlatformPublicLoginRequest, "returnTo" | "flowBinding"> {}

export interface ApplicationPlatformNativeExchangeRequest {
  state: string;
  code?: string;
  authorizationCode?: string;
  error?: string | null;
  errorDescription?: string;
  redirectUri?: string;
  client?: ApplicationPlatformClient;
  clientKind?: ApplicationPlatformClient;
  clientType?: ApplicationPlatformClient;
}

export interface ApplicationPlatformMiniProgramExchangeRequest {
  code: string;
  redirectUri?: string;
  client?: ApplicationPlatformClient;
  clientKind?: ApplicationPlatformClient;
  clientType?: ApplicationPlatformClient;
}

export class ApplicationPlatformAuthService {
  private readonly repository: ApplicationRepository;
  private readonly resolveCredentials?: ApplicationPlatformCredentialResolver;
  private readonly resolveSecret?: (secretRef: string) => string | Promise<string>;
  private readonly secretBindings?: SecretBindingRepository;
  private readonly registry: ApplicationPlatformAdapterRegistry;
  private readonly resolveHostContext?: (request: unknown) => PlatformLoginHostContext | undefined | Promise<PlatformLoginHostContext | undefined>;
  private readonly hostContext?: PlatformLoginHostContext;
  private readonly platformLoginFlow?: PlatformLoginFlow;
  private readonly sessionService?: ApplicationPlatformSessionService;
  private readonly clientSessionRepository?: OpaqueClientSessionRepository;
  private readonly webviewTicketService?: ApplicationPlatformWebviewTicketService;
  private readonly webviewTicketRepository?: WebviewTicketRepository;
  private readonly identitySessionBoundary?: ApplicationPlatformIdentitySessionBoundary;
  private readonly hostTransaction?: ApplicationPlatformHostTransaction;
  private readonly requireOpaqueClientSession: boolean;

  constructor(
    repository: ApplicationRepository,
    options: ApplicationPlatformAuthServiceOptions,
  ) {
    this.repository = repository;
    this.resolveCredentials = options.resolveCredentials;
    this.resolveSecret = options.resolveSecret;
    this.secretBindings = options.secretBindings;
    this.registry = options.registry ?? createDefaultApplicationPlatformRegistry(options.adapters);
    this.resolveHostContext = options.resolveHostContext;
    this.hostContext = options.hostContext;
    this.sessionService = normalizeApplicationPlatformSessionService(options.sessionService ?? options.clientSessionService ?? (isOpaqueSessionIssuer(options.sessionIssuer) ? options.sessionIssuer : undefined));
    this.clientSessionRepository = options.clientSessionRepository;
    this.webviewTicketService = normalizeApplicationPlatformWebviewTicketService(options.webviewTicketService);
    this.webviewTicketRepository = options.webviewTicketRepository;
    this.identitySessionBoundary = options.identitySessionBoundary;
    this.hostTransaction = options.hostTransaction ?? options.transaction;
    this.requireOpaqueClientSession = options.requireOpaqueClientSession === true;
    const login = options.login ?? options.loginFlow ?? options.platformLogin ?? (
      options.stateStore !== undefined || options.stateManager !== undefined || options.identityLinker !== undefined || options.sessionIssuer !== undefined
        ? {
            stateStore: options.stateStore as PlatformLoginStateStore,
            stateManager: options.stateManager,
            identityLinker: options.identityLinker as PlatformIdentityLinker,
            sessionIssuer: options.sessionIssuer as PlatformSessionIssuerBridge,
            ...(options.stateTtlMs === undefined ? {} : { stateTtlMs: options.stateTtlMs }),
            ...(options.stateTtlSeconds === undefined ? {} : { stateTtlSeconds: options.stateTtlSeconds }),
            ...(options.stateExpiresInSeconds === undefined ? {} : { stateExpiresInSeconds: options.stateExpiresInSeconds }),
             ...(options.requireSessionBinding === undefined ? {} : { requireSessionBinding: options.requireSessionBinding }),
             ...(options.stateNow === undefined ? {} : { now: options.stateNow }),
             ...(options.randomState === undefined ? {} : { randomState: options.randomState }),
             ...(options.allowRequestedUserId === undefined ? {} : { allowRequestedUserId: options.allowRequestedUserId }),
             ...(options.sessionService === undefined ? {} : { sessionService: options.sessionService }),
             ...(options.clientSessionService === undefined ? {} : { clientSessionService: options.clientSessionService }),
             ...(options.webviewTicketService === undefined ? {} : { webviewTicketService: options.webviewTicketService }),
             ...(options.identitySessionBoundary === undefined ? {} : { identitySessionBoundary: options.identitySessionBoundary }),
             ...(options.hostTransaction === undefined ? {} : { hostTransaction: options.hostTransaction }),
             ...(options.requireOpaqueClientSession === undefined ? {} : { requireOpaqueClientSession: options.requireOpaqueClientSession }),
          }
        : undefined
    );
    this.resolveHostContext = options.resolveHostContext ?? login?.resolveHostContext;
    this.hostContext = options.hostContext ?? login?.hostContext;
    this.sessionService = normalizeApplicationPlatformSessionService(options.sessionService ?? options.clientSessionService ?? login?.sessionService ?? (isOpaqueSessionIssuer(options.sessionIssuer) ? options.sessionIssuer : isOpaqueSessionIssuer(login?.sessionIssuer) ? login?.sessionIssuer : undefined));
    this.clientSessionRepository = options.clientSessionRepository ?? login?.clientSessionRepository;
    this.webviewTicketService = normalizeApplicationPlatformWebviewTicketService(options.webviewTicketService ?? login?.webviewTicketService);
    this.webviewTicketRepository = options.webviewTicketRepository ?? login?.webviewTicketRepository;
    this.identitySessionBoundary = options.identitySessionBoundary ?? login?.identitySessionBoundary;
    this.hostTransaction = options.hostTransaction ?? options.transaction ?? login?.hostTransaction;
    this.requireOpaqueClientSession = options.requireOpaqueClientSession ?? login?.requireOpaqueClientSession ?? false;
    if (login !== undefined) {
      if ((!login.stateStore && !login.stateManager) || !login.identityLinker || !login.sessionIssuer) {
        throw new ApplicationPlatformError("invalid_platform_login_configuration", "Platform login dependencies are incomplete");
      }
      if (login.stateManager !== undefined && login.stateManager.tenantId !== this.repository.tenantId) {
        throw new ApplicationPlatformError("invalid_platform_login_configuration", "Platform login state manager tenant does not match the application repository");
      }
      this.platformLoginFlow = createPlatformLoginFlow({
        tenantId: this.repository.tenantId,
        ...(login.stateManager === undefined ? { stateStore: login.stateStore as PlatformLoginStateStore } : { stateManager: login.stateManager }),
        registeredRedirectUris: async (applicationId, platformId) => {
          const platform = await this.getActivePlatform(applicationId, platformId);
          return platform.redirectUris ?? [];
        },
        createAuthorizationUrl: async ({ applicationId, platformId, redirectUri, state, scope, client, clientType }) =>
          this.createAuthorizationUrl(applicationId, platformId, {
            redirectUri,
            state,
            ...(scope === undefined ? {} : { scope }),
            ...(clientType === undefined && client === undefined ? {} : { client: clientType ?? client }),
          }),

        exchangeCode: async ({ applicationId, platformId, redirectUri, code, client, clientType }) =>
          this.exchangeCode(applicationId, platformId, code, redirectUri, clientType ?? client, false),
        identityLinker: login.identityLinker,
        sessionIssuer: this.wrapLoginSessionIssuer(login.sessionIssuer),
        onIdentityAuthenticated: async ({ applicationId, platformId, identity, userId }) => {
          await this.persistExternalIdentity(applicationId, platformId, identity, userId);
        },
        allowRequestedUserId: login.allowRequestedUserId,
        state: {
          tenantId: this.repository.tenantId,
          ...(login.stateTtlMs === undefined ? {} : { ttlMs: login.stateTtlMs }),
          ...(login.stateTtlSeconds === undefined ? {} : { ttlSeconds: login.stateTtlSeconds }),
          ...(login.stateExpiresInSeconds === undefined ? {} : { expiresInSeconds: login.stateExpiresInSeconds }),
          ...(login.requireSessionBinding === undefined ? {} : { requireSessionBinding: login.requireSessionBinding }),
          ...(login.now === undefined ? {} : { now: login.now }),
          ...(login.randomState === undefined ? {} : { randomState: login.randomState }),
        },
      });
    }
  }

  register(adapter: ApplicationPlatformAdapter): this {
    this.registry.register(registryAdapter(adapter));
    return this;
  }

  get loginFlow(): PlatformLoginFlow | undefined {
    return this.platformLoginFlow;
  }

  async createLogin(
    applicationId: string,
    platformId: string,
    request: ApplicationPlatformLoginRequest,
  ): Promise<PlatformLoginStartResult> {
    await this.assertApplicationChannel(applicationId, "web");
    await this.getActivePlatform(applicationId, platformId);
    const flow = this.requireLoginFlow();
    return flow.start({
      ...request,
      applicationId,
      platformId,
    });
  }

  async startLogin(
    applicationId: string,
    platformId: string,
    request: ApplicationPlatformLoginRequest,
  ): Promise<PlatformLoginStartResult> {
    return this.createLogin(applicationId, platformId, request);
  }

  async beginLogin(
    applicationId: string,
    platformId: string,
    request: ApplicationPlatformLoginRequest,
  ): Promise<PlatformLoginStartResult> {
    return this.createLogin(applicationId, platformId, request);
  }

  async createPublicLogin(
    applicationId: string,
    platformId: string,
    request: ApplicationPlatformPublicLoginRequest,
    runtimeRequest?: unknown,
    binding?: PlatformLoginBindingInput,
  ): Promise<PlatformLoginStartResult> {
    this.assertPublicRequest(request);
    const client = normalizeClient(request.clientKind ?? request.clientType ?? request.client ?? "web");
    if (client !== "web" && client !== "webview") {
      throw new ApplicationPlatformError("platform_client_not_allowed", "Platform login channel is not allowed for this application");
    }
    if (client === "webview") {
      if (binding !== undefined) {
        throw new ApplicationPlatformError("invalid_platform_request", "Webview login accepts only flowBinding");
      }
      const flowBinding = requireFlowBinding(request.flowBinding);
      return this.startPublicLoginInternal(applicationId, platformId, request, "webview", runtimeRequest, undefined, flowBinding);
    }
    if (Object.prototype.hasOwnProperty.call(request, "flowBinding")) {
      throw new ApplicationPlatformError("invalid_platform_request", "flowBinding is only valid for webview login");
    }
    return this.startPublicLoginInternal(applicationId, platformId, request, "web", runtimeRequest, binding);
  }

  private async startPublicLoginInternal(
    applicationId: string,
    platformId: string,
    request: ApplicationPlatformPublicLoginRequest,
    client: "web" | "webview",
    runtimeRequest: unknown,
    binding: PlatformLoginBindingInput | undefined,
    sessionBinding?: string,
  ): Promise<PlatformLoginStartResult> {
    const hasReturnTo = Object.prototype.hasOwnProperty.call(request, "returnTo");
    if (hasReturnTo && client !== "web") {
      throw new ApplicationPlatformError("invalid_return_to", "Platform login returnTo is only valid for web clients");
    }
    const returnTo = request.returnTo === undefined ? undefined : assertPlatformLoginReturnTo(request.returnTo);
    await this.assertApplicationChannel(applicationId, client);
    await this.getActivePlatform(applicationId, platformId);
    const flow = this.requireLoginFlow();
    const hostRequest = client === "webview" ? redactFlowBinding(runtimeRequest) : runtimeRequest;
    const hostContext = await this.resolveRequestHostContext(hostRequest);
    const input = {
      applicationId,
      platformId,
      redirectUri: request.redirectUri,
      ...(returnTo === undefined ? {} : { returnTo }),
      ...(request.scope === undefined ? {} : { scope: request.scope }),
      ...(client === "webview" ? { sessionBinding } : binding === undefined ? {} : { binding }),
      hostContext: hostContext ?? {},
    };
    return client === "webview" ? flow.startWebview(input) : flow.startWeb(input);
  }

  async startPublicLogin(
    applicationId: string,
    platformId: string,
    request: ApplicationPlatformPublicLoginRequest,
    runtimeRequest?: unknown,
    binding?: PlatformLoginBindingInput,
  ): Promise<PlatformLoginStartResult> {
    return this.createPublicLogin(applicationId, platformId, request, runtimeRequest, binding);
  }

  async startNativeLogin(
    applicationId: string,
    platformId: string,
    request: ApplicationPlatformNativeLoginRequest,
    runtimeRequest?: unknown,
  ): Promise<PlatformLoginStartResult> {
    this.assertPublicRequest(request);
    if (Object.prototype.hasOwnProperty.call(request, "flowBinding")) {
      throw new ApplicationPlatformError("invalid_platform_request", "flowBinding is only valid for webview login");
    }
    if (Object.prototype.hasOwnProperty.call(request, "returnTo") || Object.prototype.hasOwnProperty.call(request, "return_to")) {
      throw new ApplicationPlatformError("invalid_return_to", "Platform login returnTo is only valid for web clients");
    }
    await this.assertApplicationChannel(applicationId, "native");
    await this.getActivePlatform(applicationId, platformId);
    const flow = this.requireLoginFlow();
    const hostContext = await this.resolveRequestHostContext(runtimeRequest);
    return flow.startNative({
      applicationId,
      platformId,
      redirectUri: request.redirectUri,
      ...(request.scope === undefined ? {} : { scope: request.scope }),
      hostContext: hostContext ?? {},
    });
  }

  async nativeStartLogin(
    applicationId: string,
    platformId: string,
    request: ApplicationPlatformNativeLoginRequest,
    runtimeRequest?: unknown,
  ): Promise<PlatformLoginStartResult> {
    return this.startNativeLogin(applicationId, platformId, request, runtimeRequest);
  }

  async createWebLogin(
    applicationId: string,
    platformId: string,
    request: ApplicationPlatformPublicLoginRequest,
    runtimeRequest?: unknown,
    binding?: PlatformLoginBindingInput,
  ): Promise<PlatformLoginStartResult> {
    return this.createPublicLogin(applicationId, platformId, request, runtimeRequest, binding);
  }

  async startWebLogin(
    applicationId: string,
    platformId: string,
    request: ApplicationPlatformPublicLoginRequest,
    runtimeRequest?: unknown,
    binding?: PlatformLoginBindingInput,
  ): Promise<PlatformLoginStartResult> {
    return this.createPublicLogin(applicationId, platformId, request, runtimeRequest, binding);
  }

  async startWebviewLogin(
    applicationId: string,
    platformId: string,
    request: ApplicationPlatformPublicLoginRequest,
    runtimeRequest?: unknown,
    binding?: PlatformLoginBindingInput,
  ): Promise<PlatformLoginStartResult> {
    if (binding !== undefined) {
      throw new ApplicationPlatformError("invalid_platform_request", "Webview login accepts only flowBinding");
    }
    this.assertWebviewClient(request);
    return this.createPublicLogin(applicationId, platformId, { ...request, client: "webview" }, runtimeRequest);
  }

  async startWebview(
    applicationId: string,
    platformId: string,
    request: ApplicationPlatformPublicLoginRequest,
    runtimeRequest?: unknown,
    binding?: PlatformLoginBindingInput,
  ): Promise<PlatformLoginStartResult> {
    return this.startWebviewLogin(applicationId, platformId, request, runtimeRequest, binding);
  }

  async createWebview(
    applicationId: string,
    platformId: string,
    request: ApplicationPlatformPublicLoginRequest,
    runtimeRequest?: unknown,
    binding?: PlatformLoginBindingInput,
  ): Promise<PlatformLoginStartResult> {
    return this.startWebviewLogin(applicationId, platformId, request, runtimeRequest, binding);
  }

  async createWebviewLogin(
    applicationId: string,
    platformId: string,
    request: ApplicationPlatformPublicLoginRequest,
    runtimeRequest?: unknown,
    binding?: PlatformLoginBindingInput,
  ): Promise<PlatformLoginStartResult> {
    return this.startWebviewLogin(applicationId, platformId, request, runtimeRequest, binding);
  }

  async completePublicLogin(
    applicationId: string,
    platformId: string,
    request: ApplicationPlatformCallbackRequest,
    runtimeRequest?: unknown,
    binding?: PlatformLoginBindingInput,
  ): Promise<PlatformLoginResult> {
    this.assertPublicCallbackRequest(request);
    const client = normalizeClient(request.clientKind ?? request.clientType ?? request.client ?? "web");
    if (client !== "web" && client !== "webview") {
      throw new ApplicationPlatformError("platform_client_not_allowed", "Platform login channel is not allowed for this application");
    }
    const flowBinding = client === "webview" ? requireFlowBinding(request.flowBinding) : undefined;
    const effectiveBinding = client === "webview"
      ? this.resolveWebviewCallbackBinding(request, binding, flowBinding)
      : this.resolveWebCallbackBinding(request, binding);
    await this.assertApplicationChannel(applicationId, client);
    await this.getActivePlatform(applicationId, platformId);
    const flow = this.requireLoginFlow();
    const flowRuntimeRequest = client === "webview" ? redactFlowBinding(runtimeRequest) : runtimeRequest;
    const hostContext = await this.resolveRequestHostContext(flowRuntimeRequest);
    const callback = publicCallbackFields(request);
    const flowInput = {
      ...callback,
      applicationId,
      platformId,
      ...(client === "webview" ? { sessionBinding: flowBinding } : { binding: effectiveBinding }),
      hostContext: hostContext ?? {},
      context: flowRuntimeRequest,
    };
    return this.completeIdentitySession(
      { applicationId, platformId, kind: client, request: callback, binding: effectiveBinding, runtimeRequest: flowRuntimeRequest },
      () => client === "webview" ? flow.handleWebviewCallback(flowInput) : flow.handleWebCallback(flowInput),
    );
  }

  private assertWebviewClient(request: unknown): void {
    if (!isRecord(request)) {
      throw new ApplicationPlatformError("invalid_platform_request", "Webview login request is invalid");
    }
    const client = readPlatformClientAliases(request);
    if (client !== undefined && client !== "webview") {
      throw new ApplicationPlatformError("invalid_platform_client", "Webview login client is invalid");
    }
  }

  private resolveWebviewCallbackBinding(
    request: ApplicationPlatformCallbackRequest,
    binding: PlatformLoginBindingInput | undefined,
    flowBinding: string | undefined,
  ): PlatformLoginBindingInput {
    if (binding !== undefined) {
      throw new ApplicationPlatformError("invalid_platform_request", "Webview callback accepts only flowBinding");
    }
    if (flowBinding === undefined) {
      throw new ApplicationPlatformError("invalid_platform_binding", "Webview callback flowBinding is required");
    }
    return { sessionBinding: flowBinding };
  }

  private resolveWebCallbackBinding(
    request: ApplicationPlatformCallbackRequest,
    binding: PlatformLoginBindingInput | undefined,
  ): PlatformLoginBindingInput | undefined {
    if (Object.prototype.hasOwnProperty.call(request, "flowBinding")) {
      throw new ApplicationPlatformError("invalid_platform_request", "flowBinding is only valid for webview callback");
    }
    return binding;
  }

  async completeWebviewLogin(
    applicationId: string,
    platformId: string,
    request: ApplicationPlatformCallbackRequest,
    runtimeRequest?: unknown,
    binding?: PlatformLoginBindingInput,
  ): Promise<PlatformLoginResult> {
    this.assertWebviewClient(request);
    return this.completePublicLogin(applicationId, platformId, { ...request, client: "webview" }, runtimeRequest, binding);
  }

  async handleWebviewCallback(
    applicationId: string,
    platformId: string,
    request: ApplicationPlatformCallbackRequest,
    runtimeRequest?: unknown,
    binding?: PlatformLoginBindingInput,
  ): Promise<PlatformLoginResult> {
    return this.completeWebviewLogin(applicationId, platformId, request, runtimeRequest, binding);
  }

  async exchangeWebview(
    applicationId: string,
    platformId: string,
    request: ApplicationPlatformCallbackRequest,
    runtimeRequest?: unknown,
    binding?: PlatformLoginBindingInput,
  ): Promise<PlatformLoginResult> {
    return this.completeWebviewLogin(applicationId, platformId, request, runtimeRequest, binding);
  }

  async exchangeWebviewCallback(
    applicationId: string,
    platformId: string,
    request: ApplicationPlatformCallbackRequest,
    runtimeRequest?: unknown,
    binding?: PlatformLoginBindingInput,
  ): Promise<PlatformLoginResult> {
    return this.completeWebviewLogin(applicationId, platformId, request, runtimeRequest, binding);
  }

  async handleWebCallback(
    applicationId: string,
    platformId: string,
    request: ApplicationPlatformCallbackRequest,
    runtimeRequest?: unknown,
    binding?: PlatformLoginBindingInput,
  ): Promise<PlatformLoginResult> {
    return this.completePublicLogin(applicationId, platformId, request, runtimeRequest, binding);
  }

  async exchangeWebCallback(
    applicationId: string,
    platformId: string,
    request: ApplicationPlatformCallbackRequest,
    runtimeRequest?: unknown,
    binding?: PlatformLoginBindingInput,
  ): Promise<PlatformLoginResult> {
    return this.completePublicLogin(applicationId, platformId, request, runtimeRequest, binding);
  }

  async completeNativeLogin(
    applicationId: string,
    platformId: string,
    request: ApplicationPlatformNativeExchangeRequest,
    runtimeRequest?: unknown,
  ): Promise<PlatformLoginResult> {
    this.assertPublicCallbackRequest(request);
    if (Object.prototype.hasOwnProperty.call(request, "flowBinding")) {
      throw new ApplicationPlatformError("invalid_platform_request", "flowBinding is only valid for webview callback");
    }
    const client = normalizeClient(request.clientKind ?? request.clientType ?? request.client ?? "native");
    if (client !== "native" && client !== "mp_weixin") {
      throw new ApplicationPlatformError("platform_client_not_allowed", "Platform login channel is not allowed for this application");
    }
    await this.assertApplicationChannel(applicationId, "native");
    await this.getActivePlatform(applicationId, platformId);
    const flow = this.requireLoginFlow();
    const hostContext = await this.resolveRequestHostContext(runtimeRequest);
    return this.completeIdentitySession(
      { applicationId, platformId, kind: client, request, runtimeRequest },
      () => flow.exchangeNative({
        ...request,
        applicationId,
        platformId,
        hostContext: hostContext ?? {},
        context: runtimeRequest,
      }),
    );
  }

  async createNativeLogin(
    applicationId: string,
    platformId: string,
    request: ApplicationPlatformNativeLoginRequest,
    runtimeRequest?: unknown,
  ): Promise<PlatformLoginStartResult> {
    return this.startNativeLogin(applicationId, platformId, request, runtimeRequest);
  }

  async exchangeNativeLogin(
    applicationId: string,
    platformId: string,
    request: ApplicationPlatformNativeExchangeRequest,
    runtimeRequest?: unknown,
  ): Promise<PlatformLoginResult> {
    return this.completeNativeLogin(applicationId, platformId, request, runtimeRequest);
  }

  async exchangeMiniProgram(
    applicationId: string,
    platformId: string,
    request: ApplicationPlatformMiniProgramExchangeRequest,
    runtimeRequest?: unknown,
  ): Promise<PlatformLoginResult> {
    this.assertPublicMiniProgramRequest(request);
    await this.getActivePlatform(applicationId, platformId);
    const flow = this.requireLoginFlow();
    const hostContext = await this.resolveRequestHostContext(runtimeRequest);
    const result = await this.completeIdentitySession(
      { applicationId, platformId, kind: "mp_weixin", request, runtimeRequest },
      () => flow.exchangeMiniProgram({
        applicationId,
        platformId,
        code: request.code,
        ...(request.redirectUri === undefined ? {} : { redirectUri: request.redirectUri }),
        hostContext: hostContext ?? {},
        context: runtimeRequest,
      }),
    );
    return this.requireOpaqueClientSession ? result : { ...result, client: "mini_program" };
  }

  async exchangeMiniProgramCode(
    applicationId: string,
    platformId: string,
    request: ApplicationPlatformMiniProgramExchangeRequest,
    runtimeRequest?: unknown,
  ): Promise<PlatformLoginResult> {
    return this.exchangeMiniProgram(applicationId, platformId, request, runtimeRequest);
  }

  async miniProgramExchange(
    applicationId: string,
    platformId: string,
    request: ApplicationPlatformMiniProgramExchangeRequest,
    runtimeRequest?: unknown,
  ): Promise<PlatformLoginResult> {
    return this.exchangeMiniProgram(applicationId, platformId, request, runtimeRequest);
  }

  async completeLogin(
    applicationId: string,
    platformId: string,
    request: ApplicationPlatformCallbackRequest,
  ): Promise<PlatformLoginResult> {
    await this.assertApplicationChannel(applicationId, "web");
    await this.getActivePlatform(applicationId, platformId);
    const flow = this.requireLoginFlow();
    return this.completeIdentitySession(
      { applicationId, platformId, kind: "web", request },
      () => flow.handleCallback({
        ...request,
        applicationId,
        platformId,
      }),
    );
  }

  async handleCallback(
    applicationId: string,
    platformId: string,
    request: ApplicationPlatformCallbackRequest,
  ): Promise<PlatformLoginResult> {
    return this.completeLogin(applicationId, platformId, request);
  }

  async exchangeCallback(
    applicationId: string,
    platformId: string,
    request: ApplicationPlatformCallbackRequest,
  ): Promise<PlatformLoginResult> {
    return this.completeLogin(applicationId, platformId, request);
  }

  async refreshSession(
    applicationId: string,
    platformId: string,
    input: unknown,
    runtimeRequest?: unknown,
  ): Promise<OpaqueClientSessionResult> {
    await this.getActivePlatform(applicationId, platformId);
    const request = normalizeSessionRequest(input);
    const service = this.requireSessionService();
    const result = await service.refresh({ ...request, runtimeRequest });
    return this.assertSessionOwnership(applicationId, platformId, result, request.client);
  }

  async logoutSession(
    applicationId: string,
    platformId: string,
    input: unknown,
    runtimeRequest?: unknown,
  ): Promise<OpaqueClientSessionResult> {
    await this.getActivePlatform(applicationId, platformId);
    const request = normalizeSessionRequest(input);
    const service = this.requireSessionService();
    try {
      const result = await service.logout({ ...request, runtimeRequest });
      return this.assertSessionOwnership(applicationId, platformId, result, request.client);
    } catch (error) {
      if (!(error instanceof ApplicationPlatformError) || error.code !== "session_not_found") throw error;
      return {
        sessionReference: request.sessionReference,
        expiresAt: new Date(0).toISOString(),
        userId: "",
        applicationId,
        platformId,
        client: request.client === undefined || request.client === "web" ? "native" : request.client,
        revoked: true,
      };
    }
  }

  async revokeSession(
    applicationId: string,
    platformId: string,
    input: unknown,
    runtimeRequest?: unknown,
  ): Promise<OpaqueClientSessionResult> {
    await this.getActivePlatform(applicationId, platformId);
    const request = normalizeSessionRequest(input);
    const service = this.requireSessionService();
    const result = await service.revoke({ ...request, runtimeRequest });
    return this.assertSessionOwnership(applicationId, platformId, result, request.client);
  }

  async refreshClientSession(applicationId: string, platformId: string, input: unknown, runtimeRequest?: unknown): Promise<OpaqueClientSessionResult> {
    return this.refreshSession(applicationId, platformId, input, runtimeRequest);
  }

  async logoutClientSession(applicationId: string, platformId: string, input: unknown, runtimeRequest?: unknown): Promise<OpaqueClientSessionResult> {
    return this.logoutSession(applicationId, platformId, input, runtimeRequest);
  }

  async revokeClientSession(applicationId: string, platformId: string, input: unknown, runtimeRequest?: unknown): Promise<OpaqueClientSessionResult> {
    return this.revokeSession(applicationId, platformId, input, runtimeRequest);
  }

  async getSession(
    applicationId: string,
    platformId: string,
    input: unknown,
  ): Promise<OpaqueClientSessionResult | undefined> {
    await this.getActivePlatform(applicationId, platformId);
    const request = normalizeSessionRequest(input);
    const service = this.requireSessionService();
    if (service.get === undefined) return undefined;
    const result = await service.get({ ...request });
    return result === undefined ? undefined : this.assertSessionOwnership(applicationId, platformId, result, request.client);
  }

  async issueWebviewTicket(
    applicationId: string,
    platformId: string,
    input: unknown,
    runtimeRequest?: unknown,
  ): Promise<ApplicationPlatformWebviewTicket> {
    await this.getActivePlatform(applicationId, platformId);
    const request = normalizeSessionRequest(input, true);
    if (request.clientId === undefined) throw new ApplicationPlatformError("invalid_webview_ticket", "Webview ticket clientId is required");
    const rpClient = this.repository.findClientByClientId === undefined
      ? await this.repository.getClient(applicationId, request.clientId)
      : await this.repository.findClientByClientId(request.clientId);
    if (rpClient === undefined || rpClient === null || lifecycleStatusOf(rpClient) !== "active") {
      throw new ApplicationPlatformError("webview_ticket_scope_mismatch", "Webview ticket client is unavailable");
    }
    const sessionService = this.requireSessionService();
    if (sessionService.get === undefined) throw new ApplicationPlatformError("session_not_configured", "Client session service cannot verify ticket ownership");
    const session = await sessionService.get({ ...request });
    if (session === undefined) throw new ApplicationPlatformError("session_not_found", "Client session is unavailable");
    this.assertSessionOwnership(applicationId, platformId, session, request.client);
    const redirectUri = request.redirectUri === undefined
      ? rpClient.redirectUris?.[0]
      : assertRegisteredPlatformRedirectUri(request.redirectUri, rpClient.redirectUris);
    if (redirectUri === undefined) throw new ApplicationPlatformError("invalid_redirect_uri", "Webview ticket redirect URI is not registered");
    const tickets = this.webviewTicketService;
    if (tickets === undefined) {
      if (this.webviewTicketRepository === undefined) throw new ApplicationPlatformError("webview_ticket_not_configured", "Webview ticket service is not configured");
      const issued = await this.webviewTicketRepository.issue({
        applicationId,
        platformId,
        redirectUri,
         sessionReference: request.sessionReference,
         ...(request.binding === undefined ? {} : { binding: request.binding }),
         ...(request.ttlSeconds === undefined ? {} : { expiresInSeconds: request.ttlSeconds }),
         ...(request.clientId === undefined ? {} : { clientId: request.clientId }),

       });
       const ticketReference = issued.ticket.ticketReference;
       return {
        ticket: issued.ticket.ticket ?? ticketReference,
        ticketReference,
        expiresAt: issued.ticket.expiresAt,
        sessionReference: request.sessionReference,
        applicationId,
        platformId,
        clientKind: "webview",
        redirectUri,
      };
    }
    const issued = await tickets.issue({
      sessionReference: request.sessionReference,
      ...(request.userId === undefined ? {} : { userId: request.userId }),
      ...(request.client === undefined ? {} : { client: request.client }),
       ...(request.binding === undefined ? {} : { binding: request.binding }),
       ...(request.ttlSeconds === undefined ? {} : { ttlSeconds: request.ttlSeconds }),
       applicationId,

      platformId,
      redirectUri,
       ...(request.clientKind === undefined ? {} : { clientKind: request.clientKind }),
       ...(request.clientId === undefined ? {} : { clientId: request.clientId }),
     });
     return issued;
  }

  async exchangeWebviewTicket(
    applicationId: string,
    platformId: string,
    input: unknown,
    runtimeRequest?: unknown,
  ): Promise<OpaqueClientSessionResult> {
    await this.getActivePlatform(applicationId, platformId);
    let request: ApplicationPlatformSessionRequest;
    try {
      request = normalizeSessionRequest(input, true);
    } catch (error) {
      if (error instanceof ApplicationPlatformError && error.code === "invalid_session_reference") {
        throw new ApplicationPlatformError("invalid_webview_ticket", "Webview ticket is invalid");
      }
      throw error;
    }
    const value = isRecord(input) ? input : {};
    const ticket = stringValue(value.ticket ?? value.ticketReference);
    if (ticket === undefined) throw new ApplicationPlatformError("invalid_webview_ticket", "Webview ticket is invalid");
    const tickets = this.webviewTicketService;
    let consumed: ApplicationPlatformWebviewTicket | undefined;
    if (tickets !== undefined) {
      consumed = await tickets.consume({
        ticket,
        sessionReference: request.sessionReference,
         ...(request.binding === undefined ? {} : { binding: request.binding }),
         ...(request.clientId === undefined ? {} : { clientId: request.clientId }),
         ...(runtimeRequest === undefined ? {} : { runtimeRequest }),
      });
    } else if (this.webviewTicketRepository !== undefined) {
      const record = await this.webviewTicketRepository.consume({
        ticketReference: ticket,
         ...(request.clientId === undefined ? {} : { clientId: request.clientId }),
         sessionReference: request.sessionReference,
        ...(request.binding === undefined ? {} : { binding: request.binding }),
      });
      if (record !== undefined) {
        consumed = {
          ticket,
          expiresAt: record.expiresAt,
          sessionReference: request.sessionReference,
          applicationId: record.applicationId,
          platformId: record.platformId,
          clientKind: "webview",
          redirectUri: record.redirectUri,
        };
      }
    } else {
      throw new ApplicationPlatformError("webview_ticket_not_configured", "Webview ticket service is not configured");
    }
    if (consumed === undefined) throw new ApplicationPlatformError("invalid_webview_ticket", "Webview ticket is invalid or has already been used");
    if (consumed.applicationId !== undefined && consumed.applicationId !== applicationId) throw new ApplicationPlatformError("webview_ticket_scope_mismatch", "Webview ticket application does not match");
    if (consumed.platformId !== undefined && consumed.platformId !== platformId) throw new ApplicationPlatformError("webview_ticket_scope_mismatch", "Webview ticket platform does not match");
    if (consumed.sessionReference === undefined) throw new ApplicationPlatformError("session_not_found", "Client session is unavailable");
    const service = this.requireSessionService();
    if (service.get === undefined) throw new ApplicationPlatformError("session_not_configured", "Client session service is not configured");
    const session = await service.get({ sessionReference: consumed.sessionReference, ...(consumed.client === undefined ? {} : { client: consumed.client }) });
    if (session === undefined) throw new ApplicationPlatformError("session_not_found", "Client session is unavailable");
    const source = this.assertSessionOwnership(applicationId, platformId, session, consumed.client ?? request.client);
    const transferred = await service.refresh({
      sessionReference: source.sessionReference,
      client: "webview",
      ...(runtimeRequest === undefined ? {} : { runtimeRequest }),
    });
    if (transferred.sessionReference === source.sessionReference) throw new ApplicationPlatformError("session_issue_failed", "Webview client session could not be issued");
    return this.assertSessionOwnership(applicationId, platformId, transferred, "webview");
  }

  async issueWebviewTicketService(applicationId: string, platformId: string, input: unknown, runtimeRequest?: unknown): Promise<ApplicationPlatformWebviewTicket> {
    return this.issueWebviewTicket(applicationId, platformId, input, runtimeRequest);
  }

  async redeemWebviewTicket(applicationId: string, platformId: string, input: unknown, runtimeRequest?: unknown): Promise<OpaqueClientSessionResult> {
    return this.exchangeWebviewTicket(applicationId, platformId, input, runtimeRequest);
  }

  async exchangeWebviewTicketService(applicationId: string, platformId: string, input: unknown, runtimeRequest?: unknown): Promise<OpaqueClientSessionResult> {
    return this.exchangeWebviewTicket(applicationId, platformId, input, runtimeRequest);
  }

  private requireSessionService(): ApplicationPlatformSessionService {
    if (this.sessionService === undefined) throw new ApplicationPlatformError("session_not_configured", "Client session service is not configured");
    return this.sessionService;
  }

  private assertSessionOwnership(applicationId: string, platformId: string, result: OpaqueClientSessionResult, expectedClient?: ApplicationPlatformClient): OpaqueClientSessionResult {
    if (result.applicationId !== applicationId || result.platformId !== platformId) {
      throw new ApplicationPlatformError("session_scope_mismatch", "Client session scope does not match");
    }
    const sanitized = sanitizeOpaqueResult(result);
    if (expectedClient !== undefined && normalizeClient(expectedClient) !== sanitized.client) {
      throw new ApplicationPlatformError("session_scope_mismatch", "Client session scope does not match");
    }
    return sanitized;
  }

  private completeIdentitySession<T extends PlatformLoginResult>(
    context: { applicationId: string; platformId: string; kind: ApplicationPlatformClient; request: unknown; binding?: PlatformLoginBindingInput; runtimeRequest?: unknown },
    operation: () => Promise<T>,
  ): Promise<T> {
    const execute = async (): Promise<T> => {
      const result = await operation();
      if (this.requireOpaqueClientSession && context.kind !== "web") assertOpaquePlatformResult(result);
      return result;
    };
    const transaction = this.hostTransaction === undefined ? execute : () => this.hostTransaction!(execute);
    if (this.identitySessionBoundary === undefined) return transaction();
    return this.identitySessionBoundary.run(transaction, createIdentitySessionBoundaryContext(this.repository.tenantId, context));
  }

  async createAuthorizationUrl(
    applicationId: string,
    platformId: string,
    request: ApplicationPlatformAuthorizationRequest,
  ): Promise<string> {
    const platform = await this.getActivePlatform(applicationId, platformId);
    const adapter = this.getAdapter(platform.type, platform);
    if (!adapter.supportsAuthorization) {
      throw new ApplicationPlatformError("authorization_not_supported", "Application platform does not support browser authorization");
    }
    const client = readPlatformClientAliases(request as unknown as Record<string, unknown>) ?? "web";
    const redirectUri = client === "native" || client === "mp_weixin" || client === "mini_program"
      ? assertNativeRegisteredRedirectUri(request.redirectUri, platform.redirectUris)
      : assertRegisteredPlatformRedirectUri(request.redirectUri, platform.redirectUris);
    const credentials = await this.credentials(platform);
    const adapterClient = client === "webview" || client === "mp_weixin" ? "web" as const : client === "web" || client === "native" ? client : undefined;
    try {
      const authorizationUrl = adapter.createAuthorizationUrl({
        appId: credentials.appId,
        redirectUri,
        state: request.state,
        ...(request.scope === undefined && platform.scope === undefined ? {} : { scope: request.scope ?? (platform.scope ?? undefined) }),
        ...(adapterClient === undefined ? {} : { client: adapterClient }),
      });
      return assertSafeAuthorizationUrl(authorizationUrl, request.state);
    } catch (error) {
      throw toSafeApplicationPlatformError(
        error,
        "authorization_url_failed",
        "Application platform authorization URL could not be created",
      );
    }
  }

  async exchangeCode(
    applicationId: string,
    platformId: string,
    code: string,
    redirectUri?: string,
    client?: ApplicationPlatformClient,
    persistExternalIdentity = true,
  ): Promise<PlatformIdentity> {
    const platform = await this.getActivePlatform(applicationId, platformId);
    const adapter = this.getAdapter(platform.type, platform);
    const credentials = await this.credentials(platform);
    const normalizedClient = client === undefined ? undefined : normalizeClient(client);
    const registeredRedirectUri = redirectUri === undefined
      ? undefined
      : normalizedClient === undefined || normalizedClient === "web" || normalizedClient === "webview"
        ? assertRegisteredPlatformRedirectUri(redirectUri, platform.redirectUris)
        : assertNativeRegisteredRedirectUri(redirectUri, platform.redirectUris);
    const adapterClient = normalizedClient === undefined
      ? undefined
      : normalizedClient === "webview" || normalizedClient === "web"
        ? "web" as const
        : normalizedClient === "mp_weixin"
          ? "mini_program" as const
          : normalizedClient === "native"
            ? "native" as const
            : undefined;
    const input: ApplicationPlatformCodeExchangeInput = {
      appId: credentials.appId,
      ...(credentials.appSecret === undefined ? {} : { appSecret: credentials.appSecret }),
      ...(isComponentPlatformTypeName(platform.type) ? {
        componentAppId: platform.componentAppId as string,
        authorizedAppId: credentials.appId,
      } : {}),
      code,
      ...(registeredRedirectUri === undefined ? {} : { redirectUri: registeredRedirectUri }),
      ...(adapterClient === undefined ? {} : { client: adapterClient }),
    };
    try {
      const identity = sanitizePlatformIdentity(await adapter.exchangeCode(input));
      if (identity.appId !== credentials.appId) {
        throw new ApplicationPlatformError("platform_identity_mismatch", "Platform provider returned an identity for another application");
      }
      if (!identityPlatformMatches(platform.type, adapter.type, identity.platform)) {
        throw new ApplicationPlatformError("platform_identity_mismatch", "Platform provider returned an identity for another platform");
      }
       if (persistExternalIdentity && typeof this.repository.upsertExternalIdentity === "function") {
         await this.persistExternalIdentity(applicationId, platformId, identity);
       }
       return identity;
    } catch (error) {
      throw toSafeApplicationPlatformError(
        error,
        "platform_exchange_failed",
        "Application platform code exchange failed",
      );
    }
  }

  private async assertApplicationChannel(applicationId: string, channel: "web" | "native" | "webview"): Promise<void> {
    const application = await this.repository.getApplication(applicationId);
    if (!application || lifecycleStatusOf(application) !== "active") {
      throw new ApplicationPlatformError("application_unavailable", "Application is unavailable");
    }
    const applicationType = application.applicationType;
    if ((channel === "web" || channel === "webview") && applicationType === "native") {
      throw new ApplicationPlatformError("platform_client_not_allowed", "Platform login channel is not allowed for this application");
    }
  }

  private assertPublicRequest(value: unknown): asserts value is ApplicationPlatformPublicLoginRequest {
    if (!isRecord(value)) {
      throw new ApplicationPlatformError("invalid_platform_request", "Platform login request is invalid");
    }
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
      "state",
      "code",
      "authorizationCode",
      "hostContext",
      "context",
      "authenticatedUserId",
      "tenantId",
      "tenant_id",
      "applicationId",
      "application_id",
      "platformId",
      "platform_id",
      "return_to",
    ]) {
      if (Object.prototype.hasOwnProperty.call(value, key)) {
        throw new ApplicationPlatformError("invalid_platform_request", "Platform login request is invalid");
      }
    }
    if (typeof value.redirectUri !== "string" || value.redirectUri.trim().length === 0) {
      throw new ApplicationPlatformError("invalid_platform_request", "Platform login request is invalid");
    }
    if (value.scope !== undefined && typeof value.scope !== "string") {
      throw new ApplicationPlatformError("invalid_platform_request", "Platform login request is invalid");
    }
    if (value.returnTo !== undefined) assertPlatformLoginReturnTo(value.returnTo);
    readPlatformClientAliases(value);
  }

  private assertPublicCallbackRequest(value: unknown): void {
    if (!isRecord(value)) {
      throw new ApplicationPlatformError("invalid_platform_request", "Platform callback is invalid");
    }
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
      "returnTo",
      "return_to",
    ]) {
      if (Object.prototype.hasOwnProperty.call(value, key)) {
        throw new ApplicationPlatformError("invalid_platform_request", "Platform callback is invalid");
      }
    }
    readPlatformClientAliases(value);
  }

  private assertPublicMiniProgramRequest(value: unknown): asserts value is ApplicationPlatformMiniProgramExchangeRequest {
    if (!isRecord(value)) {
      throw new ApplicationPlatformError("invalid_platform_request", "Platform request is invalid");
    }
    for (const key of [
      "state",
      "authorizationCode",
      "error",
      "errorDescription",
      "error_description",
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
      "flowBinding",
      "flow_binding",
      "returnTo",
      "return_to",
    ]) {
      if (Object.prototype.hasOwnProperty.call(value, key)) {
        throw new ApplicationPlatformError("invalid_platform_request", "Platform request is invalid");
      }
    }
    const client = readPlatformClientAliases(value);
    if (client !== undefined && client !== "mp_weixin") {
      throw new ApplicationPlatformError("invalid_platform_client", "Platform client is invalid");
    }
    if (typeof value.code !== "string") {
      throw new ApplicationPlatformError("invalid_platform_request", "Platform request is invalid");
    }
  }

  private async resolveRequestHostContext(request: unknown): Promise<PlatformLoginHostContext | undefined> {
    if (this.resolveHostContext === undefined) return this.hostContext;
    try {
      const context = await this.resolveHostContext(request);
      if (context === undefined || context === null) return undefined;
      if (!isRecord(context)) {
        throw new ApplicationPlatformError("invalid_host_context", "Platform host context is invalid");
      }
      return context;
    } catch (error) {
      if (error instanceof ApplicationPlatformError) throw error;
      throw new ApplicationPlatformError("host_context_unavailable", "Platform host context is unavailable");
    }
  }

  private wrapLoginSessionIssuer(issuer: PlatformSessionIssuerBridge): PlatformSessionIssuerBridge {
    return {
      issue: async (input) => {
        const result = await issuer.issue(input);
        if (this.requireOpaqueClientSession) return result;
        if (input.client === "web") return result;
        if (isRecord(result) && typeof result.sessionId === "string" && result.sessionReference === undefined) {
          return { ...result, sessionReference: result.sessionId };
        }
        return result;
      },
    };
  }

  private requireLoginFlow(): PlatformLoginFlow {
    if (!this.platformLoginFlow) {
      throw new ApplicationPlatformError("platform_login_not_configured", "Platform login flow is not configured");
    }
    return this.platformLoginFlow;
  }

  private async getActivePlatform(applicationId: string, platformId: string): Promise<ApplicationPlatformRecord> {
    const application = await this.repository.getApplication(applicationId);
    if (!application || lifecycleStatusOf(application) !== "active") {
      throw new ApplicationPlatformError("application_unavailable", "Application is unavailable");
    }
    const platform = await this.repository.getPlatform(applicationId, platformId);
    if (!platform || lifecycleStatusOf(platform) !== "active") {
      throw new ApplicationPlatformError("platform_unavailable", "Application platform is unavailable");
    }
    if (platformHasComponentFields(platform) && !isComponentPlatformTypeName(platform.type)) {
      throw new ApplicationPlatformError("invalid_component_binding", "WeChat component fields require a component platform type");
    }
    if (isComponentPlatformTypeName(platform.type)) assertComponentPlatformRecord(platform);
    return platform;
  }

  private getAdapter(type: ApplicationPlatformType | string, platform?: ApplicationPlatformRecord): ApplicationPlatformAuthAdapter {
    const direct = this.registry.get(type);
    if (isComponentPlatformTypeName(type)) {
      if (platform !== undefined) assertComponentPlatformRecord(platform);
      if (direct !== undefined) {
        if (isComponentAdapter(direct) && platform !== undefined) assertComponentAdapterBinding(direct, platform);
        return direct;
      }
      const baseType = componentBasePlatformType(type);
      const mapped = this.registry.get(baseType);
      if (mapped === undefined || !isComponentAdapter(mapped)) {
        throw new ApplicationPlatformError("component_adapter_not_configured", "WeChat component adapter is not configured");
      }
      if (platform !== undefined) assertComponentAdapterBinding(mapped, platform);
      return mapped;
    }
    if (!direct) {
      throw new ApplicationPlatformError("unsupported_platform", "Application platform adapter is not registered");
    }
    return direct;
  }

  private async persistExternalIdentity(
    applicationId: string,
    platformId: string,
    identity: PlatformIdentity,
    canonicalUserId?: string,
  ): Promise<void> {
    if (typeof this.repository.upsertExternalIdentity !== "function") return;
    await this.repository.upsertExternalIdentity(applicationId, {
      platformId,
      provider: identity.provider,
      platform: identity.platform,
      appId: identity.appId,
      subject: identity.subject,
      externalAppId: identity.appId,
      openid: identity.openid,
      unionid: identity.unionid,
      nickname: identity.nickname,
      email: identity.email,
      avatarUrl: identity.avatarUrl,
      scopes: identity.scopes,
      canonicalUserId,
      linkStatus: canonicalUserId === undefined ? "pending" : "linked",
      emailVerified: identity.emailVerified,
    });
  }

  private async credentials(platform: ApplicationPlatformRecord): Promise<ApplicationPlatformCredentials> {
    const component = isComponentPlatformTypeName(platform.type);
    const expectedAppId = component
      ? componentAuthorizedAppId(platform)
      : typeof platform.externalAppId === "string" && platform.externalAppId.trim().length > 0 ? platform.externalAppId.trim() : undefined;
    if (component && expectedAppId === undefined) {
      throw new ApplicationPlatformError("invalid_component_binding", "WeChat component authorized account is not configured");
    }
    let credentials: ApplicationPlatformCredentials | undefined;
    if (this.secretBindings !== undefined && (!component || this.resolveSecret !== undefined)) {
      if (this.resolveSecret === undefined) {
        throw new ApplicationPlatformError("invalid_platform_login_configuration", "Platform secret resolver is not configured");
      }
      try {
        const resolution = await this.secretBindings.resolve("application-platform", platform.id, "platform-secret");
        if (resolution === undefined || typeof expectedAppId !== "string") {
          throw new Error("unavailable");
        }
        credentials = {
          appId: expectedAppId,
          appSecret: await this.resolveSecret(resolution.binding.secretRef),
        };
      } catch {
        if (component && this.resolveCredentials === undefined) {
          credentials = undefined;
        } else {
          throw new ApplicationPlatformError("credential_unavailable", "Application platform credentials are unavailable");
        }
      }
    } else if (this.resolveCredentials !== undefined) {
      try {
        credentials = await this.resolveCredentials(platform);
      } catch {
        throw new ApplicationPlatformError("credential_unavailable", "Application platform credentials are unavailable");
      }
    } else if (!component) {
      throw new ApplicationPlatformError("invalid_platform_login_configuration", "Platform credential resolver is not configured");
    }
    if (credentials === undefined && component) {
      return { appId: expectedAppId as string };
    }
    if (
      !credentials ||
      typeof credentials.appId !== "string" ||
      credentials.appId.trim().length === 0 ||
      credentials.appId.trim().length > 512 ||
      /[\u0000-\u001f\u007f\s]/u.test(credentials.appId.trim()) ||
      (credentials.appSecret !== undefined && (
        typeof credentials.appSecret !== "string" ||
        credentials.appSecret.trim().length === 0 ||
        credentials.appSecret.trim().length > 512 ||
        /[\u0000-\u001f\u007f\s]/u.test(credentials.appSecret.trim())
      ))
    ) {
      throw new ApplicationPlatformError("invalid_credentials", "Application platform credentials are unavailable");
    }
    if (component && expectedAppId !== undefined && credentials.appId.trim() !== expectedAppId.trim()) {
      throw new ApplicationPlatformError("invalid_component_binding", "WeChat component authorized account binding is invalid");
    }
    return {
      appId: credentials.appId.trim(),
      ...(credentials.appSecret === undefined ? {} : { appSecret: credentials.appSecret.trim() }),
    };
  }
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

function redactFlowBinding(value: unknown): unknown {
  if (!isRecord(value)) return value;
  const redacted = { ...value };
  delete redacted.flowBinding;
  delete redacted.flow_binding;
  const body = isRecord(value.body) ? { ...value.body } : value.body;
  const query = isRecord(value.query) ? { ...value.query } : value.query;
  if (isRecord(body)) {
    delete body.flowBinding;
    delete body.flow_binding;
  }
  if (isRecord(query)) {
    delete query.flowBinding;
    delete query.flow_binding;
  }
  return {
    ...redacted,
    ...(body === undefined ? {} : { body }),
    ...(query === undefined ? {} : { query }),
  };
}

function publicCallbackFields(request: ApplicationPlatformCallbackRequest): {
  state: string;
  code?: string;
  authorizationCode?: string;
  error?: string | null;
  errorDescription?: string;
  redirectUri?: string;
} {
  return {
    state: request.state,
    ...(typeof request.code === "string" ? { code: request.code } : {}),
    ...(typeof request.authorizationCode === "string" ? { authorizationCode: request.authorizationCode } : {}),
    ...(request.error === undefined ? {} : { error: request.error }),
    ...(typeof request.errorDescription === "string" ? { errorDescription: request.errorDescription } : {}),
    ...(typeof request.redirectUri === "string" ? { redirectUri: request.redirectUri } : {}),
  };
}

function platformHasComponentFields(platform: ApplicationPlatformRecord): boolean {
  return [
    "componentAppId",
    "authorizedAppId",
    "authorizerAppId",
    "componentBinding",
    "componentAppSecretRef",
    "componentVerifyTicketRef",
    "componentAccessTokenRef",
    "authorizerRefreshTokenRef",
    "authorizerAccessTokenRef",
    "componentTicketRef",
    "componentTicketExpiresAt",
    "componentBindingStatus",
    "componentBindingVersion",
    "componentScope",
  ].some((field) => Object.prototype.hasOwnProperty.call(platform, field));
}

function isComponentPlatformTypeName(value: unknown): value is "wechat_component" | "wechat_open_platform_component" {
  return value === "wechat_component" || value === "wechat_open_platform_component";
}

function componentBasePlatformType(value: "wechat_component" | "wechat_open_platform_component"): "wechat_official_account" | "wechat_open_platform" {
  return value === "wechat_open_platform_component" ? "wechat_open_platform" : "wechat_official_account";
}

function componentAuthorizedAppId(platform: ApplicationPlatformRecord): string | undefined {
  const authorized = typeof platform.authorizedAppId === "string" && platform.authorizedAppId.trim().length > 0 ? platform.authorizedAppId.trim() : undefined;
  const authorizer = typeof platform.authorizerAppId === "string" && platform.authorizerAppId.trim().length > 0 ? platform.authorizerAppId.trim() : undefined;
  if (authorized !== undefined && authorizer !== undefined && authorized !== authorizer) {
    throw new ApplicationPlatformError("invalid_component_binding", "WeChat component authorized account aliases conflict");
  }
  return authorized ?? authorizer ?? (typeof platform.externalAppId === "string" && platform.externalAppId.trim().length > 0 ? platform.externalAppId.trim() : undefined);
}

function assertComponentPlatformRecord(platform: ApplicationPlatformRecord): void {
  if (!isComponentPlatformTypeName(platform.type)) return;
  if (typeof platform.componentAppId !== "string" || platform.componentAppId.trim().length === 0) {
    throw new ApplicationPlatformError("invalid_component_binding", "WeChat componentAppId is not configured");
  }
  const authorized = componentAuthorizedAppId(platform);
  if (authorized === undefined) throw new ApplicationPlatformError("invalid_component_binding", "WeChat component authorized account is not configured");
}

function isComponentAdapter(value: unknown): value is ApplicationPlatformAdapter & {
  componentAppId: string;
  bindAuthorizedAccount: (binding: unknown) => void;
  resolveComponentAccessToken: (input: string | { authorizedAppId: string }) => Promise<string>;
} {
  if (value === null || typeof value !== "object") return false;
  const candidate = value as Record<string, unknown>;
  return typeof candidate.componentAppId === "string" &&
    typeof candidate.bindAuthorizedAccount === "function" &&
    typeof candidate.resolveComponentAccessToken === "function";
}

function assertComponentAdapterBinding(adapter: ApplicationPlatformAdapter, platform: ApplicationPlatformRecord): void {
  if (!isComponentAdapter(adapter)) return;
  assertComponentPlatformRecord(platform);
  if (adapter.componentAppId.trim() !== String(platform.componentAppId).trim()) {
    throw new ApplicationPlatformError("invalid_component_binding", "WeChat componentAppId does not match the adapter");
  }
}

function identityPlatformMatches(platformType: string, adapterType: string, identityType: string): boolean {
  if (identityType === adapterType) return true;
  return isComponentPlatformTypeName(platformType) && identityType === componentBasePlatformType(platformType);
}

function assertSafeAuthorizationUrl(value: unknown, expectedState?: string): string {
  let parsed: URL;
  try {
    parsed = new URL(typeof value === "string" ? value : String(value));
  } catch {
    throw new ApplicationPlatformError("authorization_url_failed", "Application platform authorization URL is invalid");
  }
  if (
    value === undefined ||
    value === null ||
    (parsed.protocol !== "https:" && parsed.protocol !== "http:") ||
    (parsed.protocol !== "https:" && parsed.hostname !== "localhost" && parsed.hostname !== "127.0.0.1" && parsed.hostname !== "[::1]") ||
    parsed.username !== "" ||
    parsed.password !== "" ||
    parsed.hostname.length === 0 ||
    parsed.toString().length > 4096 ||
    /[\u0000-\u001f\u007f]/u.test(parsed.toString())
  ) {
    throw new ApplicationPlatformError("authorization_url_failed", "Application platform authorization URL is invalid");
  }
  for (const key of parsed.searchParams.keys()) {
    const normalized = key.toLowerCase().replace(/[^a-z0-9]/gu, "");
    if (["accesstoken", "refreshtoken", "idtoken", "sessionkey", "clientsecret", "secret", "password", "code"].includes(normalized)) {
      throw new ApplicationPlatformError("authorization_url_failed", "Application platform authorization URL contained a forbidden secret");
    }
  }
  if (expectedState !== undefined && parsed.searchParams.getAll("state").length !== 1) {
    throw new ApplicationPlatformError("authorization_url_failed", "Application platform authorization URL did not preserve login state");
  }
  if (expectedState !== undefined && parsed.searchParams.get("state") !== expectedState) {
    throw new ApplicationPlatformError("authorization_url_failed", "Application platform authorization URL did not preserve login state");
  }
  return parsed.toString();
}

function mappedRegistryAdapter(adapter: ApplicationPlatformAdapter, type: "wechat_component" | "wechat_open_platform_component"): ApplicationPlatformAuthAdapter {
  const mapped = Object.create(adapter) as Record<string, unknown>;
  Object.defineProperty(mapped, "type", { value: type, enumerable: true });
  return mapped as unknown as ApplicationPlatformAuthAdapter;
}

function registryAdapter(adapter: ApplicationPlatformAdapter): ApplicationPlatformAuthAdapter {
  if (!isComponentAdapter(adapter) || isComponentPlatformTypeName(adapter.type)) {
    return adapter as unknown as ApplicationPlatformAuthAdapter;
  }
  if (adapter.type === "wechat_official_account" || adapter.type === "wechat_component") {
    return mappedRegistryAdapter(adapter, "wechat_component");
  }
  if (adapter.type === "wechat_open_platform" || adapter.type === "wechat_open_platform_component") {
    return mappedRegistryAdapter(adapter, "wechat_open_platform_component");
  }
  return adapter as unknown as ApplicationPlatformAuthAdapter;
}

export function createDefaultApplicationPlatformRegistry(
  adapters: readonly ApplicationPlatformAdapter[] = [],
): ApplicationPlatformAdapterRegistry {
  const registry = new ApplicationPlatformAdapterRegistry()
    .register(createWechatOfficialAccountAdapter())
    .register(createWechatOpenPlatformAdapter())
    .register(createWechatMiniProgramAdapter());
  for (const adapter of adapters) registry.register(registryAdapter(adapter));
  return registry;
}

export function createApplicationPlatformAuthService(
  repository: ApplicationRepository,
  options: ApplicationPlatformAuthServiceOptions,
): ApplicationPlatformAuthService {
  return new ApplicationPlatformAuthService(repository, options);
}

function assertNativeRegisteredRedirectUri(value: unknown, registered: readonly unknown[] | undefined): string {
  if (typeof value !== "string" || value.length === 0 || value.length > 2048 || !Array.isArray(registered) || !registered.includes(value)) {
    throw new ApplicationPlatformError("invalid_redirect_uri", "Platform redirect URI is not registered for the application platform");
  }
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new ApplicationPlatformError("invalid_redirect_uri", "Platform redirect URI is invalid");
  }
  if (
    parsed.username !== "" ||
    parsed.password !== "" ||
    parsed.hash !== "" ||
    /[\u0000-\u001f\u007f\s\\]/u.test(value)
  ) {
    throw new ApplicationPlatformError("invalid_redirect_uri", "Platform redirect URI is invalid");
  }
  if (parsed.protocol === "http:") {
    if (parsed.hostname.length === 0 || (parsed.hostname !== "localhost" && parsed.hostname !== "127.0.0.1" && parsed.hostname !== "[::1]")) {
      throw new ApplicationPlatformError("invalid_redirect_uri", "Platform redirect URI is invalid");
    }
    return value;
  }
  if (parsed.protocol === "https:") {
    if (parsed.hostname.length === 0 || parsed.hostname === "localhost" || parsed.hostname === "127.0.0.1" || parsed.hostname === "[::1]") {
      throw new ApplicationPlatformError("invalid_redirect_uri", "Platform redirect URI is invalid");
    }
    return value;
  }
  if (!isRfc8252PrivateUseRedirectUri(value)) {
    throw new ApplicationPlatformError("invalid_redirect_uri", "Platform redirect URI is invalid");
  }
  return value;
}

function lifecycleStatusOf(record: { status?: unknown; lifecycleStatus?: unknown }): ApplicationStatus {
  const lifecycle = record.lifecycleStatus;
  if (lifecycle === "active" || lifecycle === "disabled" || lifecycle === "archived" || lifecycle === "purged") {
    return lifecycle;
  }
  return record.status === "disabled" || record.status === "archived" || record.status === "purged"
    ? record.status
    : "active";
}

function normalizeClient(value: unknown): ApplicationPlatformClient {
  if (value === undefined || value === "web") return "web";
  if (value === "mini_program") return "mp_weixin";
  if (value === "native" || value === "mp_weixin" || value === "webview") return value;
  throw new ApplicationPlatformError("invalid_platform_client", "Platform client is invalid");
}

function readPlatformClientAliases(value: Record<string, unknown>): ApplicationPlatformClient | undefined {
  const present = ["client", "clientKind", "clientType"].filter((key) => Object.prototype.hasOwnProperty.call(value, key));
  if (present.length === 0) return undefined;
  const normalized: ApplicationPlatformClient[] = [];
  for (const key of present) {
    const raw = value[key];
    if (typeof raw !== "string" || raw.trim().length === 0) {
      throw new ApplicationPlatformError("invalid_platform_client", "Platform client is invalid");
    }
    normalized.push(normalizeClient(raw.trim()));
  }
  if (new Set(normalized).size > 1) {
    throw new ApplicationPlatformError("invalid_platform_client", "Platform client aliases conflict");
  }
  return normalized[0];
}

function createOpaqueReference(prefix: "session" | "ticket"): string {
  return `${prefix === "session" ? "ocs" : "gbt"}_${randomBytes(32).toString("base64url")}`;
}

function normalizeOpaqueReference(value: unknown): string {
  if (typeof value !== "string") throw new ApplicationPlatformError("invalid_session_reference", "Client session reference is invalid");
  const normalized = value.trim();
  if (!/^[A-Za-z0-9_-]{16,512}$/u.test(normalized)) throw new ApplicationPlatformError("invalid_session_reference", "Client session reference is invalid");
  return normalized;
}

function normalizeOpaqueRecord(value: OpaqueClientSessionRecord): OpaqueClientSessionRecord {
  const client = normalizeClient(value.client);
  if (client === "web") throw new ApplicationPlatformError("invalid_session_reference", "Only native, mini-program, and webview sessions can use an opaque client reference");
  const userId = normalizeOpaqueText(value.userId, "user", 512);
  const applicationId = normalizeOpaqueText(value.applicationId, "application", 512);
  const platformId = normalizeOpaqueText(value.platformId, "platform", 512);
  const hostSessionToken = normalizeOpaqueText(value.hostSessionToken, "host session", 4096);
  if (!Number.isSafeInteger(value.createdAt) || value.createdAt < 0 || !Number.isSafeInteger(value.expiresAt) || value.expiresAt <= value.createdAt) {
    throw new ApplicationPlatformError("invalid_session_reference", "Client session lifetime is invalid");
  }
  return {
    sessionReference: normalizeOpaqueReference(value.sessionReference),
    userId,
    ...(value.tenantId === undefined ? {} : { tenantId: normalizeOpaqueText(value.tenantId, "tenant", 256) }),
    applicationId,
    platformId,
    ...(value.identityKey === undefined ? {} : { identityKey: normalizeOpaqueText(value.identityKey, "identity", 2048) }),
    client,
    hostSessionToken,
    createdAt: value.createdAt,
    expiresAt: value.expiresAt,
    updatedAt: Number.isSafeInteger(value.updatedAt) && value.updatedAt >= value.createdAt ? value.updatedAt : value.createdAt,
    ...(value.revokedAt === undefined ? {} : { revokedAt: value.revokedAt }),
  };
}

function cloneOpaqueRecord(value: OpaqueClientSessionRecord): OpaqueClientSessionRecord {
  return { ...value };
}

function dateTimestamp(value: unknown): number {
  const timestamp = value instanceof Date ? value.getTime() : typeof value === "number" ? value : new Date(typeof value === "string" ? value : String(value)).getTime();
  return Number.isSafeInteger(timestamp) ? timestamp : Number.NaN;
}

function readIdentityKey(input: PlatformSessionIssueInput): string | undefined {
  const value = input.projection?.identityKey;
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

function opaqueResult(record: OpaqueClientSessionRecord): OpaqueClientSessionResult & { clientKind: ApplicationPlatformOpaqueClient } {
  return {
    sessionReference: record.sessionReference,
    expiresAt: new Date(record.expiresAt).toISOString(),
    userId: record.userId,
    applicationId: record.applicationId,
    platformId: record.platformId,
    client: record.client,
    clientKind: record.client,
    ...(record.identityKey === undefined ? {} : { identityKey: record.identityKey }),
  };
}

function isOpaqueSessionIssuer(value: unknown): value is PlatformSessionIssuerBridge & ApplicationPlatformSessionService {
  if (!isRecord(value) || typeof value.issue !== "function") return false;
  return (typeof value.refresh === "function" || typeof value.refreshSession === "function") &&
    (typeof value.logout === "function" || typeof value.logoutSession === "function") &&
    (typeof value.revoke === "function" || typeof value.revokeSession === "function");
}

function normalizeApplicationPlatformSessionService(value: unknown): ApplicationPlatformSessionService | undefined {
  if (value === undefined || value === null) return undefined;
  if (!isRecord(value)) return undefined;
  const refresh = value.refresh ?? value.refreshSession;
  const logout = value.logout ?? value.logoutSession;
  const revoke = value.revoke ?? value.revokeSession;
  const get = value.get ?? value.getSession ?? value.resolve;
  if (typeof refresh !== "function" || typeof logout !== "function" || typeof revoke !== "function") return undefined;
  return {
    refresh: (input) => refresh.call(value, input),
    logout: (input) => logout.call(value, input),
    revoke: (input) => revoke.call(value, input),
    ...(typeof get === "function" ? { get: (input) => get.call(value, input) } : {}),
  };
}

function normalizeApplicationPlatformWebviewTicketService(value: unknown): ApplicationPlatformWebviewTicketService | undefined {
  if (value === undefined || value === null) return undefined;
  if (!isRecord(value)) return undefined;
  const issue = value.issue ?? value.create ?? value.issueTicket;
  const consume = value.consume ?? value.redeem ?? value.exchange;
  const revoke = value.revoke;
  const ready = value.ready;
  if (typeof issue !== "function" || typeof consume !== "function") return undefined;
  return {
    issue: (input) => issue.call(value, input),
    consume: (input) => consume.call(value, input),
    ...(typeof revoke === "function" ? { revoke: (ticket: string) => revoke.call(value, ticket) } : {}),
    ...(typeof ready === "function" ? { ready: () => ready.call(value) } : {}),
  };
}

function normalizeSessionRequest(value: unknown, ticket = false): ApplicationPlatformSessionRequest {
  if (typeof value === "string") return { sessionReference: normalizeOpaqueReference(value) };
  if (!isRecord(value)) throw new ApplicationPlatformError("invalid_session_reference", "Client session request is invalid");
  for (const key of ["token", "sessionToken", "accessToken", "refreshToken", "idToken", "hostSessionToken", "cookie", "authorization", "clientSecret", "client_secret", "appSecret", "app_secret", "componentAppSecret", "component_app_secret", "secret", "password"]) {
    if (Object.prototype.hasOwnProperty.call(value, key)) throw new ApplicationPlatformError("invalid_session_reference", "Client session request is invalid");
  }
  const sessionReference = normalizeOpaqueReference(value.sessionReference ?? value.session_reference ?? value.reference);
  const client = readPlatformClientAliases(value);
  if (client === "web" || client === "webview") throw new ApplicationPlatformError("invalid_session_reference", "Only native and mini-program sessions can use an opaque client reference");
  const clientId = value.clientId === undefined ? undefined : normalizeOpaqueText(value.clientId, "client", 512);
  const userId = value.userId === undefined ? undefined : normalizeOpaqueText(value.userId, "user", 512);
  const redirectUri = value.redirectUri === undefined && value.redirect_uri === undefined
    ? undefined
    : normalizeOpaqueText(value.redirectUri ?? value.redirect_uri, "redirect URI", 2048);
  const binding = value.binding === undefined ? undefined : normalizeOpaqueText(value.binding, "binding", 512);
  const ttlSeconds = ticket ? value.ttlSeconds ?? value.expiresInSeconds ?? value.expires_in_seconds : undefined;
  if (ttlSeconds !== undefined && (typeof ttlSeconds !== "number" || !Number.isSafeInteger(ttlSeconds) || ttlSeconds < 30 || ttlSeconds > 900)) {
    throw new ApplicationPlatformError("invalid_webview_ticket", "Webview ticket lifetime is invalid");
  }
  return {
    sessionReference,
    ...(client === undefined ? {} : { client }),
    ...(client === undefined ? {} : { clientKind: client }),
    ...(clientId === undefined ? {} : { clientId }),
    ...(userId === undefined ? {} : { userId }),
    ...(redirectUri === undefined ? {} : { redirectUri }),
    ...(binding === undefined ? {} : { binding }),
    ...(ttlSeconds === undefined ? {} : { ttlSeconds }),
  };
 }


function sanitizeOpaqueResult(value: OpaqueClientSessionResult): OpaqueClientSessionResult {
  const client = normalizeClient(value.client);
  if (client === "web") throw new ApplicationPlatformError("invalid_session_reference", "Only native, mini-program, and webview sessions can use an opaque client reference");
  return {
    sessionReference: normalizeOpaqueReference(value.sessionReference),
    expiresAt: new Date(value.expiresAt).toISOString(),
    userId: normalizeOpaqueText(value.userId, "user", 512),
    applicationId: normalizeOpaqueText(value.applicationId, "application", 512),
    platformId: normalizeOpaqueText(value.platformId, "platform", 512),
    client,
    ...(value.identityKey === undefined ? {} : { identityKey: normalizeOpaqueText(value.identityKey, "identity", 2048) }),
    ...(value.refreshed === true ? { refreshed: true } : {}),
    ...(value.revoked === true ? { revoked: true } : {}),
  };
}

function assertOpaquePlatformResult(result: PlatformLoginResult): void {
  if (result.client === "web") return;
  const reference = result.session.sessionReference ?? result.session.sessionId;
  if (result.session.response !== undefined || reference === undefined || !/^(?:ocs|gbs|gbt|sess)_[A-Za-z0-9_-]{16,512}$/u.test(reference)) {
    throw new ApplicationPlatformError("session_issuer_secret_exposed", "Opaque client sessions must not use a response");
  }
}

function createIdentitySessionBoundaryContext(
  tenantId: string,
  context: { applicationId: string; platformId: string; kind: ApplicationPlatformClient; request: unknown; binding?: PlatformLoginBindingInput },
): ApplicationPlatformIdentitySessionBoundaryContext | undefined {
  const request = isRecord(context.request) ? context.request : {};
  const state = stringValue(request.state);
  const binding = identityBoundaryBinding(context.binding ?? request.binding ?? request.browserBinding ?? request.sessionBinding);
  if (state === undefined || binding === undefined) return undefined;
  const code = stringValue(request.code ?? request.authorizationCode);
  return {
    tenantId,
    applicationId: context.applicationId,
    platformId: context.platformId,
    client: context.kind,
    state,
    binding,
    ...(code === undefined ? {} : { code }),
  };
}

function identityBoundaryBinding(value: unknown): string | undefined {
  const direct = stringValue(value);
  if (direct !== undefined) return direct;
  if (!isRecord(value)) return undefined;
  const parts = [
    value.browserId,
    value.browserBinding,
    value.sessionId,
    value.sessionBinding,
    value.browser,
    value.session,
  ].map((item) => stringValue(item)).filter((item): item is string => item !== undefined);
  return parts.length === 0 ? undefined : parts.join("|");
}

function boundaryKey(value: unknown): string | undefined {
  if (!isRecord(value)) return undefined;
  const tenantId = stringValue(value.tenantId);
  const applicationId = stringValue(value.applicationId);
  const platformId = stringValue(value.platformId);
  const client = stringValue(value.client);
  const state = stringValue(value.state);
  const binding = stringValue(value.binding);
  if (tenantId === undefined || applicationId === undefined || platformId === undefined || client === undefined || state === undefined || binding === undefined) return undefined;
  const code = stringValue(value.code);
  const material = [tenantId, applicationId, platformId, client, state, binding, ...(code === undefined ? [] : [code])].map((item) => createHash("sha256").update(item).digest("hex")).join(":");
  return createHash("sha256").update(material).digest("hex");
}

function normalizeOpaqueText(value: unknown, field: string, max: number): string {
  if (typeof value !== "string") throw new ApplicationPlatformError("invalid_session_reference", `${field} is invalid`);
  const normalized = value.trim();
  if (normalized.length === 0 || normalized.length > max || /[\u0000-\u001f\u007f]/u.test(normalized)) throw new ApplicationPlatformError("invalid_session_reference", `${field} is invalid`);
  return normalized;
}

function stringValue(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  const normalized = value.trim();
  return normalized.length > 0 && normalized.length <= 2048 && !/[\u0000-\u001f\u007f]/u.test(normalized) ? normalized : undefined;
}


function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
