import { createHash, randomUUID } from "node:crypto";
import {
  isExactOidcRedirectUri,
  type OidcGrantRevocationPort,
  type OidcLogoutCoordinator as OidcLogoutCoordinatorContract,
  type OidcLogoutOperation,
  type OidcLogoutRequest,
  type OidcLogoutResult,
  type OidcLogoutRevocationInput,
  type OidcLogoutTarget,
} from "@getbrick/idaas-core";
import type { GetbrickAuthLike } from "../tokens.js";

export const GETBRICK_OIDC_LOGOUT_COORDINATOR = "GETBRICK_OIDC_LOGOUT_COORDINATOR";
export const DEFAULT_OIDC_LOGOUT_TENANT_ID = "default";
export const DEFAULT_OIDC_LOGOUT_NAMESPACE = "default";

const DEFAULT_LOGOUT_TARGETS: readonly OidcLogoutTarget[] = [
  "op_session",
  "offline_grant",
  "better_auth",
  "bff_cookie",
];

export const DEFAULT_OIDC_LOGOUT_STATE_TTL_MS = 5 * 60 * 1000;
export const DEFAULT_OIDC_LOGOUT_MAX_OPERATIONS = 1024;
export const DEFAULT_OIDC_LOGOUT_MAX_IN_FLIGHT = 128;

export interface OidcLogoutPersistencePort {
  ready(): boolean | void | Promise<boolean | void>;
  load(idempotencyKey: string): Promise<OidcLogoutOperation | null | undefined>;
  save(operation: OidcLogoutOperation): Promise<void> | void;
  delete(idempotencyKey: string): Promise<void> | void;
}

export type OidcLogoutPersistenceLike =
  | OidcLogoutPersistencePort
  | {
      ready(): boolean | void | Promise<boolean | void>;
      load?: (idempotencyKey: string) => Promise<OidcLogoutOperation | null | undefined>;
      get?: (idempotencyKey: string) => Promise<OidcLogoutOperation | null | undefined>;
      save?: (operation: OidcLogoutOperation) => Promise<void> | void;
      set?: (operation: OidcLogoutOperation) => Promise<void> | void;
      delete?: (idempotencyKey: string) => Promise<void> | void;
      remove?: (idempotencyKey: string) => Promise<void> | void;
    };

export interface OidcLogoutStateOptions {
  stateTtlMs?: number;
  operationTtlMs?: number;
  ttlMs?: number;
  maxOperations?: number;
  maxEntries?: number;
  maxInFlight?: number;
}

class TtlMap<T> {
  private readonly entries = new Map<string, { value: T; expiresAt: number }>();

  constructor(
    private readonly ttlMs: number,
    private readonly maxEntries: number,
    private readonly clock: () => number,
  ) {}

  get size(): number {
    this.pruneExpired();
    return this.entries.size;
  }

  get(key: string): T | undefined {
    this.pruneExpired();
    return this.entries.get(key)?.value;
  }

  set(key: string, value: T): void {
    this.pruneExpired();
    this.entries.delete(key);
    while (this.entries.size >= this.maxEntries) {
      const oldest = this.entries.keys().next().value as string | undefined;
      if (oldest === undefined) break;
      this.entries.delete(oldest);
    }
    this.entries.set(key, { value, expiresAt: this.clock() + this.ttlMs });
  }

  delete(key: string): boolean {
    return this.entries.delete(key);
  }

  has(key: string): boolean {
    return this.get(key) !== undefined;
  }

  clear(): void {
    this.entries.clear();
  }

  forEach(callback: (value: T, key: string) => void): void {
    this.pruneExpired();
    for (const [key, entry] of this.entries) callback(entry.value, key);
  }

  private pruneExpired(): void {
    const now = this.clock();
    for (const [key, entry] of this.entries) {
      if (entry.expiresAt <= now) this.entries.delete(key);
    }
  }
}

interface FailedOperationState {
  operation: OidcLogoutOperation;
  fingerprint: string;
  revokedTargets: Set<OidcLogoutTarget>;
}

interface CompletedOperationState {
  result: OidcLogoutResult;
  fingerprint: string;
}

export interface OidcLogoutRequestContext {
  headers?: Headers | Record<string, unknown>;
  requestHeaders?: Headers | Record<string, unknown>;
  response?: unknown;
  clientId?: string;
  userId?: string;
  providerSessionId?: string;
  postLogoutRedirectUri?: string;
  providerSessionRevoked?: boolean;
  providerGrantRevoked?: boolean;
  grantIds?: readonly string[];
}

export interface OidcSessionRevocationInput extends OidcLogoutRevocationInput {
  context?: OidcLogoutRequestContext;
}

export type OidcSessionRevocationResult =
  | readonly OidcLogoutTarget[]
  | { revokedTargets: readonly OidcLogoutTarget[] }
  | void;

export interface OidcSessionRevocationPort {
  revoke(
    input: OidcSessionRevocationInput,
    context?: OidcLogoutRequestContext,
  ): OidcSessionRevocationResult | Promise<OidcSessionRevocationResult>;
}

export type OidcLogoutSessionRevocationPort = OidcSessionRevocationPort;
export type OidcLogoutSessionPort = OidcSessionRevocationPortLike;
export type OidcLogoutRevocationPort = OidcSessionRevocationPort;
export type OidcLogoutGrantRevocationPort = OidcGrantRevocationPort;
export type OidcLogoutGrantPort = OidcGrantRevocationPortLike;

type AnyFunction = { bivarianceHack(...args: unknown[]): unknown }["bivarianceHack"];

export type OidcSessionRevocationPortLike =
  | OidcSessionRevocationPort
  | AnyFunction
  | {
      revoke?: AnyFunction;
      revokeSession?: AnyFunction;
      revokeBySessionId?: AnyFunction;
      revokeByAccountId?: AnyFunction;
      clearCookie?: AnyFunction;
      clearCookies?: AnyFunction;
      revokeCookie?: AnyFunction;
    };

export type OidcGrantRevocationPortLike =
  | OidcGrantRevocationPort
  | AnyFunction
  | {
      revoke?: AnyFunction;
      revokeByGrantId?: AnyFunction;
      revokeByAccountId?: AnyFunction;
    };

export type OidcLogoutClientResolver = (clientId: string) => unknown | Promise<unknown>;

export type OidcLogoutCoordinatorLike = Omit<OidcLogoutCoordinatorContract, "complete"> & {
  preflight?: (request: OidcLogoutRequest) => Promise<void>;
  ready?: () => boolean | void | Promise<boolean | void>;
  persistence?: OidcLogoutPersistenceLike;
  operationStore?: OidcLogoutPersistenceLike;
  complete(
    operation: OidcLogoutOperation,
    context: OidcLogoutRequestContext,
  ): Promise<OidcLogoutResult>;
};

export interface OidcLogoutCoordinatorOptions extends OidcLogoutStateOptions {
  resolveClient?: OidcLogoutClientResolver;
  clientResolver?: OidcLogoutClientResolver;
  findClient?: OidcLogoutClientResolver;
  clientLookup?: OidcLogoutClientResolver;
  clients?: Record<string, unknown>;
  sessionRevocation?: OidcSessionRevocationPortLike;
  sessionRevocationPort?: OidcSessionRevocationPortLike;
  sessionPort?: OidcSessionRevocationPortLike;
  grantRevocation?: OidcGrantRevocationPortLike;
  grantRevocationPort?: OidcGrantRevocationPortLike;
  grantPort?: OidcGrantRevocationPortLike;
  auth?: GetbrickAuthLike;
  issuer?: string;
  provider?: unknown;
  adapter?: unknown;
  profile?: "development" | "test" | "staging" | "production";
  tenantId?: string;
  applicationId?: string;
  namespace?: string;
  targets?: readonly OidcLogoutTarget[];
  now?: () => Date;
  createOperationId?: () => string;
  persistence?: OidcLogoutPersistenceLike;
  operationStore?: OidcLogoutPersistenceLike;
}

export class OidcLogoutCoordinator implements OidcLogoutCoordinatorContract {
  readonly tenantId: string;
  readonly applicationId?: string;
  readonly namespace: string;

  private readonly clientResolver?: OidcLogoutClientResolver;
  private readonly sessionPort?: OidcSessionRevocationPortLike;
  private readonly grantPort?: OidcGrantRevocationPortLike;
  private readonly targets: readonly OidcLogoutTarget[];
  private readonly now: () => Date;
  private readonly nowMs: () => number;
  readonly stateTtlMs: number;
  readonly maxOperations: number;
  readonly maxInFlight: number;
  private readonly createOperationId: () => string;
  readonly persistence?: OidcLogoutPersistenceLike;
  readonly operationStore?: OidcLogoutPersistenceLike;
  private readonly operations: TtlMap<OidcLogoutOperation>;
  private readonly fingerprints: TtlMap<string>;
  private readonly preparing: TtlMap<Promise<OidcLogoutOperation>>;
  private readonly revokedByOperation: TtlMap<Set<OidcLogoutTarget>>;
  private readonly failedOperations: TtlMap<FailedOperationState>;
  private readonly completedOperations: TtlMap<CompletedOperationState>;
  private readonly inFlight: TtlMap<Promise<OidcLogoutResult>>;

  constructor(options: OidcLogoutCoordinatorOptions);
  constructor(
    resolveClient: OidcLogoutClientResolver,
    sessionPort?: OidcSessionRevocationPortLike,
    grantPort?: OidcGrantRevocationPortLike,
  );
  constructor(
    optionsOrResolver: OidcLogoutCoordinatorOptions | OidcLogoutClientResolver,
    sessionPort?: OidcSessionRevocationPortLike,
    grantPort?: OidcGrantRevocationPortLike,
  ) {
    const options: OidcLogoutCoordinatorOptions = typeof optionsOrResolver === "function"
      ? {
          resolveClient: optionsOrResolver,
          sessionRevocation: sessionPort,
          grantRevocation: grantPort,
        }
      : optionsOrResolver;
    this.tenantId = normalizeOptionalText(options.tenantId) ?? DEFAULT_OIDC_LOGOUT_TENANT_ID;
    this.applicationId = normalizeOptionalText(options.applicationId);
    this.namespace = normalizeOptionalText(options.namespace) ?? DEFAULT_OIDC_LOGOUT_NAMESPACE;
    const provider = options.provider;
    const providerClient = isObjectLike(provider) && isObjectLike(provider.Client) ? provider.Client : undefined;
    const providerClientFind = providerClient !== undefined && typeof providerClient.find === "function"
      ? providerClient.find
      : undefined;
    this.clientResolver = options.resolveClient ?? options.clientResolver ?? options.findClient ?? options.clientLookup
      ?? (options.clients === undefined ? undefined : async (clientId: string) => options.clients?.[clientId])
      ?? (providerClientFind === undefined ? undefined : async (clientId: string) => providerClientFind.call(providerClient, clientId));
    this.sessionPort = options.sessionRevocation ?? options.sessionRevocationPort ?? options.sessionPort
      ?? (options.auth !== undefined && options.issuer !== undefined && (options.profile === "development" || options.profile === "test")
        ? createBetterAuthOidcSessionRevocationPort(options.auth, options.issuer)
        : undefined);
    this.grantPort = options.grantRevocation ?? options.grantRevocationPort ?? options.grantPort
      ?? (options.provider !== undefined && (options.profile === "development" || options.profile === "test")
        ? createProviderOidcGrantRevocationPort(options.provider, options.adapter)
        : undefined);
    this.targets = normalizeTargets(options.targets ?? DEFAULT_LOGOUT_TARGETS);
    this.now = options.now ?? (() => new Date());
    this.nowMs = () => {
      const value = this.now().getTime();
      if (!Number.isFinite(value)) throw new Error("OIDC logout clock is invalid");
      return value;
    };
    this.stateTtlMs = normalizePositiveInteger(
      options.stateTtlMs ?? options.operationTtlMs ?? options.ttlMs,
      DEFAULT_OIDC_LOGOUT_STATE_TTL_MS,
      "state TTL",
    );
    this.maxOperations = normalizePositiveInteger(
      options.maxOperations ?? options.maxEntries,
      DEFAULT_OIDC_LOGOUT_MAX_OPERATIONS,
      "operation capacity",
    );
    this.maxInFlight = normalizePositiveInteger(
      options.maxInFlight,
      Math.min(DEFAULT_OIDC_LOGOUT_MAX_IN_FLIGHT, this.maxOperations),
      "in-flight capacity",
    );
    this.persistence = options.persistence ?? options.operationStore;
    this.operationStore = this.persistence;
    this.operations = new TtlMap(this.stateTtlMs, this.maxOperations, this.nowMs);
    this.fingerprints = new TtlMap(this.stateTtlMs, this.maxOperations, this.nowMs);
    this.preparing = new TtlMap(this.stateTtlMs, this.maxInFlight, this.nowMs);
    this.revokedByOperation = new TtlMap(this.stateTtlMs, this.maxOperations, this.nowMs);
    this.failedOperations = new TtlMap(this.stateTtlMs, this.maxOperations, this.nowMs);
    this.completedOperations = new TtlMap(this.stateTtlMs, this.maxOperations, this.nowMs);
    this.inFlight = new TtlMap(this.stateTtlMs, this.maxInFlight, this.nowMs);
    this.createOperationId = options.createOperationId ?? randomUUID;
  }

  async ready(): Promise<boolean> {
    if (this.persistence === undefined) return true;
    return (await this.persistence.ready()) !== false;
  }

  async preflight(request: OidcLogoutRequest): Promise<void> {
    validateLogoutRequest(request);
    await this.validateClientAndRedirect(request.clientId, request.postLogoutRedirectUri);
  }

  async prepare(request: OidcLogoutRequest): Promise<OidcLogoutOperation> {
    validateLogoutRequest(request);
    this.pruneConsistentState();
    const fingerprint = requestFingerprint(request);
    await this.loadPersisted(request.idempotencyKey, fingerprint);
    const completed = this.completedOperations.get(request.idempotencyKey);
    if (completed !== undefined) {
      if (completed.fingerprint.length > 0 && completed.fingerprint !== fingerprint) {
        throw new Error("[getbrick-idaas] OIDC logout idempotency key conflicts with another request");
      }
      return cloneOperation(completed.result.operation);
    }
    const failed = this.failedOperations.get(request.idempotencyKey);
    if (failed !== undefined) {
      if (failed.fingerprint.length > 0 && failed.fingerprint !== fingerprint) {
        throw new Error("[getbrick-idaas] OIDC logout idempotency key conflicts with another request");
      }
      return cloneOperation(failed.operation);
    }
    const existing = this.operations.get(request.idempotencyKey);
    if (existing !== undefined) {
      if (this.fingerprints.get(request.idempotencyKey) !== fingerprint) {
        throw new Error("[getbrick-idaas] OIDC logout idempotency key conflicts with another request");
      }
      return cloneOperation(existing);
    }
    const current = this.preparing.get(request.idempotencyKey);
    if (current !== undefined) {
      const operation = await current;
      if (this.fingerprints.get(request.idempotencyKey) !== fingerprint) {
        throw new Error("[getbrick-idaas] OIDC logout idempotency key conflicts with another request");
      }
      return cloneOperation(operation);
    }
    const promise = this.prepareNew(request, fingerprint);
    this.preparing.set(request.idempotencyKey, promise);
    try {
      return cloneOperation(await promise);
    } finally {
      if (this.preparing.get(request.idempotencyKey) === promise) this.preparing.delete(request.idempotencyKey);
    }
  }

  private async prepareNew(request: OidcLogoutRequest, fingerprint: string): Promise<OidcLogoutOperation> {
    await this.validateClientAndRedirect(request.clientId, request.postLogoutRedirectUri);
    const timestamp = this.now().toISOString();
    const operation: OidcLogoutOperation = {
      contractVersion: 1,
      operationId: this.createOperationId(),
      tenantId: request.tenantId,
      ...(request.applicationId === undefined ? {} : { applicationId: request.applicationId }),
      clientId: request.clientId,
      ...(request.userId === undefined ? {} : { userId: request.userId }),
      ...(request.providerSessionId === undefined ? {} : { providerSessionId: request.providerSessionId }),
      status: "pending",
      idempotencyKey: request.idempotencyKey,
      targets: [...this.targets],
      createdAt: timestamp,
      updatedAt: timestamp,
    };
    this.saveActiveOperation(operation, fingerprint);
    try {
      await this.persistOperation(operation);
    } catch (error) {
      this.removeActiveOperation(operation.idempotencyKey, operation.operationId);
      throw error;
    }
    return operation;
  }

  async complete(
    operation: OidcLogoutOperation,
    context: OidcLogoutRequestContext = {},
  ): Promise<OidcLogoutResult> {
    validateOperation(operation);
    this.pruneConsistentState();
    await this.loadPersisted(operation.idempotencyKey, operationFingerprint(operation));
    const completed = this.completedOperations.get(operation.idempotencyKey);
    if (completed !== undefined) return cloneResult(completed.result);
    const current = this.inFlight.get(operation.operationId);
    if (current !== undefined) return current;
    const promise = this.completeInternal(operation, context).catch((error: unknown) => this.recordFailure(operation, error));
    this.inFlight.set(operation.operationId, promise);
    try {
      return await promise;
    } finally {
      if (this.inFlight.get(operation.operationId) === promise) this.inFlight.delete(operation.operationId);
    }
  }

  private async completeInternal(
    operation: OidcLogoutOperation,
    context: OidcLogoutRequestContext,
  ): Promise<OidcLogoutResult> {
    const key = operation.idempotencyKey;
    const failedState = this.failedOperations.get(key);
    const stored = this.operations.get(key);
    let source = stored === undefined
      ? failedState === undefined ? cloneOperation(operation) : cloneOperation(failedState.operation)
      : cloneOperation(stored);
    const fingerprint = this.fingerprints.get(key)
      ?? failedState?.fingerprint
      ?? operationFingerprint(source);
    if (context.clientId !== undefined && context.clientId !== source.clientId) {
      throw new Error("OIDC logout client verification failed");
    }
    if (context.userId !== undefined) {
      if (source.userId !== undefined && context.userId !== source.userId) {
        throw new Error("OIDC logout session binding failed");
      }
      source = { ...source, userId: context.userId };
    }
    if (context.providerSessionId !== undefined) {
      if (source.providerSessionId !== undefined && context.providerSessionId !== source.providerSessionId) {
        throw new Error("OIDC logout provider session verification failed");
      }
      source = { ...source, providerSessionId: context.providerSessionId };
    }
    if (source.status === "completed") {
      const result = { operation: cloneOperation(source), revokedTargets: [...source.targets], completed: true };
      await this.persistOperation(result.operation);
      this.completedOperations.set(key, { result: cloneResult(result), fingerprint });
      this.failedOperations.delete(key);
      this.removeActiveOperation(key, source.operationId);
      return cloneResult(result);
    }
    const targets = normalizeTargets(source.targets);
    const revokedTargets = new Set<OidcLogoutTarget>(
      this.revokedByOperation.get(source.operationId) ?? failedState?.revokedTargets ?? [],
    );
    const revoking: OidcLogoutOperation = {
      ...source,
      status: "revoking",
      updatedAt: this.now().toISOString(),
    };
    this.failedOperations.delete(key);
    this.saveActiveOperation(revoking, fingerprint);
    try {
      await this.persistOperation(revoking);
      if (context.providerSessionRevoked === true) revokedTargets.add("op_session");
      if (context.providerGrantRevoked === true) revokedTargets.add("offline_grant");
      const sessionTargets = targets.filter((target) => target !== "offline_grant" && !revokedTargets.has(target));
      if (sessionTargets.length > 0) {
        if (this.sessionPort === undefined) throw new Error("OIDC session revocation port is unavailable");
        const invocation = await invokeSessionPort(this.sessionPort, {
          operation: revoking,
          targets: sessionTargets,
          context,
        }, context);
        assertPortResult(invocation.result);
        addTargets(revokedTargets, invocation.targets, invocation.result);
        this.revokedByOperation.set(revoking.operationId, new Set(revokedTargets));
      }
      const grantTargets = targets.filter((target) => target === "offline_grant" && !revokedTargets.has(target));
      if (grantTargets.length > 0) {
        if (this.grantPort === undefined) throw new Error("OIDC grant revocation port is unavailable");
        const result = await invokeGrantPort(this.grantPort, revoking, grantTargets, context, this.namespace);
        assertPortResult(result);
        addTargets(revokedTargets, grantTargets, result);
        this.revokedByOperation.set(revoking.operationId, new Set(revokedTargets));
      }
      const missing = targets.filter((target) => !revokedTargets.has(target));
      if (missing.length > 0) throw new Error(`OIDC logout targets were not revoked: ${missing.join(",")}`);
      const { errorCode: _errorCode, ...completedBase } = revoking;
      const completed: OidcLogoutOperation = {
        ...completedBase,
        status: "completed",
        updatedAt: this.now().toISOString(),
      };
      await this.persistOperation(completed);
      const result: OidcLogoutResult = {
        operation: cloneOperation(completed),
        revokedTargets: targets,
        completed: true,
      };
      this.completedOperations.set(key, { result: cloneResult(result), fingerprint });
      this.removeActiveOperation(key, revoking.operationId);
      this.failedOperations.delete(key);
      return cloneResult(result);
    } catch (error) {
      const failed: OidcLogoutOperation = {
        ...revoking,
        status: "failed",
        errorCode: readErrorCode(error),
        updatedAt: this.now().toISOString(),
      };
      this.failedOperations.set(key, {
        operation: cloneOperation(failed),
        fingerprint,
        revokedTargets: new Set(revokedTargets),
      });
      this.completedOperations.delete(key);
      this.removeActiveOperation(key, revoking.operationId);
      try {
        await this.persistOperation(failed);
      } catch {
        return {
          operation: cloneOperation(failed),
          revokedTargets: targets.filter((target) => revokedTargets.has(target)),
          completed: false,
        };
      }
      return {
        operation: cloneOperation(failed),
        revokedTargets: targets.filter((target) => revokedTargets.has(target)),
        completed: false,
      };
    }
  }

  private async validateClientAndRedirect(clientId: string, redirectUri?: string): Promise<void> {
    if (this.clientResolver === undefined) throw new Error("OIDC client resolver is unavailable");
    const client = await this.clientResolver(clientId);
    if (client === undefined || client === null) throw new Error("OIDC client is unavailable");
    const metadata = readClientMetadata(client);
    const resolvedClientId = typeof metadata.clientId === "string"
      ? metadata.clientId
      : isRecord(client) && typeof client.clientId === "string"
        ? client.clientId
        : undefined;
    if (resolvedClientId !== undefined && resolvedClientId !== clientId) {
      throw new Error("OIDC client verification failed");
    }
    if (redirectUri === undefined) return;
    const checker = isRecord(client) && typeof client.postLogoutRedirectUriAllowed === "function"
      ? client.postLogoutRedirectUriAllowed
      : undefined;
    if (checker !== undefined) {
      try {
        const allowed = checker.call(client, redirectUri);
        if (allowed === true) return;
        if (allowed === false) throw new Error("OIDC redirect URI is not registered");
      } catch (error) {
        if (error instanceof Error && error.message === "OIDC redirect URI is not registered") throw error;
        throw new Error("OIDC redirect URI is not registered");
      }
    }
    const registered = readRegisteredRedirectUris(metadata);
    if (registered.length === 0 || !registered.some((value) => isExactOidcRedirectUri(value, redirectUri))) {
      throw new Error("OIDC redirect URI is not registered");
    }
  }

  private saveActiveOperation(operation: OidcLogoutOperation, fingerprint: string): void {
    this.operations.set(operation.idempotencyKey, cloneOperation(operation));
    this.fingerprints.set(operation.idempotencyKey, fingerprint);
    this.pruneConsistentState();
  }

  private pruneConsistentState(): void {
    const activeOperationIds = new Set<string>();
    this.operations.forEach((operation) => activeOperationIds.add(operation.operationId));
    const activeKeys = new Set<string>();
    this.operations.forEach((_operation, key) => activeKeys.add(key));
    this.operations.forEach((_operation, key) => {
      if (!this.fingerprints.has(key)) {
        this.operations.delete(key);
        activeKeys.delete(key);
      }
    });
    this.fingerprints.forEach((_fingerprint, key) => {
      if (!activeKeys.has(key)) this.fingerprints.delete(key);
    });
    activeOperationIds.clear();
    this.operations.forEach((operation) => activeOperationIds.add(operation.operationId));
    this.revokedByOperation.forEach((_targets, operationId) => {
      if (!activeOperationIds.has(operationId)) this.revokedByOperation.delete(operationId);
    });
  }

  private removeActiveOperation(idempotencyKey: string, operationId?: string): void {
    const operation = this.operations.get(idempotencyKey);
    this.operations.delete(idempotencyKey);
    this.fingerprints.delete(idempotencyKey);
    this.revokedByOperation.delete(operationId ?? operation?.operationId ?? "");
  }

  private async recordFailure(operation: OidcLogoutOperation, error: unknown): Promise<OidcLogoutResult> {
    const key = operation.idempotencyKey;
    const active = this.operations.get(key);
    const failed = this.failedOperations.get(key);
    const source = active ?? failed?.operation ?? cloneOperation(operation);
    const fingerprint = this.fingerprints.get(key) ?? failed?.fingerprint ?? operationFingerprint(source);
    const revokedTargets = new Set<OidcLogoutTarget>(
      this.revokedByOperation.get(source.operationId) ?? failed?.revokedTargets ?? [],
    );
    const failedOperation: OidcLogoutOperation = {
      ...source,
      status: "failed",
      errorCode: readErrorCode(error),
      updatedAt: this.now().toISOString(),
    };
    this.failedOperations.set(key, {
      operation: cloneOperation(failedOperation),
      fingerprint,
      revokedTargets,
    });
    this.completedOperations.delete(key);
    this.removeActiveOperation(key, source.operationId);
    try {
      await this.persistOperation(failedOperation);
    } catch {
      return {
        operation: cloneOperation(failedOperation),
        revokedTargets: [...revokedTargets],
        completed: false,
      };
    }
    return {
      operation: cloneOperation(failedOperation),
      revokedTargets: [...revokedTargets],
      completed: false,
    };
  }

  private async loadPersisted(idempotencyKey: string, requestFingerprint = ""): Promise<void> {
    if (this.persistence === undefined || this.operations.get(idempotencyKey) !== undefined) return;
    const loader = "load" in this.persistence && typeof this.persistence.load === "function"
      ? this.persistence.load
      : "get" in this.persistence && typeof this.persistence.get === "function"
        ? this.persistence.get
        : undefined;
    if (loader === undefined) return;
    const operation = await loader.call(this.persistence, idempotencyKey);
    if (operation === undefined || operation === null) return;
    validateOperation(operation);
    const fingerprint = requestFingerprint;
    if (operation.status === "completed") {
      this.completedOperations.set(idempotencyKey, {
        result: { operation: cloneOperation(operation), revokedTargets: [...operation.targets], completed: true },
        fingerprint,
      });
      this.failedOperations.delete(idempotencyKey);
    } else if (operation.status === "failed") {
      this.failedOperations.set(idempotencyKey, {
        operation: cloneOperation(operation),
        fingerprint,
        revokedTargets: new Set(),
      });
      this.completedOperations.delete(idempotencyKey);
    } else {
      this.completedOperations.delete(idempotencyKey);
      this.failedOperations.delete(idempotencyKey);
      this.saveActiveOperation(operation, fingerprint);
    }
  }

  private async persistOperation(operation: OidcLogoutOperation): Promise<void> {
    if (this.persistence === undefined) return;
    const saver = "save" in this.persistence && typeof this.persistence.save === "function"
      ? this.persistence.save
      : "set" in this.persistence && typeof this.persistence.set === "function"
        ? this.persistence.set
        : undefined;
    if (saver === undefined) throw new Error("OIDC logout persistence is unavailable");
    await saver.call(this.persistence, cloneOperation(operation));
  }
}

export function createBetterAuthOidcSessionRevocationPort(
  auth: GetbrickAuthLike,
  issuer: string,
): OidcSessionRevocationPort {
  if (typeof auth.handler !== "function") throw new Error("OIDC session revocation requires a Better Auth handler");
  const issuerUrl = new URL(issuer);
  const authBasePath = normalizePath(auth.options?.basePath ?? "/api/auth");
  const signOutUrl = new URL(authBasePath === "/" ? "/sign-out" : `${authBasePath}/sign-out`, issuerUrl.origin);
  return {
    async revoke(input): Promise<readonly OidcLogoutTarget[]> {
      const context = input.context;
      const headers = contextHeaders(context);
      headers.delete("content-length");
      headers.set("content-type", "application/json");
      headers.set("origin", issuerUrl.origin);
      const response = await auth.handler(new Request(signOutUrl, {
        method: "POST",
        headers,
        body: JSON.stringify({ disableRedirect: true }),
      }));
      if (!response || typeof response.status !== "number" || typeof response.headers?.get !== "function") {
        throw new Error("OIDC session revocation returned an invalid response");
      }
      if (!response.ok && response.status !== 401) {
        throw new Error("[getbrick-idaas] local OIDC logout failed");
      }
      const target = responseTarget(context?.response);
      if (target === undefined) return ["better_auth"];
      const cookies = readSetCookies(response);
      if (cookies.length === 0) return ["better_auth"];
      appendResponseCookies(target, cookies);
      return ["better_auth", "bff_cookie"];
    },
  };
}

export function createProviderOidcGrantRevocationPort(provider: unknown, baseAdapter?: unknown): OidcGrantRevocationPortLike {
  return {
    async revokeByGrantId(input: { grantId: string }): Promise<number> {
      if (!isObjectLike(provider) || !isObjectLike(provider.Grant)) {
        throw new Error("OIDC grant revocation is unavailable");
      }
      const externalAdapter = isObjectLike(baseAdapter) ? baseAdapter : undefined;
      if (typeof externalAdapter?.revokeByGrantId === "function") {
        return readCount(await externalAdapter.revokeByGrantId(input.grantId));
      }
      const adapter = providerGrantAdapter(provider);
      if (typeof adapter.revokeByGrantId === "function") {
        return readCount(await adapter.revokeByGrantId(input.grantId));
      }
      const grant = await findProviderGrant(provider, input.grantId);
      if (grant === undefined) return 0;
      if (typeof grant.destroy !== "function") throw new Error("OIDC grant revocation is unavailable");
      await grant.destroy();
      return 1;
    },
    async revokeByAccountId(input: { accountId: string }): Promise<number> {
      const externalAdapter = isObjectLike(baseAdapter) ? baseAdapter : undefined;
      if (typeof externalAdapter?.revokeByAccountId === "function") {
        return await externalAdapter.revokeByAccountId(input.accountId);
      }
      const adapter = providerGrantAdapter(provider);
      if (typeof adapter.revokeByAccountId === "function") {
        return await adapter.revokeByAccountId(input.accountId);
      }
      if (!isObjectLike(provider) || !isObjectLike(provider.Grant)) {
        throw new Error("OIDC grant revocation is unavailable");
      }
      return 0;
    },
  };
}

export function createOidcLogoutCoordinator(
  options: OidcLogoutCoordinatorOptions,
): OidcLogoutCoordinator {
  return new OidcLogoutCoordinator(options);
}

export function createOidcLogoutIdempotencyKey(input: {
  tenantId?: string;
  applicationId?: string;
  clientId: string;
  userId?: string;
  providerSessionId?: string;
  postLogoutRedirectUri?: string;
}): string {
  return `oidc-logout:${hashValue(JSON.stringify({
    tenantId: input.tenantId,
    applicationId: input.applicationId,
    clientId: input.clientId,
    userId: input.userId,
    providerSessionId: input.providerSessionId,
    postLogoutRedirectUri: input.postLogoutRedirectUri,
  }))}`;
}

function validateLogoutRequest(request: OidcLogoutRequest): void {
  if (!isRecord(request)) throw new Error("OIDC logout request is invalid");
  assertText(request.tenantId, "tenant", 200);
  assertText(request.clientId, "client", 512);
  assertText(request.idempotencyKey, "idempotency", 512);
  if (request.applicationId !== undefined) assertText(request.applicationId, "application", 512);
  if (request.userId !== undefined) assertText(request.userId, "user", 512);
  if (request.providerSessionId !== undefined) assertText(request.providerSessionId, "provider session", 512);
  if (request.postLogoutRedirectUri !== undefined) {
    assertText(request.postLogoutRedirectUri, "redirect", 2048);
    if (!isExactOidcRedirectUri(request.postLogoutRedirectUri, request.postLogoutRedirectUri)) {
      throw new Error("OIDC redirect URI is invalid");
    }
  }
  if (request.idTokenHint !== undefined) {
    if (typeof request.idTokenHint !== "string" || request.idTokenHint.length === 0 || request.idTokenHint.length > 16_384 || /[\u0000-\u001f\u007f\s]/u.test(request.idTokenHint)) {
      throw new Error("OIDC id_token_hint is invalid");
    }
  }
}

function validateOperation(operation: OidcLogoutOperation): void {
  if (!isRecord(operation) || operation.contractVersion !== 1) throw new Error("OIDC logout operation is invalid");
  assertText(operation.operationId, "operation", 512);
  assertText(operation.tenantId, "tenant", 200);
  assertText(operation.clientId, "client", 512);
  assertText(operation.idempotencyKey, "idempotency", 512);
  if (!Array.isArray(operation.targets) || operation.targets.length === 0) throw new Error("OIDC logout targets are invalid");
  if (!["pending", "revoking", "completed", "failed"].includes(operation.status)) throw new Error("OIDC logout status is invalid");
}

function normalizeTargets(targets: readonly OidcLogoutTarget[]): readonly OidcLogoutTarget[] {
  const allowed = new Set<OidcLogoutTarget>([
    "op_session",
    "offline_grant",
    "better_auth",
    "bff_cookie",
    "native_session",
    "webview_ticket",
  ]);
  const result: OidcLogoutTarget[] = [];
  const seen = new Set<OidcLogoutTarget>();
  for (const target of targets) {
    if (!allowed.has(target) || seen.has(target)) throw new Error("OIDC logout target is invalid");
    seen.add(target);
    result.push(target);
  }
  return result;
}

function normalizePath(value: string): string {
  const path = value.trim().replace(/\/+$/u, "");
  return path || "/";
}

function normalizeOptionalText(value: string | undefined): string | undefined {
  if (value === undefined) return undefined;
  assertText(value, "value", 512);
  return value;
}

function assertText(value: unknown, label: string, maxLength: number): asserts value is string {
  if (typeof value !== "string" || value.length === 0 || value.length > maxLength || /[\u0000-\u001f\u007f\s]/u.test(value)) {
    throw new Error(`OIDC logout ${label} is invalid`);
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function cloneOperation(operation: OidcLogoutOperation): OidcLogoutOperation {
  return {
    ...operation,
    targets: [...operation.targets],
  };
}

function cloneResult(result: OidcLogoutResult): OidcLogoutResult {
  return {
    operation: cloneOperation(result.operation),
    revokedTargets: [...result.revokedTargets],
    completed: result.completed,
  };
}

function operationFingerprint(operation: OidcLogoutOperation): string {
  return hashValue(JSON.stringify({
    tenantId: operation.tenantId,
    applicationId: operation.applicationId,
    clientId: operation.clientId,
    userId: operation.userId,
    providerSessionId: operation.providerSessionId,
    postLogoutRedirectUri: undefined,
  }));
}

function normalizePositiveInteger(value: number | undefined, fallback: number, label: string): number {
  if (value === undefined) return fallback;
  if (!Number.isSafeInteger(value) || value <= 0 || value > 1_000_000) {
    throw new Error(`OIDC logout ${label} is invalid`);
  }
  return value;
}

function requestFingerprint(request: OidcLogoutRequest): string {
  return hashValue(JSON.stringify({
    tenantId: request.tenantId,
    applicationId: request.applicationId,
    clientId: request.clientId,
    userId: request.userId,
    providerSessionId: request.providerSessionId,
    postLogoutRedirectUri: request.postLogoutRedirectUri,
  }));
}

function hashValue(value: string): string {
  return createHash("sha256").update(value).digest("base64url");
}

function readErrorCode(_error: unknown): "temporarily_unavailable" {
  return "temporarily_unavailable";
}

function assertPortResult(result: unknown): void {
  if (Array.isArray(result)) {
    for (const value of result) assertPortResult(value);
    return;
  }
  if (!isRecord(result)) return;
  if (result.completed === false) throw new Error("OIDC revocation port reported failure");
  if (isRecord(result.operation) && result.operation.status === "failed") {
    throw new Error("OIDC revocation port reported failure");
  }
}

function addTargets(
  targetSet: Set<OidcLogoutTarget>,
  requested: readonly OidcLogoutTarget[],
  result: unknown,
): void {
  if (result === undefined || result === null) {
    for (const target of requested) targetSet.add(target);
    return;
  }
  if (typeof result === "number") {
    if (Number.isInteger(result) && result >= 0) for (const target of requested) targetSet.add(target);
    return;
  }
  const values: unknown[] = Array.isArray(result)
    ? result.flatMap((value) => isRecord(value) && Array.isArray(value.revokedTargets) ? value.revokedTargets : [value])
    : isRecord(result) && Array.isArray(result.revokedTargets)
      ? result.revokedTargets
      : [];
  const allowed = new Set<OidcLogoutTarget>([
    "op_session",
    "offline_grant",
    "better_auth",
    "bff_cookie",
    "native_session",
    "webview_ticket",
  ]);
  for (const value of values) {
    if (typeof value === "string" && allowed.has(value as OidcLogoutTarget)) targetSet.add(value as OidcLogoutTarget);
  }
}

interface SessionPortInvocation {
  result: unknown;
  targets: readonly OidcLogoutTarget[];
}

async function invokeSessionPort(
  port: OidcSessionRevocationPortLike,
  input: OidcSessionRevocationInput,
  context: OidcLogoutRequestContext,
): Promise<SessionPortInvocation> {
  if (typeof port === "function") {
    return { result: await port(input, context), targets: input.targets };
  }
  const record = port as Record<string, unknown>;
  const revoke = record.revoke;
  if (typeof revoke === "function") {
    return { result: await revoke.call(port, input, context), targets: input.targets };
  }
  const revokeSession = record.revokeSession;
  if (typeof revokeSession === "function") {
    return { result: await revokeSession.call(port, input, context), targets: input.targets };
  }
  const revokeBySessionId = record.revokeBySessionId;
  const revokeByAccountId = record.revokeByAccountId;
  const results: unknown[] = [];
  const handled = new Set<OidcLogoutTarget>();
  if (typeof revokeBySessionId === "function") {
    results.push(await revokeBySessionId.call(port, {
      ...input,
      tenantId: input.operation.tenantId,
      sessionId: input.operation.providerSessionId,
      accountId: input.operation.userId,
    }, context));
    handled.add("op_session");
  }
  if (typeof revokeByAccountId === "function") {
    results.push(await revokeByAccountId.call(port, {
      ...input,
      tenantId: input.operation.tenantId,
      accountId: input.operation.userId,
    }, context));
    handled.add("better_auth");
  }
  const clearCookie = [record.clearCookie, record.clearCookies, record.revokeCookie]
    .find((value): value is AnyFunction => typeof value === "function");
  if (clearCookie !== undefined) {
    results.push(await clearCookie.call(port, input, context));
    handled.add("bff_cookie");
  }
  if (results.length === 0) throw new Error("OIDC session revocation port is invalid");
  return { result: results.length === 1 ? results[0] : results, targets: [...handled] };
}

async function invokeGrantPort(
  port: OidcGrantRevocationPortLike,
  operation: OidcLogoutOperation,
  targets: readonly OidcLogoutTarget[],
  context: OidcLogoutRequestContext,
  namespace: string,
): Promise<unknown> {
  if (typeof port === "function") return await port({ operation, targets, context });
  const record = port as Record<string, unknown>;
  const generic = record.revoke;
  if (typeof generic === "function") {
    return await generic.call(port, { operation, targets, context });
  }
  const grantIds = uniqueStrings(context.grantIds);
  const accountId = typeof operation.userId === "string" ? operation.userId : undefined;
  const revokeByGrantId = record.revokeByGrantId;
  const revokeByAccountId = record.revokeByAccountId;
  if (typeof revokeByGrantId !== "function" && typeof revokeByAccountId !== "function") {
    throw new Error("OIDC grant revocation port is invalid");
  }
  if (grantIds.length === 0 && accountId === undefined) {
    throw new Error("OIDC grant revocation input is unavailable");
  }
  let count = 0;
  const structuredResults: unknown[] = [];
  if (typeof revokeByGrantId === "function") {
    for (const grantId of grantIds) {
      const result = await revokeByGrantId.call(port, {
        tenantId: operation.tenantId,
        namespace: readNamespace(port, namespace),
        grantId,
      });
      if (typeof result === "number" || result === undefined || result === null) count += readCount(result);
      else structuredResults.push(result);
    }
  }
  if (typeof revokeByAccountId === "function" && accountId !== undefined) {
    const result = await revokeByAccountId.call(port, {
      tenantId: operation.tenantId,
      namespace: readNamespace(port, namespace),
      accountId,
    });
    if (typeof result === "number" || result === undefined || result === null) count += readCount(result);
    else structuredResults.push(result);
  }
  if (structuredResults.length === 1) return structuredResults[0];
  if (structuredResults.length > 1) return structuredResults;
  return count;
}

function readNamespace(port: unknown, fallback: string): string {
  if (isRecord(port) && typeof port.namespace === "string" && port.namespace.length > 0) return port.namespace;
  return fallback;
}

function readCount(value: unknown): number {
  if (typeof value === "number" && Number.isInteger(value) && value >= 0) return value;
  if (value === undefined || value === null) return 1;
  return 0;
}

function uniqueStrings(values: readonly string[] | undefined): string[] {
  if (!Array.isArray(values)) return [];
  return [...new Set(values.filter((value): value is string => typeof value === "string" && value.length > 0))];
}

function readClientMetadata(client: unknown): Record<string, unknown> {
  if (!isRecord(client)) return {};
  const metadata = typeof client.metadata === "function" ? client.metadata() : client.metadata ?? client;
  return isRecord(metadata) ? metadata : {};
}

function readRegisteredRedirectUris(metadata: Record<string, unknown>): string[] {
  const values = metadata.post_logout_redirect_uris ?? metadata.postLogoutRedirectUris;
  return Array.isArray(values)
    ? values.filter((value): value is string => typeof value === "string")
    : [];
}

function contextHeaders(context: OidcLogoutRequestContext | undefined): Headers {
  const source = context?.requestHeaders ?? context?.headers;
  const headers = new Headers();
  if (source instanceof Headers) {
    source.forEach((value, key) => headers.set(key, value));
    return headers;
  }
  if (isRecord(source)) {
    for (const [key, value] of Object.entries(source)) {
      if (typeof value === "string") headers.set(key, value);
      else if (Array.isArray(value)) {
        for (const item of value) if (typeof item === "string") headers.append(key, item);
      }
    }
  }
  return headers;
}

function responseTarget(value: unknown): any {
  if (!isRecord(value)) return undefined;
  if (isRecord(value.res)) return value.res;
  if (isRecord(value.response) && isRecord(value.response.res)) return value.response.res;
  if (typeof value.append === "function" || typeof value.setHeader === "function") return value;
  return undefined;
}

function readSetCookies(response: Response): string[] {
  const headers = response.headers as Headers & { getSetCookie?: () => string[] };
  if (typeof headers.getSetCookie === "function") {
    const values = headers.getSetCookie();
    if (values.length > 0) return values;
  }
  const value = headers.get("set-cookie");
  return value === null ? [] : [value];
}

function appendResponseCookies(target: any, cookies: readonly string[]): void {
  for (const cookie of cookies) {
    if (typeof target.append === "function") {
      target.append("Set-Cookie", cookie);
      continue;
    }
    if (typeof target.setHeader !== "function") throw new Error("OIDC logout response cannot accept cookies");
    const current = typeof target.getHeader === "function" ? target.getHeader("Set-Cookie") : undefined;
    const values = Array.isArray(current) ? current : current ? [String(current)] : [];
    target.setHeader("Set-Cookie", [...values, cookie]);
  }
}

function providerGrantAdapter(provider: unknown): Record<string, unknown> {
  if (!isObjectLike(provider)) return {};
  const grant = provider.Grant;
  if (!isObjectLike(grant)) return {};
  const adapter = grant.adapter;
  return isObjectLike(adapter) ? adapter : {};
}

async function findProviderGrant(provider: unknown, grantId: string): Promise<any> {
  if (!isObjectLike(provider) || !isObjectLike(provider.Grant) || typeof provider.Grant.find !== "function") return undefined;
  return await provider.Grant.find(grantId);
}

function isObjectLike(value: unknown): value is Record<string, unknown> {
  return (typeof value === "object" && value !== null) || typeof value === "function";
}
