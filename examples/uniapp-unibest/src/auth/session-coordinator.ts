import { AuthError } from "./errors";
import { OpaqueSessionStore, type OpaqueSession } from "./session";

export interface SessionFence {
  readonly generation: number;
  readonly sessionReference: string | null;
}

export interface SessionRefreshContext extends SessionFence {}

export interface SessionCoordinatorOptions {
  sessions?: OpaqueSessionStore;
  generation?: number;
  now?: () => number;
  refresh?: SessionRefreshOperation;
  refreshCookie?: SessionCookieRefreshOperation;
  logout?: SessionLogoutOperation;
}

export type SessionRefreshOperation = (context: SessionRefreshContext) => Promise<OpaqueSession>;
export type SessionCookieRefreshOperation = () => Promise<void>;
export type SessionLogoutOperation = (sessionReference: string | null) => Promise<void>;

interface RefreshState {
  generation: number;
  promise: Promise<OpaqueSession>;
}

interface CookieRefreshState {
  generation: number;
  promise: Promise<void>;
}

export class SessionCoordinator {
  private readonly sessions: OpaqueSessionStore;
  private readonly refreshOperation: SessionRefreshOperation | undefined;
  private readonly cookieRefreshOperation: SessionCookieRefreshOperation | undefined;
  private readonly logoutOperation: SessionLogoutOperation | undefined;
  private generationValue: number;
  private refreshState: RefreshState | undefined;
  private cookieRefreshState: CookieRefreshState | undefined;

  constructor(options: SessionCoordinatorOptions = {}) {
    this.sessions = options.sessions ?? new OpaqueSessionStore({ now: options.now });
    this.refreshOperation = options.refresh;
    this.cookieRefreshOperation = options.refreshCookie;
    this.logoutOperation = options.logout;
    this.generationValue = normalizeGeneration(options.generation);
  }

  get generation(): number {
    return this.generationValue;
  }

  getGeneration(): number {
    return this.generationValue;
  }

  get sessionStore(): OpaqueSessionStore {
    return this.sessions;
  }

  snapshot(): SessionFence {
    const session = this.sessions.load();
    return { generation: this.generationValue, sessionReference: session?.sessionReference ?? null };
  }

  current(): OpaqueSession | null {
    return this.sessions.load();
  }

  isCurrent(fence: SessionFence): boolean {
    const session = this.sessions.load();
    return this.generationValue === fence.generation && (session?.sessionReference ?? null) === fence.sessionReference;
  }

  save(value: OpaqueSession, expected?: SessionFence): OpaqueSession {
    if (expected !== undefined && !this.isCurrent(expected)) throw staleFenceError();
    const session = this.sessions.save(value);
    this.generationValue = normalizeGeneration(this.generationValue + 1);
    return session;
  }

  accept(value: OpaqueSession, expected?: SessionFence): OpaqueSession {
    return this.save(value, expected);
  }

  clear(expected?: SessionFence): boolean {
    if (expected !== undefined && !this.isCurrent(expected)) return false;
    this.sessions.clear();
    this.generationValue = normalizeGeneration(this.generationValue + 1);
    return true;
  }

  clearIfCurrent(expected: SessionFence): boolean {
    return this.clear(expected);
  }

  invalidate(): number {
    this.clear();
    return this.generationValue;
  }

  async refresh(operation: SessionRefreshOperation = this.refreshOperation as SessionRefreshOperation): Promise<OpaqueSession> {
    if (typeof operation !== "function") throw new AuthError("session_missing", "Session refresh is unavailable", 500, false);
    const fence = this.snapshot();
    if (fence.sessionReference === null) throw new AuthError("session_missing", "Client session is unavailable");
    if (this.refreshState?.generation === fence.generation) return this.refreshState.promise;
    let promise: Promise<OpaqueSession>;
    promise = Promise.resolve()
      .then(() => operation({ ...fence }))
      .then((session) => {
        if (!this.isCurrent(fence)) throw staleFenceError();
        return this.save(session, fence);
      })
      .finally(() => {
        if (this.refreshState?.promise === promise) this.refreshState = undefined;
      });
    this.refreshState = { generation: fence.generation, promise };
    return promise;
  }

  async refreshCookie(operation: SessionCookieRefreshOperation = this.cookieRefreshOperation as SessionCookieRefreshOperation): Promise<void> {
    if (typeof operation !== "function") throw new AuthError("session_missing", "Session refresh is unavailable", 500, false);
    const fence = this.snapshot();
    if (this.cookieRefreshState?.generation === fence.generation) return this.cookieRefreshState.promise;
    let promise: Promise<void>;
    promise = Promise.resolve()
      .then(operation)
      .then(() => {
        if (!this.isCurrent(fence)) throw staleFenceError();
      })
      .finally(() => {
        if (this.cookieRefreshState?.promise === promise) this.cookieRefreshState = undefined;
      });
    this.cookieRefreshState = { generation: fence.generation, promise };
    return promise;
  }

  async logout(operation: SessionLogoutOperation | undefined = this.logoutOperation): Promise<SessionFence> {
    const fence = this.snapshot();
    this.clear();
    if (operation !== undefined) await operation(fence.sessionReference);
    return fence;
  }

  runRefresh(operation?: SessionRefreshOperation): Promise<OpaqueSession> {
    return this.refresh(operation);
  }

  runCookieRefresh(operation?: SessionCookieRefreshOperation): Promise<void> {
    return this.refreshCookie(operation);
  }

  runLogout(operation?: SessionLogoutOperation): Promise<SessionFence> {
    return this.logout(operation);
  }
}

function staleFenceError(): AuthError {
  return new AuthError("session_generation_mismatch", "Client session changed while the operation was in progress", 409, false);
}

function normalizeGeneration(value: number | undefined): number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0 ? value : 0;
}
