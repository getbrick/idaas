import { assertApiBaseUrl } from "../config";
import { AuthError } from "../auth/errors";
import { SessionCoordinator, type SessionFence } from "../auth/session-coordinator";
import { assertNoCredentialFields, OpaqueSessionStore, type OpaqueSession } from "../auth/session";
import { getUniRuntime, type UniRequestMethod, type UniRequestOptions, type UniResponse, type UniRuntime } from "../types/runtime";

export class ApiError extends AuthError {
  constructor(code: string, message: string, status: number, retryable = false) {
    super(code, message, status, retryable);
    this.name = "ApiError";
  }
}

export interface RequestInput {
  path: string;
  method?: UniRequestMethod;
  data?: unknown;
  header?: Record<string, string>;
  auth?: boolean;
  refreshOnUnauthorized?: boolean;
  withCredentials?: boolean;
  timeout?: number;
}

export interface RequestClientOptions {
  baseUrl: string;
  sessions?: OpaqueSessionStore;
  coordinator?: SessionCoordinator;
  runtime?: UniRuntime;
  timeoutMs?: number;
  onSessionInvalid?: () => void;
}

type RefreshHandler = () => Promise<OpaqueSession | null | void>;

interface RefreshState {
  generation: number;
  promise: Promise<void>;
}

export class ApiRequestClient {
  private readonly baseUrl: string;
  private readonly sessions: OpaqueSessionStore;
  private readonly coordinator: SessionCoordinator | undefined;
  private readonly runtime: UniRuntime;
  private readonly timeoutMs: number;
  private readonly onSessionInvalid: () => void;
  private refreshHandler: RefreshHandler | undefined;
  private refreshState: RefreshState | undefined;

  constructor(options: RequestClientOptions) {
    this.baseUrl = assertApiBaseUrl(options.baseUrl);
    this.sessions = options.sessions ?? new OpaqueSessionStore();
    this.coordinator = options.coordinator;
    this.runtime = options.runtime ?? getUniRuntime();
    this.timeoutMs = normalizeTimeout(options.timeoutMs);
    this.onSessionInvalid = options.onSessionInvalid ?? (() => {
      if (this.coordinator === undefined) this.sessions.clear();
    });
  }

  setRefreshHandler(handler: RefreshHandler): void {
    this.refreshHandler = handler;
  }

  async request<T>(input: RequestInput): Promise<T> {
    return this.execute<T>(input, true);
  }

  private async execute<T>(input: RequestInput, allowRefresh: boolean): Promise<T> {
    const session = input.auth === false ? null : this.sessions.load();
    const fence = this.coordinator?.snapshot();
    const response = await this.invoke({ ...input, session });
    if (response.statusCode === 401 && session !== null && allowRefresh && input.refreshOnUnauthorized !== false && this.refreshHandler !== undefined) {
      try {
        await this.refreshSession(fence);
      } catch (error) {
        this.invalidateSession(fence);
        throw normalizeApiError(error);
      }
      return this.execute<T>(input, false);
    }
    if (response.statusCode < 200 || response.statusCode >= 300) {
      if (response.statusCode === 401) this.invalidateSession(fence);
      throw createApiError(response);
    }
    const payload = parseResponseBody(response.data);
    try {
      assertNoCredentialFields(payload);
    } catch {
      throw new ApiError("invalid_response", "Server response contained a forbidden credential", response.statusCode, false);
    }
    return extractPayload(payload) as T;
  }

  private async refreshSession(fence: SessionFence | undefined): Promise<void> {
    const generation = fence?.generation ?? this.coordinator?.generation;
    const stateGeneration = generation ?? -1;
    if (this.refreshState !== undefined && this.refreshState.generation === stateGeneration) return this.refreshState.promise;
    const handler = this.refreshHandler;
    if (handler === undefined) throw new ApiError("unauthorized", "Authentication is required", 401, false);
    let promise: Promise<void>;
    promise = Promise.resolve()
      .then(handler)
      .then((session) => {
        if (session === undefined || session === null) return;
        if (this.coordinator === undefined) {
          this.sessions.save(session);
          return;
        }
        if (fence !== undefined && this.coordinator.isCurrent(fence)) this.coordinator.save(session, fence);
      })
      .finally(() => {
        if (this.refreshState?.promise === promise) this.refreshState = undefined;
      });
    this.refreshState = { generation: stateGeneration, promise };
    return promise;
  }

  private invalidateSession(fence: SessionFence | undefined): void {
    if (this.coordinator !== undefined) {
      if (fence === undefined || this.coordinator.clearIfCurrent(fence)) this.onSessionInvalid();
      return;
    }
    this.sessions.clear();
    this.onSessionInvalid();
  }

  private async invoke(input: RequestInput & { session: OpaqueSession | null }): Promise<UniResponse> {
    const header = createHeaders(input.header, input.data, input.session, this.baseUrl);
    const requestOptions: UniRequestOptions = {
      url: resolveUrl(this.baseUrl, input.path),
      method: input.method ?? "GET",
      ...(input.data === undefined ? {} : { data: input.data }),
      header,
      withCredentials: input.withCredentials ?? true,
      timeout: input.timeout ?? this.timeoutMs,
    };
    return new Promise<UniResponse>((resolve, reject) => {
      requestOptions.success = resolve;
      requestOptions.fail = () => reject(new ApiError("network_error", "Network request failed", 0, true));
      try {
        const result = this.runtime.request(requestOptions);
        if (isPromiseLike(result)) {
          result.catch(() => reject(new ApiError("network_error", "Network request failed", 0, true)));
        }
      } catch {
        reject(new ApiError("network_error", "Network request failed", 0, true));
      }
    });
  }
}

function createHeaders(
  supplied: Record<string, string> | undefined,
  data: unknown,
  session: OpaqueSession | null,
  baseUrl: string,
): Record<string, string> {
  const headers: Record<string, string> = { accept: "application/json" };
  if (data !== undefined) headers["content-type"] = "application/json";
  for (const [key, value] of Object.entries(supplied ?? {})) {
    if (isForbiddenHeader(key)) continue;
    assertHeaderValue(value);
    headers[key.toLowerCase()] = value;
  }
  if (session !== null) headers["x-client-session"] = session.sessionReference;
  assertApiBaseUrl(baseUrl);
  return headers;
}

function resolveUrl(baseUrl: string, path: string): string {
  if (typeof path !== "string" || path.length === 0 || /[\u0000-\u001f\u007f\s]/u.test(path)) throw new ApiError("invalid_request", "Request URL is invalid", 0, false);
  const base = new URL(baseUrl);
  let resolved: URL;
  try {
    resolved = new URL(path, `${base.origin}${base.pathname.replace(/\/$/u, "")}/`);
  } catch {
    throw new ApiError("invalid_request", "Request URL is invalid", 0, false);
  }
  if (resolved.origin !== base.origin || (resolved.protocol !== "http:" && resolved.protocol !== "https:")) throw new ApiError("invalid_request", "Request URL is invalid", 0, false);
  return resolved.toString();
}

function parseResponseBody(value: unknown): unknown {
  if (typeof value !== "string") return value;
  if (value.trim().length === 0) return undefined;
  try {
    return JSON.parse(value) as unknown;
  } catch {
    return value;
  }
}

function extractPayload(value: unknown): unknown {
  if (!isRecord(value)) return value;
  const keys = Object.keys(value);
  const hasEnvelope = Object.prototype.hasOwnProperty.call(value, "code") || Object.prototype.hasOwnProperty.call(value, "success") || Object.prototype.hasOwnProperty.call(value, "error");
  const onlyData = keys.length === 1 && keys[0] === "data";
  if ((hasEnvelope || onlyData) && Object.prototype.hasOwnProperty.call(value, "data")) return value.data;
  return value;
}

function createApiError(response: UniResponse): ApiError {
  const body = parseResponseBody(response.data);
  const error = isRecord(body) && isRecord(body.error) ? body.error : undefined;
  const candidate = error?.code ?? (isRecord(body) ? body.code : undefined);
  const code = typeof candidate === "string" && /^[A-Za-z][A-Za-z0-9_.-]{0,127}$/u.test(candidate) ? candidate : response.statusCode === 401 ? "unauthorized" : `http_${response.statusCode}`;
  const status = readStatus(error?.status) ?? readStatus(isRecord(body) ? body.status : undefined) ?? response.statusCode;
  const bodyRetryable = isRecord(body) && typeof body.retryable === "boolean" ? body.retryable : undefined;
  const explicitRetryable = typeof error?.retryable === "boolean" ? error.retryable : bodyRetryable;
  const retryable = explicitRetryable ?? (status === 408 || status === 425 || status === 429 || status >= 500);
  const message = status === 401 ? "Authentication is required" : status === 403 ? "Access is denied" : "Request failed";
  return new ApiError(code, message, status, retryable);
}

function normalizeApiError(error: unknown): AuthError {
  if (error instanceof AuthError) return error;
  return new ApiError("network_error", "Network request failed", 0, true);
}

function isForbiddenHeader(key: string): boolean {
  const normalized = key.toLowerCase().replace(/[^a-z0-9]/gu, "");
  return normalized === "authorization" || normalized === "cookie" || normalized === "setcookie" || normalized.includes("token") || normalized.includes("secret");
}

function assertHeaderValue(value: string): void {
  if (typeof value !== "string" || value.length > 2048 || /[\r\n\u0000]/u.test(value)) throw new ApiError("invalid_request", "Request header is invalid", 0, false);
}

function normalizeTimeout(value: number | undefined): number {
  return value !== undefined && Number.isSafeInteger(value) && value >= 1000 && value <= 120000 ? value : 15000;
}

function readStatus(value: unknown): number | undefined {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 100 && value <= 599 ? value : undefined;
}

function isPromiseLike(value: unknown): value is { catch: (onRejected: (reason: unknown) => unknown) => unknown } {
  return isRecord(value) && typeof value.catch === "function";
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
