import { createAuthClient } from "better-auth/react";
import {
  ERROR_CODES,
  type ApplicationClientRotateSecretRequest,
  type ApplicationClientSummary,
  type ApplicationCreateRequest,
  type ApplicationListQuery,
  type ApplicationPage,
  type ApplicationPurgeJob,
  type ApplicationPurgeRequest,
  type ApplicationSummary,
  type ApplicationUpdateRequest,
  type ErrorEnvelope,
  type ErrorResponse,
} from "@getbrick/idaas-contracts";

export type GetbrickClient = ReturnType<typeof createAuthClient>;

export function createGetbrickClient(baseURL?: string): GetbrickClient {
  return createAuthClient({ baseURL, fetchOptions: { throw: false } });
}

export const getbrickContextKey = "getbrick:auth-client";

export interface GetbrickApiClientOptions {
  baseURL: string;
  fetch?: typeof fetch;
  headers?: Readonly<Record<string, string>>;
}

export interface GetbrickApiRequestOptions extends Omit<RequestInit, "body" | "headers"> {
  body?: unknown;
  method?: RequestInit["method"];
  headers?: Readonly<Record<string, string>>;
  ifMatch?: string;
}

export class GetbrickApiError extends Error {
  readonly status: number;
  readonly code: string;
  readonly requestId?: string;
  readonly details?: unknown;
  readonly envelope?: ErrorResponse;

  constructor(status: number, envelope?: ErrorResponse) {
    const message = safeApiErrorMessage(envelope);
    super(message);
    this.name = "GetbrickApiError";
    this.status = status;
    this.code = envelope?.error.code ?? "INTERNAL_ERROR";
    this.requestId = envelope?.requestId;
    this.details = envelope?.error.details;
    this.envelope = envelope;
  }
}

export interface GetbrickApiClient {
  request<T>(path: string, options?: GetbrickApiRequestOptions): Promise<T>;
  listApplications(query?: ApplicationListQuery): Promise<ApplicationPage<ApplicationSummary>>;
  getApplication(id: string): Promise<ApplicationSummary>;
  createApplication(body: ApplicationCreateRequest): Promise<ApplicationSummary>;
  updateApplication(id: string, body: ApplicationUpdateRequest, ifMatch?: string): Promise<ApplicationSummary>;
  archiveApplication(id: string, ifMatch?: string): Promise<ApplicationSummary>;
  restoreApplication(id: string, ifMatch?: string): Promise<ApplicationSummary>;
  purgeApplication(id: string, body?: ApplicationPurgeRequest, ifMatch?: string): Promise<ApplicationPurgeJob>;
  rotateClientSecret(applicationId: string, clientId: string, body: ApplicationClientRotateSecretRequest, ifMatch?: string): Promise<ApplicationClientSummary>;
  revokeClientSecret(applicationId: string, clientId: string, ifMatch?: string): Promise<ApplicationClientSummary>;
}

export function parseGetbrickErrorEnvelope(value: unknown, status = 500): GetbrickApiError {
  if (!isRecord(value) || !isRecord(value.error)) return new GetbrickApiError(status);
  const error = value.error;
  const code = typeof error.code === "string" && isStableErrorCode(error.code) ? error.code : undefined;
  const message = typeof error.message === "string" ? error.message : undefined;
  if (!code || !message) return new GetbrickApiError(status);
  const requestId = safeRequestId(value.requestId);
  const safeMessage = safeApiErrorMessage({ error: { code: code as ErrorEnvelope["code"], message } });
  const safeDetails = sanitizeErrorDetails(error.details);
  const envelope: ErrorResponse = {
    error: {
      code: code as ErrorEnvelope["code"],
      message: safeMessage,
      ...(safeDetails === undefined ? {} : { details: safeDetails }),
    },
    ...(requestId === undefined ? {} : { requestId }),
  };
  return new GetbrickApiError(status, envelope);
}

export function createGetbrickApiClient(options: GetbrickApiClientOptions): GetbrickApiClient {
  const baseURL = normalizeBaseURL(options.baseURL);
  const request = async <T>(path: string, requestOptions: GetbrickApiRequestOptions = {}): Promise<T> => {
    const headers: Record<string, string> = {
      accept: "application/json",
      ...(requestOptions.body === undefined ? {} : { "content-type": "application/json" }),
      ...lowercaseHeaders(options.headers),
      ...lowercaseHeaders(requestOptions.headers),
    };
    if (requestOptions.ifMatch !== undefined) headers["if-match"] = formatIfMatch(requestOptions.ifMatch);
    const { body, headers: _headers, ifMatch: _ifMatch, method, ...rest } = requestOptions;
    let response: Response;
    try {
      response = await (options.fetch ?? fetch)(`${baseURL}${normalizePath(path)}`, {
        ...rest,
        method: method ?? "GET",
        headers,
        ...(body === undefined ? {} : { body: JSON.stringify(body) }),
      });
    } catch {
      throw new GetbrickApiError(0);
    }
    const value = await readResponseBody(response);
    if (!response.ok) throw parseGetbrickErrorEnvelope(value, response.status);
    return value as T;
  };
  return {
    request,
    listApplications: (query) => request(`/applications${queryString(query)}`),
    getApplication: (id) => request(`/applications/${encodeURIComponent(id)}`),
    createApplication: (body) => request("/applications", { method: "POST", body }),
    updateApplication: (id, body, ifMatch) => request(`/applications/${encodeURIComponent(id)}`, { method: "PATCH", body, ifMatch }),
    archiveApplication: (id, ifMatch) => request(`/applications/${encodeURIComponent(id)}/archive`, { method: "POST", body: {}, ifMatch }),
    restoreApplication: (id, ifMatch) => request(`/applications/${encodeURIComponent(id)}/restore`, { method: "POST", body: {}, ifMatch }),
    purgeApplication: (id, body = {}, ifMatch) => request(`/applications/${encodeURIComponent(id)}/purge`, { method: "POST", body, ifMatch }),
    rotateClientSecret: (applicationId, clientId, body, ifMatch) => request(`/applications/${encodeURIComponent(applicationId)}/clients/${encodeURIComponent(clientId)}/rotate-secret`, { method: "POST", body, ifMatch }),
    revokeClientSecret: (applicationId, clientId, ifMatch) => request(`/applications/${encodeURIComponent(applicationId)}/clients/${encodeURIComponent(clientId)}/revoke-secret`, { method: "POST", body: {}, ifMatch }),
  };
}

export const createAdminClient = createGetbrickApiClient;
export const createControlPlaneClient = createGetbrickApiClient;

async function readResponseBody(response: Response): Promise<unknown> {
  if (response.status === 204) return undefined;
  const contentType = response.headers.get("content-type") ?? "";
  try {
    const text = await response.text();
    if (text.trim().length === 0) return undefined;
    if (!contentType.toLowerCase().includes("json")) {
      try {
        return JSON.parse(text) as unknown;
      } catch {
        return undefined;
      }
    }
    return JSON.parse(text) as unknown;
  } catch {
    return undefined;
  }
}

function isStableErrorCode(value: string): value is ErrorEnvelope["code"] {
  return Object.values(ERROR_CODES).includes(value as ErrorEnvelope["code"]);
}

function formatIfMatch(value: string): string {
  const normalized = value.trim();
  if (
    normalized.length === 0 ||
    normalized.length > 512 ||
    normalized.includes(",") ||
    normalized === "*" ||
    /[\u0000-\u001f\u007f]/u.test(normalized) ||
    /(?:secret|token|password|private[-_]?key|credential|authorization|cookie|vault:\/\/)/iu.test(normalized)
  ) throw new TypeError("Invalid If-Match value");
  if (normalized.startsWith("W/") || normalized.startsWith('"')) return normalized;
  return `"${normalized}"`;
}

function safeApiErrorMessage(envelope: ErrorResponse | undefined): string {
  const message = envelope?.error.message?.trim();
  if (
    message === undefined ||
    message.length === 0 ||
    message.length > 512 ||
    /[\u0000-\u001f\u007f]/u.test(message) ||
    /(?:secret|token|password|private[-_]?key|credential|authorization|cookie|vault:\/\/)/iu.test(message)
  ) return "Request failed";
  return message;
}

function sanitizeErrorDetails(value: unknown, depth = 0): unknown {
  if (depth > 3) return undefined;
  if (typeof value === "string") {
    return /(?:secret|token|password|private[-_]?key|credential|authorization|cookie|vault:\/\/)/iu.test(value)
      ? undefined
      : value.slice(0, 256);
  }
  if (typeof value === "number" || typeof value === "boolean") return value;
  if (value === null) return null;
  if (Array.isArray(value)) return value.slice(0, 20).map((item) => sanitizeErrorDetails(item, depth + 1)).filter((item) => item !== undefined);
  if (!isRecord(value)) return undefined;
  const output: Record<string, unknown> = {};
  for (const [key, nested] of Object.entries(value)) {
    if (/^(?:__proto__|prototype|constructor)$/u.test(key)) continue;
    if (/(?:secret|token|password|private[-_]?key|credential|authorization|cookie)/iu.test(key)) continue;
    const safe = sanitizeErrorDetails(nested, depth + 1);
    if (safe !== undefined) output[key] = safe;
  }
  return output;
}

function safeRequestId(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  const normalized = value.trim();
  return normalized.length > 0 && normalized.length <= 128 && !/[\u0000-\u001f\u007f]/u.test(normalized) && !/(?:secret|token|password|private[-_]?key|credential|authorization|cookie|vault:\/\/)/iu.test(normalized)
    ? normalized
    : undefined;
}

function normalizeBaseURL(value: string): string {
  const normalized = value.trim().replace(/\/+$/u, "");
  let parsed: URL;
  try {
    parsed = new URL(normalized);
  } catch {
    throw new TypeError("Invalid API base URL");
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") throw new TypeError("Invalid API base URL");
  if (parsed.username || parsed.password || parsed.search || parsed.hash) throw new TypeError("Invalid API base URL");
  return normalized;
}

function normalizePath(value: string): string {
  if (!value.startsWith("/") || /[\u0000-\u001f\u007f]/u.test(value)) throw new TypeError("Invalid API path");
  return value;
}

function queryString(query: ApplicationListQuery | undefined): string {
  if (!query) return "";
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(query)) {
    if (value === undefined || value === null || value === "") continue;
    params.set(key, String(value));
  }
  const value = params.toString();
  return value ? `?${value}` : "";
}

function lowercaseHeaders(value: Readonly<Record<string, string>> | undefined): Record<string, string> {
  const output: Record<string, string> = {};
  for (const [key, item] of Object.entries(value ?? {})) {
    const normalized = key.trim().toLowerCase();
    if (normalized && !/[\u0000-\u001f\u007f]/u.test(normalized) && !/[\r\n]/u.test(item)) output[normalized] = item;
  }
  return output;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
