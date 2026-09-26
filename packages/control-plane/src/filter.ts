import {
  ArgumentsHost,
  CallHandler,
  Catch,
  HttpException,
  type ExceptionFilter,
  type ExecutionContext,
  Injectable,
  type NestInterceptor,
} from "@nestjs/common";
import { map, type Observable } from "rxjs";
import {
  CONTROL_PLANE_ERROR_CODES,
  ControlPlaneError,
  isControlPlaneErrorCode,
  type ControlPlaneErrorCode,
  type ControlPlaneErrorResponse,
} from "./errors.js";

interface HttpResponse {
  status(code: number): HttpResponse;
  json(body: ControlPlaneErrorResponse): void;
  setHeader?(name: string, value: string): void;
}

interface HttpRequest {
  headers?: Record<string, unknown>;
  id?: unknown;
}

@Injectable()
export class ApplicationEtagInterceptor implements NestInterceptor {
  intercept(context: ExecutionContext, next: CallHandler): Observable<unknown> {
    const response = context.switchToHttp().getResponse<Pick<HttpResponse, "setHeader">>();
    return next.handle().pipe(map((value) => {
      const etag = formatResponseEtag(value);
      if (etag !== undefined) response.setHeader?.("ETag", etag);
      return value;
    }));
  }
}

@Catch()
export class ControlPlaneExceptionFilter implements ExceptionFilter {
  catch(exception: unknown, host: ArgumentsHost): void {
    const http = host.switchToHttp();
    const response = http.getResponse<HttpResponse>();
    const request = http.getRequest<HttpRequest>();
    const normalized = normalizeException(exception);
    const requestId = requestIdFromRequest(request);
    const body: ControlPlaneErrorResponse = {
      error: {
        code: normalized.code,
        message: normalized.message,
        ...(normalized.details ? { details: normalized.details } : {}),
      },
      ...(requestId ? { requestId } : {}),
    };
    if (requestId) response.setHeader?.("x-request-id", requestId);
    response.status(normalized.statusCode).json(body);
  }
}

function normalizeException(exception: unknown): {
  statusCode: number;
  code: ControlPlaneErrorCode;
  message: string;
  details?: Record<string, unknown>;
} {
  if (exception instanceof ControlPlaneError) {
    return {
      statusCode: exception.statusCode,
      code: exception.code,
      message: safeErrorMessage(exception.message),
      ...(exception.details ? { details: exception.details } : {}),
    };
  }
  if (exception instanceof HttpException) {
    const statusCode = exception.getStatus();
    const response = exception.getResponse();
    if (isRecord(response)) {
      const code = response.code;
      const message = response.message;
      if (isControlPlaneErrorCode(code) && typeof message === "string" && message.trim().length > 0) {
        const safeMessage = safeErrorMessage(message);
        const details = isRecord(response.details)
          ? new ControlPlaneError(code, safeMessage, { statusCode, details: response.details }).details
          : undefined;
        return {
          statusCode,
          code,
          message: safeMessage,
          ...(details === undefined ? {} : { details }),
        };
      }
    }
    return {
      statusCode,
      code: codeForStatus(statusCode),
      message: messageForStatus(statusCode),
    };
  }
  return {
    statusCode: 500,
    code: CONTROL_PLANE_ERROR_CODES.INTERNAL_ERROR,
    message: "Internal server error",
  };
}

function codeForStatus(statusCode: number): ControlPlaneErrorCode {
  if (statusCode === 400) return CONTROL_PLANE_ERROR_CODES.INVALID_REQUEST;
  if (statusCode === 401) return CONTROL_PLANE_ERROR_CODES.UNAUTHENTICATED;
  if (statusCode === 403) return CONTROL_PLANE_ERROR_CODES.FORBIDDEN;
  if (statusCode === 404) return CONTROL_PLANE_ERROR_CODES.NOT_FOUND;
  if (statusCode === 409) return CONTROL_PLANE_ERROR_CODES.CONFLICT;
  if (statusCode === 429) return CONTROL_PLANE_ERROR_CODES.RATE_LIMITED;
  if (statusCode === 503) return CONTROL_PLANE_ERROR_CODES.SERVICE_UNAVAILABLE;
  if (statusCode >= 500) return CONTROL_PLANE_ERROR_CODES.INTERNAL_ERROR;
  return CONTROL_PLANE_ERROR_CODES.BAD_REQUEST;
}

function messageForStatus(statusCode: number): string {
  if (statusCode === 400) return "Invalid request";
  if (statusCode === 401) return "Authentication required";
  if (statusCode === 403) return "Insufficient permission";
  if (statusCode === 404) return "Resource not found";
  if (statusCode === 409) return "Resource state conflict";
  if (statusCode === 429) return "Too many requests";
  if (statusCode === 503) return "Service unavailable";
  if (statusCode >= 500) return "Internal server error";
  return "Request failed";
}

function requestIdFromRequest(request: HttpRequest): string | undefined {
  const headers = request.headers ?? {};
  const header = Object.entries(headers).find(([key]) => key.toLowerCase() === "x-request-id" || key.toLowerCase() === "x-correlation-id")?.[1];
  const value = Array.isArray(header) ? header[0] : header;
  const candidate = typeof value === "string" ? value : request.id;
  if (typeof candidate !== "string") return undefined;
  const normalized = candidate.trim();
  if (normalized.length === 0 || normalized.length > 128 || /[\u0000-\u001f\u007f]/u.test(normalized)) return undefined;
  if (/(?:secret|token|password|private[-_]?key|credential|authorization|cookie|vault:\/\/)/iu.test(normalized)) return undefined;
  return normalized;
}

function safeErrorMessage(value: string): string {
  const normalized = value.trim();
  if (
    normalized.length === 0 ||
    normalized.length > 512 ||
    /[\u0000-\u001f\u007f]/u.test(normalized) ||
    /(?:secret|token|password|private[-_]?key|credential|authorization|cookie|vault:\/\/)/iu.test(normalized)
  ) return "Request failed";
  return normalized;
}

function formatResponseEtag(value: unknown): string | undefined {
  if (!isRecord(value)) return undefined;
  return formatEtag(value.etag);
}

function formatEtag(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  const normalized = value.trim();
  if (
    normalized.length === 0 ||
    normalized.length > 512 ||
    /[\u0000-\u001f\u007f]/u.test(normalized) ||
    /(?:secret|token|password|private[-_]?key|credential|authorization|cookie|vault:\/\/)/iu.test(normalized)
  ) return undefined;
  const weak = normalized.startsWith("W/");
  const entity = weak ? normalized.slice(2).trim() : normalized;
  const quoted = entity.length >= 2 && entity.startsWith('"') && entity.endsWith('"');
  const opaque = quoted ? entity.slice(1, -1) : entity;
  if (opaque.length === 0 || opaque.includes('"') || opaque.includes("\\") || /[\u0000-\u001f\u007f]/u.test(opaque)) return undefined;
  return `${weak ? "W/" : ""}"${opaque}"`;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
