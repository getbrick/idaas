import {
  ArgumentsHost,
  Catch,
  Injectable,
} from "@nestjs/common";
import {
  isOpenPlatformRequestContext,
} from "../authorization.js";
import {
  isOpenPlatformCommerceError,
  toOpenPlatformCommerceContractError,
  type OpenPlatformCommerceErrorCode,
} from "../commerce/errors.js";
import { toOpenPlatformHttpError } from "./open-platform-http.filter.js";
import {
  OPEN_PLATFORM_HTTP_CONTEXT,
  type OpenPlatformHttpRequest,
} from "./open-platform-http.types.js";
import type { OpenPlatformErrorCode } from "../errors.js";

export interface OpenPlatformCommerceHttpErrorBody {
  readonly code: OpenPlatformCommerceErrorCode | OpenPlatformErrorCode;
  readonly message: string;
  readonly requestId?: string;
}

export interface OpenPlatformCommerceHttpErrorResponse {
  readonly statusCode: number;
  readonly body: OpenPlatformCommerceHttpErrorBody;
}

interface HttpResponse {
  status(code: number): HttpResponse;
  json(body: OpenPlatformCommerceHttpErrorBody): void;
  setHeader?(name: string, value: string): unknown;
  headersSent?: boolean;
}

export function toOpenPlatformCommerceHttpError(
  error: unknown,
  requestId?: string,
): OpenPlatformCommerceHttpErrorResponse {
  if (isOpenPlatformCommerceError(error)) {
    const contract = toOpenPlatformCommerceContractError(error);
    const safeRequestId = normalizeCommerceRequestId(requestId);
    return {
      statusCode: contract.statusCode,
      body: {
        code: contract.body.code,
        message: contract.body.message,
        ...(safeRequestId === undefined ? {} : { requestId: safeRequestId }),
      },
    };
  }
  const shared = toOpenPlatformHttpError(
    error,
    normalizeCommerceRequestId(requestId),
  );
  return {
    statusCode: shared.statusCode,
    body: shared.body,
  };
}

@Catch()
@Injectable()
export class OpenPlatformCommerceHttpExceptionFilter {
  catch(exception: unknown, host: ArgumentsHost): void {
    const http = host.switchToHttp();
    const response = http.getResponse<HttpResponse>();
    const request = http.getRequest<OpenPlatformHttpRequest>();
    const requestId = trustedCommerceRequestId(request);
    const contract = toOpenPlatformCommerceHttpError(exception, requestId);
    setNoStore(response);
    if (requestId !== undefined) response.setHeader?.("x-request-id", requestId);
    if (contract.statusCode === 429 || contract.statusCode === 503) {
      response.setHeader?.("Retry-After", "1");
    }
    if (response.headersSent === true) return;
    response.status(contract.statusCode).json(contract.body);
  }
}

export { OpenPlatformCommerceHttpExceptionFilter as OpenPlatformCommerceErrorFilter };

function trustedCommerceRequestId(request: OpenPlatformHttpRequest): string | undefined {
  const value = request[OPEN_PLATFORM_HTTP_CONTEXT];
  return isOpenPlatformRequestContext(value)
    ? normalizeCommerceRequestId(value.requestId)
    : undefined;
}

function normalizeCommerceRequestId(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  const normalized = value.trim();
  if (
    normalized.length < 1 ||
    normalized.length > 128 ||
    /[\s\u0000-\u001f\u007f]/u.test(normalized) ||
    /(?:secret|token|password|private[-_]?key|credential|authorization|cookie|vault:\/\/)/iu.test(normalized)
  ) {
    return undefined;
  }
  return normalized;
}

function setNoStore(response: HttpResponse): void {
  response.setHeader?.("Cache-Control", "no-store");
  response.setHeader?.("Pragma", "no-cache");
  response.setHeader?.("Referrer-Policy", "no-referrer");
}
