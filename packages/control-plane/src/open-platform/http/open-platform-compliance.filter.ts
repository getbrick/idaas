import { ArgumentsHost, Catch, Injectable } from "@nestjs/common";
import {
  isOpenPlatformRequestContext,
} from "../authorization.js";
import {
  isOpenPlatformComplianceError,
  toOpenPlatformComplianceContractError,
  type ComplianceErrorCode,
} from "../compliance/errors.js";
import { toOpenPlatformHttpError } from "./open-platform-http.filter.js";
import {
  OPEN_PLATFORM_HTTP_CONTEXT,
  type OpenPlatformHttpRequest,
} from "./open-platform-http.types.js";
import type { OpenPlatformErrorCode } from "../errors.js";

export interface OpenPlatformComplianceHttpErrorBody {
  readonly code: ComplianceErrorCode | OpenPlatformErrorCode;
  readonly message: string;
  readonly requestId?: string;
}

export interface OpenPlatformComplianceHttpErrorResponse {
  readonly statusCode: number;
  readonly body: OpenPlatformComplianceHttpErrorBody;
}

interface HttpResponse {
  status(code: number): HttpResponse;
  json(body: OpenPlatformComplianceHttpErrorBody): void;
  setHeader?(name: string, value: string): unknown;
  headersSent?: boolean;
}

export function toOpenPlatformComplianceHttpError(
  error: unknown,
  requestId?: string,
): OpenPlatformComplianceHttpErrorResponse {
  if (isOpenPlatformComplianceError(error)) {
    const contract = toOpenPlatformComplianceContractError(error);
    const safeRequestId = normalizeComplianceRequestId(requestId);
    return {
      statusCode: contract.statusCode,
      body: {
        code: contract.body.code,
        message: contract.body.message,
        ...(safeRequestId === undefined ? {} : { requestId: safeRequestId }),
      },
    };
  }
  const shared = toOpenPlatformHttpError(error, normalizeComplianceRequestId(requestId));
  return {
    statusCode: shared.statusCode,
    body: shared.body,
  };
}

@Catch()
@Injectable()
export class OpenPlatformComplianceHttpExceptionFilter {
  catch(exception: unknown, host: ArgumentsHost): void {
    const http = host.switchToHttp();
    const response = http.getResponse<HttpResponse>();
    const request = http.getRequest<OpenPlatformHttpRequest>();
    const requestId = trustedComplianceRequestId(request);
    const contract = toOpenPlatformComplianceHttpError(exception, requestId);
    setNoStore(response);
    if (requestId !== undefined) response.setHeader?.("x-request-id", requestId);
    if (contract.statusCode === 429 || contract.statusCode === 503) {
      response.setHeader?.("Retry-After", "1");
    }
    if (response.headersSent === true) return;
    response.status(contract.statusCode).json(contract.body);
  }
}

export { OpenPlatformComplianceHttpExceptionFilter as OpenPlatformComplianceErrorFilter };

function trustedComplianceRequestId(
  request: OpenPlatformHttpRequest,
): string | undefined {
  const value = request[OPEN_PLATFORM_HTTP_CONTEXT];
  return isOpenPlatformRequestContext(value)
    ? normalizeComplianceRequestId(value.requestId)
    : undefined;
}

function normalizeComplianceRequestId(value: unknown): string | undefined {
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
