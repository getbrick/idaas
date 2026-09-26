import {
  ArgumentsHost,
  Catch,
  Injectable,
} from "@nestjs/common";
import {
  toOpenPlatformContractError,
} from "../errors.js";
import {
  isOpenPlatformCommerceError,
  toOpenPlatformCommerceContractError,
} from "../commerce/errors.js";
import {
  type OpenPlatformHttpErrorBody,
  type OpenPlatformHttpErrorResponse,
  type OpenPlatformHttpRequest,
} from "./open-platform-http.types.js";
import { OPEN_PLATFORM_HTTP_CONTEXT } from "./open-platform-http.types.js";
import { isOpenPlatformRequestContext } from "../authorization.js";

interface HttpResponse {
  status(code: number): HttpResponse;
  json(body: OpenPlatformHttpErrorBody): void;
  setHeader?(name: string, value: string): unknown;
  headersSent?: boolean;
}

@Catch()
@Injectable()
export class OpenPlatformHttpExceptionFilter {
  catch(exception: unknown, host: ArgumentsHost): void {
    const http = host.switchToHttp();
    const response = http.getResponse<HttpResponse>();
    const request = http.getRequest<OpenPlatformHttpRequest>();
    const requestId = trustedRequestId(request);
    const contract = toOpenPlatformHttpError(exception, requestId);
    setNoStore(response);
    if (requestId !== undefined) response.setHeader?.("x-request-id", requestId);
    if (contract.statusCode === 429 || contract.statusCode === 503) {
      response.setHeader?.("Retry-After", "1");
    }
    if (response.headersSent === true) return;
    response.status(contract.statusCode).json(contract.body);
  }
}

export function toOpenPlatformHttpError(
  error: unknown,
  requestId?: string,
): OpenPlatformHttpErrorResponse {
  if (isOpenPlatformCommerceError(error)) {
    const commerceContract = toOpenPlatformCommerceContractError(error);
    const safeRequestId = normalizeRequestId(requestId);
    return {
      statusCode: commerceContract.statusCode,
      body: {
        code: commerceContract.body.code as unknown as OpenPlatformHttpErrorBody["code"],
        message: commerceContract.body.message,
        ...(safeRequestId === undefined ? {} : { requestId: safeRequestId }),
      },
    };
  }
  const contract = toOpenPlatformContractError(
    error,
    normalizeRequestId(requestId),
  );
  return {
    statusCode: contract.statusCode,
    body: contract.body,
  };
}

export { OpenPlatformHttpExceptionFilter as OpenPlatformHttpErrorFilter };

function trustedRequestId(request: OpenPlatformHttpRequest): string | undefined {
  const value = request[OPEN_PLATFORM_HTTP_CONTEXT];
  return isOpenPlatformRequestContext(value)
    ? normalizeRequestId(value.requestId)
    : undefined;
}

function normalizeRequestId(value: unknown): string | undefined {
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
