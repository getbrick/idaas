import {
  CallHandler,
  ExecutionContext,
  Injectable,
  type NestInterceptor,
} from "@nestjs/common";
import type { Observable } from "rxjs";
import {
  OPEN_PLATFORM_HTTP_CONTEXT,
  type OpenPlatformHttpRequest,
} from "./open-platform-http.types.js";
import { isOpenPlatformRequestContext } from "../authorization.js";

interface HttpResponse {
  setHeader?(name: string, value: string): unknown;
}

@Injectable()
export class OpenPlatformHttpResponseInterceptor implements NestInterceptor {
  intercept(context: ExecutionContext, next: CallHandler): Observable<unknown> {
    const http = context.switchToHttp();
    const response = http.getResponse<HttpResponse>();
    const request = http.getRequest<OpenPlatformHttpRequest>();
    setNoStore(response);
    const value = request[OPEN_PLATFORM_HTTP_CONTEXT];
    if (isOpenPlatformRequestContext(value) && safeRequestId(value.requestId)) {
      response.setHeader?.("x-request-id", value.requestId);
    }
    return next.handle();
  }
}

function safeRequestId(value: unknown): value is string {
  return typeof value === "string" &&
    value.length > 0 &&
    value.length <= 128 &&
    !/[\s\u0000-\u001f\u007f]/u.test(value) &&
    !/(?:secret|token|password|private[-_]?key|credential|authorization|cookie|vault:\/\/)/iu.test(value);
}

function setNoStore(response: HttpResponse): void {
  response.setHeader?.("Cache-Control", "no-store");
  response.setHeader?.("Pragma", "no-cache");
  response.setHeader?.("Referrer-Policy", "no-referrer");
}
