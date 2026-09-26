import { randomUUID } from "node:crypto";
import {
  CanActivate,
  ExecutionContext,
  Inject,
  Injectable,
  Optional,
  createParamDecorator,
} from "@nestjs/common";
import {
  isOpenPlatformRequestContext,
  type OpenPlatformRequestContext,
  type OpenPlatformRequestContextInput,
} from "../authorization.js";
import {
  authenticationRequired,
  isOpenPlatformDomainError,
  storageUnavailable,
  tenantMismatch,
  validationError,
} from "../errors.js";
import {
  OPEN_PLATFORM_HTTP_CONTEXT,
  OPEN_PLATFORM_HTTP_CONTEXT_ISSUER,
  OPEN_PLATFORM_HTTP_CONTEXT_RESOLVER,
  OPEN_PLATFORM_HTTP_MODE,
  isOpenPlatformHttpRecord,
  type OpenPlatformHttpContextResolution,
  type OpenPlatformHttpContextResolver,
  type OpenPlatformHttpContextResolverWithContext,
  type OpenPlatformHttpRequest,
} from "./open-platform-http.types.js";

@Injectable()
export class OpenPlatformHttpContextGuard implements CanActivate {
  constructor(
    @Optional()
    @Inject(OPEN_PLATFORM_HTTP_CONTEXT_RESOLVER)
    private readonly resolver?: OpenPlatformHttpContextResolver | OpenPlatformHttpContextResolverWithContext,
    @Optional()
    @Inject(OPEN_PLATFORM_HTTP_CONTEXT_ISSUER)
    private readonly issuer?: {
      readonly issuerId: string;
      issueAuthenticated(input: OpenPlatformRequestContextInput): OpenPlatformRequestContext;
      issueDevelopment(input: OpenPlatformRequestContextInput): OpenPlatformRequestContext;
    },
    @Optional()
    @Inject(OPEN_PLATFORM_HTTP_MODE)
    private readonly mode?: string,
  ) {}

  async canActivate(executionContext: ExecutionContext): Promise<boolean> {
    const http = executionContext.switchToHttp();
    const request = http.getRequest<OpenPlatformHttpRequest>();
    const response = http.getResponse<{ setHeader?: (name: string, value: string) => unknown }>();
    let context: OpenPlatformRequestContext | undefined;
    try {
      if (this.resolver === undefined) throw authenticationRequired();
      const resolve = "resolve" in this.resolver
        ? this.resolver.resolve
        : this.resolver.resolveContext;
      if (typeof resolve !== "function") throw authenticationRequired();
      const resolved = await resolve.call(this.resolver, request);
      context = this.toTrustedContext(resolved, request);
    } catch (error) {
      if (isOpenPlatformDomainError(error)) throw error;
      throw storageUnavailable();
    }
    if (context === undefined) throw authenticationRequired();
    request[OPEN_PLATFORM_HTTP_CONTEXT] = context;
    response?.setHeader?.("x-request-id", context.requestId);
    assertNoPlaintextInput(request.body);
    assertNoPlaintextInput(request.query);
    assertTenantMatches(context, request);
    return true;
  }

  private toTrustedContext(
    resolved: OpenPlatformHttpContextResolution,
    request: OpenPlatformHttpRequest,
  ): OpenPlatformRequestContext | undefined {
    const value = unwrapResolution(resolved);
    if (isOpenPlatformRequestContext(value)) {
      if (this.mode === "production") {
        return value.assurance === "authenticated" ? safeContext(value) : undefined;
      }
      return safeContext(value);
    }
    if (!isOpenPlatformHttpRecord(value)) return undefined;
    if (this.mode === "production" && value.assurance === "development") {
      return undefined;
    }
    const tenantId = value.tenantId ?? value.tenant_id;
    const actorId = value.actorId ?? value.actor_id;
    const requestId = value.requestId ?? value.request_id ??
      safeRequestId(request.id) ?? safeRequestId(headerValue(request.headers, "x-request-id")) ??
      `open-http-${randomUUID()}`;
    if (typeof tenantId !== "string" || typeof actorId !== "string") {
      return undefined;
    }
    const input: OpenPlatformRequestContextInput = {
      tenantId,
      actorId,
      requestId: typeof requestId === "string" ? requestId : "",
    };
    return safeContext(
      this.issue(input, request, this.mode === "production" ? "authenticated" : "development"),
    );
  }

  private issue(
    input: OpenPlatformRequestContextInput,
    _request: OpenPlatformHttpRequest,
    assurance: "development" | "authenticated",
  ): OpenPlatformRequestContext | undefined {
    if (this.issuer === undefined) return undefined;
    try {
      return assurance === "authenticated"
        ? this.issuer.issueAuthenticated(input)
        : this.issuer.issueDevelopment(input);
    } catch {
      return undefined;
    }
  }
}

export const OpenPlatformHttpContext = createParamDecorator(
  (_data: unknown, context: ExecutionContext): OpenPlatformRequestContext | undefined => {
    const request = context.switchToHttp().getRequest<OpenPlatformHttpRequest>();
    const value = request[OPEN_PLATFORM_HTTP_CONTEXT];
    return isOpenPlatformRequestContext(value) ? value : undefined;
  },
);

export const OpenPlatformContext = OpenPlatformHttpContext;
export const OpenPlatformAuthenticationGuard = OpenPlatformHttpContextGuard;

function unwrapResolution(
  value: OpenPlatformHttpContextResolution,
): OpenPlatformRequestContextInput | OpenPlatformRequestContext | Record<string, unknown> | undefined {
  if (isOpenPlatformRequestContext(value)) return value;
  if (isOpenPlatformHttpRecord(value) && "context" in value) {
    return unwrapResolution(value.context as OpenPlatformHttpContextResolution);
  }
  return isOpenPlatformHttpRecord(value) ? value : undefined;
}

function assertNoPlaintextInput(
  value: unknown,
  depth = 0,
): void {
  if (depth > 6 || value === null || typeof value !== "object") return;
  if (Array.isArray(value)) {
    value.forEach((item) => assertNoPlaintextInput(item, depth + 1));
    return;
  }
  for (const [key, nested] of Object.entries(value as Record<string, unknown>)) {
    if (isPlaintextKey(key)) throw validationError("Plaintext secret input is not accepted");
    assertNoPlaintextInput(nested, depth + 1);
  }
}

function isPlaintextKey(key: string): boolean {
  const normalized = key.replace(/[-_]/gu, "").toLowerCase();
  return normalized === "secret" ||
    normalized === "clientsecret" ||
    normalized === "plaintext" ||
    normalized === "password" ||
    normalized === "token" ||
    normalized === "accesstoken" ||
    normalized === "refreshtoken" ||
    normalized === "idtoken" ||
    normalized === "privatekey" ||
    normalized === "authorization";
}

function assertTenantMatches(
  context: OpenPlatformRequestContext,
  request: OpenPlatformHttpRequest,
): void {
  for (const value of [request.body, request.query]) {
    if (!isOpenPlatformHttpRecord(value)) continue;
    for (const key of ["tenantId", "tenant_id"]) {
      const candidate = value[key];
      if (candidate !== undefined && candidate !== context.tenantId) {
        throw tenantMismatch();
      }
    }
  }
}

function safeContext(
  value: OpenPlatformRequestContext | undefined,
): OpenPlatformRequestContext | undefined {
  return value !== undefined && safeRequestId(value.requestId) !== undefined
    ? value
    : undefined;
}

function safeRequestId(value: unknown): string | undefined {
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

function headerValue(
  headers: Record<string, unknown> | undefined,
  name: string,
): unknown {
  const entry = Object.entries(headers ?? {}).find(([key]) => key.toLowerCase() === name);
  const value = entry?.[1];
  return Array.isArray(value) ? value[0] : value;
}
