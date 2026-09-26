import { createHash, randomBytes } from "node:crypto";
import { Controller, Get, Req, Res, UseFilters } from "@nestjs/common";
import { Public } from "@getbrick/idaas-nestjs";
import { assertPlatformLoginReturnTo } from "@getbrick/idaas-core";
import { ApplicationPlatformAuthService } from "@getbrick/idaas-control-plane";
import { ControlPlaneExceptionFilter } from "@getbrick/idaas-control-plane";

const APPLICATION_ID = process.env.IDAAS_OIDC_APPLICATION_ID;
const PLATFORM_ID = process.env.IDAAS_OIDC_PLATFORM_ID;
const REDIRECT_URI = process.env.IDAAS_OIDC_PLATFORM_REDIRECT_URI;
const BINDING_COOKIE_PREFIX = "gb_platform_binding_";
const BINDING_COOKIE_MAX_AGE_SECONDS = 600;

@Controller()
@Public()
@UseFilters(ControlPlaneExceptionFilter)
export class OidcPlatformLoginController {
  constructor(private readonly platformAuth: ApplicationPlatformAuthService) {}

  @Get("login")
  async login(@Req() request: LoginRequest, @Res() response: LoginResponse): Promise<void> {
    const applicationId = requiredEnvironment(APPLICATION_ID, "application");
    const platformId = requiredEnvironment(PLATFORM_ID, "platform");
    const redirectUri = requiredEnvironment(REDIRECT_URI, "redirect");
    const returnTo = readReturnTo(request.query?.returnTo);
    const binding = randomBytes(32).toString("base64url");
    const result = await this.platformAuth.createPublicLogin(
      applicationId,
      platformId,
      { redirectUri, returnTo },
      request,
      { browserId: binding },
    );
    const cookieName = bindingCookieName(applicationId, platformId);
    const maxAge = Math.max(1, Math.min(BINDING_COOKIE_MAX_AGE_SECONDS, Math.ceil((Date.parse(result.expiresAt) - Date.now()) / 1000)));
    response.setHeader?.("Set-Cookie", `${cookieName}=${encodeURIComponent(binding)}; Max-Age=${Number.isFinite(maxAge) ? maxAge : BINDING_COOKIE_MAX_AGE_SECONDS}; Path=/; HttpOnly; Secure; SameSite=Lax`);
    response.setHeader?.("Cache-Control", "no-store");
    response.setHeader?.("Pragma", "no-cache");
    response.setHeader?.("Referrer-Policy", "no-referrer");
    response.status?.(303);
    response.setHeader?.("Location", result.authorizationUrl);
    response.end?.();
  }
}

interface LoginRequest {
  query?: Record<string, unknown>;
  headers?: Record<string, unknown>;
  url?: string;
  originalUrl?: string;
  method?: string;
}

interface LoginResponse {
  status?: (code: number) => unknown;
  statusCode?: number;
  setHeader?: (name: string, value: string) => unknown;
  end?: () => unknown;
}

function requiredEnvironment(value: string | undefined, name: string): string {
  if (value === undefined || value.trim().length === 0) throw new Error(`[getbrick-example] OIDC platform ${name} is not configured`);
  return value.trim();
}

function readReturnTo(value: unknown): string {
  if (typeof value !== "string" || value.length === 0) throw new Error("[getbrick-example] OIDC interaction returnTo is required");
  return assertPlatformLoginReturnTo(value);
}

function bindingCookieName(applicationId: string, platformId: string): string {
  const digest = createHash("sha256").update(`${applicationId}:${platformId}`, "utf8").digest("hex").slice(0, 24);
  return `${BINDING_COOKIE_PREFIX}${digest}`;
}
