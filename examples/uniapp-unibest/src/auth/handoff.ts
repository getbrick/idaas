import { AuthError } from "./errors";
import { getUniRuntime, type UniRuntime } from "../types/runtime";

export interface AuthHandoff {
  open(authorizationUrl: string): Promise<void>;
}

export function createUniAuthHandoff(runtime: UniRuntime = getUniRuntime()): AuthHandoff {
  return {
    async open(authorizationUrl) {
      assertAuthorizationUrl(authorizationUrl);
      // #ifdef H5
      const location = (globalThis as { location?: { assign?: (url: string) => void } }).location;
      if (typeof location?.assign !== "function") {
        throw new AuthError("oidc_configuration_missing", "H5 authorization handoff is unavailable");
      }
      location.assign(authorizationUrl);
      return;
      // #endif
      // #ifdef APP-PLUS
      await navigateToWebView(authorizationUrl, runtime);
      return;
      // #endif
      throw new AuthError("unsupported_platform", "OIDC handoff is unavailable on this platform");
    },
  };
}

export function assertAuthorizationUrl(value: string, expectedRedirectUri?: string): string {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new AuthError("oidc_configuration_missing", "OIDC authorization URL is invalid");
  }
  if (
    parsed.protocol !== "https:" ||
    parsed.hostname.length === 0 ||
    parsed.username !== "" ||
    parsed.password !== "" ||
    parsed.hash !== "" ||
    /[\u0000-\u001f\u007f\s]/u.test(value)
  ) {
    throw new AuthError("oidc_configuration_missing", "OIDC authorization URL is invalid");
  }
  for (const key of parsed.searchParams.keys()) {
    const normalized = key.toLowerCase().replace(/[^a-z0-9]/gu, "");
    if (["accesstoken", "authorization", "clientsecret", "code", "idtoken", "password", "refreshtoken", "secret", "sessionkey", "token"].includes(normalized)) {
      throw new AuthError("oidc_configuration_missing", "OIDC authorization URL is invalid");
    }
  }
  if (expectedRedirectUri !== undefined) {
    const redirectValues = parsed.searchParams.getAll("redirect_uri");
    if (redirectValues.length !== 1 || redirectValues[0] !== expectedRedirectUri) {
      throw new AuthError("oidc_configuration_missing", "OIDC authorization redirect does not match the callback");
    }
  }
  return value;
}

function navigateToWebView(url: string, runtime: UniRuntime): Promise<void> {
  return new Promise<void>((resolve, reject) => {
    try {
      runtime.navigateTo({
        url: `/pages/auth/web-view?url=${encodeURIComponent(url)}`,
        success: () => resolve(),
        fail: () => reject(new AuthError("oidc_configuration_missing", "OIDC web-view handoff failed")),
      });
    } catch {
      reject(new AuthError("oidc_configuration_missing", "OIDC web-view handoff failed"));
    }
  });
}
