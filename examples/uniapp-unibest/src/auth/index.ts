import { createAuthClient, type AuthClient, type AuthClientOptions } from "./client";

export * from "./callback";
export * from "./client";
export * from "./errors";
export * from "./handoff";
export * from "./pkce";
export * from "./platform";
export * from "./session";
export * from "./session-coordinator";
export * from "../services/auth";
export * from "../services/request";

let defaultClient: AuthClient | undefined;

export function getAuthClient(options?: AuthClientOptions): AuthClient {
  if (options !== undefined) return createAuthClient(options);
  defaultClient ??= createAuthClient();
  return defaultClient;
}
