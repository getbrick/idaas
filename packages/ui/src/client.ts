import { createAuthClient } from "better-auth/react";

export type GetbrickClient = ReturnType<typeof createAuthClient>;

export function createGetbrickClient(baseURL?: string): GetbrickClient {
  return createAuthClient({ baseURL, fetchOptions: { throw: false } });
}

export const getbrickContextKey = "getbrick:auth-client";
