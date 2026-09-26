import { describe, expect, it, vi } from "vitest";
import { GetbrickOidcMiddleware } from "../src/oidc/middleware.js";
import {
  createBetterAuthOidcSessionRevocationPort,
  DEFAULT_OIDC_LOGOUT_STATE_TTL_MS,
  OidcLogoutCoordinator,
  type OidcSessionRevocationInput,
} from "../src/oidc/logout-coordinator.js";

const redirectUri = "https://client.example.test/logout";

function request(idempotencyKey = "logout-1") {
  return {
    tenantId: "tenant-1",
    applicationId: "application-1",
    clientId: "client-1",
    userId: "user-1",
    providerSessionId: "op-session-1",
    postLogoutRedirectUri: redirectUri,
    idempotencyKey,
  };
}

describe("OIDC logout coordinator", () => {
  it("preflights the explicit client and exact registered redirect", async () => {
    const calls: string[] = [];
    const coordinator = new OidcLogoutCoordinator({
      resolveClient: async (clientId) => {
        calls.push(clientId);
        return { metadata: { post_logout_redirect_uris: [redirectUri] } };
      },
      sessionRevocation: { revoke: () => undefined },
      grantRevocation: { revoke: () => undefined },
    });

    await expect(coordinator.prepare(request())).resolves.toMatchObject({
      clientId: "client-1",
      status: "pending",
    });
    await expect(coordinator.prepare({
      ...request("logout-invalid-redirect"),
      postLogoutRedirectUri: "https://attacker.example/logout",
    })).rejects.toThrow(/not registered/i);
    expect(calls).toEqual(["client-1", "client-1"]);
  });

  it("does not infer a client from an id token hint", async () => {
    const resolvedClients: string[] = [];
    const coordinator = new OidcLogoutCoordinator({
      resolveClient: async (clientId) => {
        resolvedClients.push(clientId);
        return { post_logout_redirect_uris: [redirectUri] };
      },
      sessionRevocation: { revoke: () => undefined },
      grantRevocation: { revoke: () => undefined },
    });
    const forgedHint = `${Buffer.from(JSON.stringify({ alg: "none" })).toString("base64url")}.${Buffer.from(JSON.stringify({ aud: "attacker-client" })).toString("base64url")}.signature`;

    await expect(coordinator.prepare({
      ...request(),
      clientId: "client-1",
      idTokenHint: forgedHint,
    })).resolves.toMatchObject({ clientId: "client-1" });
    expect(resolvedClients).toEqual(["client-1"]);
  });

  it("revokes every target once and makes duplicate completion idempotent", async () => {
    const sessionCalls: string[][] = [];
    const grantCalls: string[][] = [];
    const coordinator = new OidcLogoutCoordinator({
      resolveClient: async () => ({ post_logout_redirect_uris: [redirectUri] }),
      sessionRevocation: {
        revoke: (input: OidcSessionRevocationInput) => {
          sessionCalls.push([...input.targets]);
          return input.targets;
        },
      },
      grantRevocation: {
        revoke: (input: { targets: readonly string[] }) => {
          grantCalls.push([...input.targets]);
          return input.targets;
        },
      },
    });
    const operation = await coordinator.prepare(request());
    const first = await coordinator.complete(operation, { providerSessionRevoked: true });
    const second = await coordinator.complete(operation);

    expect(first.completed).toBe(true);
    expect(first.revokedTargets).toEqual(["op_session", "offline_grant", "better_auth", "bff_cookie"]);
    expect(second.completed).toBe(true);
    expect(sessionCalls).toEqual([["better_auth", "bff_cookie"]]);
    expect(grantCalls).toEqual([["offline_grant"]]);
  });

  it("returns failure and retries only unfinished revocation", async () => {
    let attempts = 0;
    const sessionCalls: string[][] = [];
    const coordinator = new OidcLogoutCoordinator({
      resolveClient: async () => ({ post_logout_redirect_uris: [redirectUri] }),
      sessionRevocation: {
        revoke: (input: OidcSessionRevocationInput) => {
          attempts += 1;
          sessionCalls.push([...input.targets]);
          if (attempts === 1) throw new Error("temporary session store failure");
          return input.targets;
        },
      },
      grantRevocation: { revoke: (input: { targets: readonly string[] }) => input.targets },
    });
    const operation = await coordinator.prepare(request("logout-retry"));
    const failed = await coordinator.complete(operation);
    const retried = await coordinator.complete(failed.operation);
    const duplicate = await coordinator.complete(retried.operation);

    expect(failed.completed).toBe(false);
    expect(failed.operation.status).toBe("failed");
    expect(retried.completed).toBe(true);
    expect(duplicate.completed).toBe(true);
    expect(sessionCalls).toEqual([["op_session", "better_auth", "bff_cookie"], ["op_session", "better_auth", "bff_cookie"]]);
  });

  it("always passes request context to a custom coordinator", async () => {
    let receivedContext: unknown;
    const operation = {
      contractVersion: 1 as const,
      operationId: "custom-operation",
      tenantId: "tenant-1",
      clientId: "client-1",
      status: "pending" as const,
      idempotencyKey: "custom-logout",
      targets: ["op_session", "offline_grant", "better_auth", "bff_cookie"] as const,
      createdAt: "2026-01-01T00:00:00.000Z",
      updatedAt: "2026-01-01T00:00:00.000Z",
    };
    const complete = vi.fn(async (_operation: typeof operation, context: unknown) => {
      receivedContext = context;
      return { operation: { ...operation, status: "completed" as const }, revokedTargets: operation.targets, completed: true };
    });
    const coordinator = {
      prepare: vi.fn(async () => operation),
      complete,
    };
    let listener: ((context: unknown) => void) | undefined;
    const runtime = {
      issuer: "https://id.example.test/oidc",
      basePath: "/oidc",
      interactionPath: "/oidc/interaction",
      provider: {
        on: vi.fn((_event: string, value: (context: unknown) => void) => {
          listener = value;
        }),
        off: vi.fn(),
        callback: () => async (_request: unknown, response: { end: () => void }) => {
          response.end();
          listener?.({
            oidc: {
              client: { clientId: "client-1" },
              session: { accountId: "user-1", uid: "op-session-1" },
            },
          });
        },
      },
    };
    const auth = {
      options: {},
      api: { getSession: async () => ({ user: { id: "user-1" } }) },
      handler: async () => new Response("ok"),
    };
    const response = { end: vi.fn(), headersSent: false };
    const middleware = new GetbrickOidcMiddleware(runtime as never, auth as never, undefined, undefined, coordinator as never);

    await middleware.use({
      originalUrl: "/oidc/session/end/confirm",
      method: "POST",
      headers: { cookie: "opaque-cookie" },
    }, response, () => undefined);

    expect(complete).toHaveBeenCalledTimes(1);
    expect(receivedContext).toMatchObject({
      clientId: "client-1",
      userId: "user-1",
      providerSessionId: "op-session-1",
      providerSessionRevoked: true,
    });
  });

  it("uses one completion listener and one Better Auth signout", async () => {
    const response = {
      end: vi.fn(),
      append: vi.fn(),
      setHeader: vi.fn(),
      headersSent: false,
    };
    const signOut = vi.fn(async () => new Response("ok", {
      headers: { "set-cookie": "better-auth.session_token=; Max-Age=0; Path=/; HttpOnly" },
    }));
    const auth = {
      options: {},
      api: { getSession: async () => ({ user: { id: "user-1" } }) },
      handler: signOut,
    };
    let listener: ((context: unknown) => void) | undefined;
    const provider = {
      on: vi.fn((_event: string, value: (context: unknown) => void) => {
        listener = value;
      }),
      off: vi.fn(),
      callback: () => async (_request: unknown, output: { end: () => void }) => {
        output.end();
        listener?.({
          res: response,
          oidc: {
            client: { clientId: "client-1" },
            session: { accountId: "user-1", uid: "op-session-1" },
          },
        });
      },
    };
    const coordinator = new OidcLogoutCoordinator({
      auth,
      issuer: "https://id.example.test/oidc",
      profile: "development",
      resolveClient: async () => ({ post_logout_redirect_uris: [redirectUri] }),
      grantRevocation: { revoke: (input: { targets: readonly string[] }) => input.targets },
    });
    const middleware = new GetbrickOidcMiddleware({
      issuer: "https://id.example.test/oidc",
      basePath: "/oidc",
      interactionPath: "/oidc/interaction",
      provider,
    } as never, auth as never, undefined, undefined, coordinator as never);

    await middleware.use({
      originalUrl: "/oidc/session/end/confirm",
      method: "POST",
      headers: { cookie: "opaque-cookie" },
    }, response, () => undefined);

    expect(provider.on).toHaveBeenCalledTimes(1);
    expect(provider.off).toHaveBeenCalledTimes(1);
    expect(signOut).toHaveBeenCalledTimes(1);
  });

  it("does not report success when a confirm has no completion event", async () => {
    const runtime = {
      issuer: "https://id.example.test/oidc",
      basePath: "/oidc",
      interactionPath: "/oidc/interaction",
      provider: {
        on: vi.fn(),
        off: vi.fn(),
        callback: () => async () => undefined,
      },
    };
    const response = { end: vi.fn(), headersSent: false };
    const middleware = new GetbrickOidcMiddleware(runtime as never, {} as never, undefined, undefined, {
      prepare: vi.fn(),
      complete: vi.fn(),
    } as never);

    await middleware.use({
      originalUrl: "/oidc/session/end/confirm",
      method: "POST",
      headers: { cookie: "opaque-cookie" },
    }, response, () => undefined);

    expect(response.end).toHaveBeenCalledTimes(1);
  });

  it("bounds and expires pending logout requests", () => {
    const middleware = new GetbrickOidcMiddleware(
      { issuer: "https://id.example.test/oidc", basePath: "/oidc", interactionPath: "/oidc/interaction" } as never,
      {} as never,
    );
    const state = middleware as unknown as {
      maxPendingLogoutRequests: number;
      pendingLogoutRequests: Map<string, unknown>;
      pendingLogoutExpiresAt: Map<string, number>;
      setPendingLogoutRequest: (request: { headers: Record<string, string> }, pending: unknown) => void;
      prunePendingLogoutRequests: () => void;
    };
    state.maxPendingLogoutRequests = 2;
    vi.useFakeTimers();
    try {
      state.setPendingLogoutRequest({ headers: { cookie: "a" } }, { clientId: "a" });
      state.setPendingLogoutRequest({ headers: { cookie: "b" } }, { clientId: "b" });
      state.setPendingLogoutRequest({ headers: { cookie: "c" } }, { clientId: "c" });
      expect(state.pendingLogoutRequests.size).toBe(2);
      vi.advanceTimersByTime(DEFAULT_OIDC_LOGOUT_STATE_TTL_MS + 1);
      state.prunePendingLogoutRequests();
      expect(state.pendingLogoutRequests.size).toBe(0);
      expect(state.pendingLogoutExpiresAt.size).toBe(0);
    } finally {
      vi.useRealTimers();
    }
  });

  it("bounds coordinator state and clears active maps at terminal paths", async () => {
    let now = 0;
    const coordinator = new OidcLogoutCoordinator({
      resolveClient: async () => ({ post_logout_redirect_uris: [redirectUri] }),
      sessionRevocation: { revoke: () => undefined },
      grantRevocation: { revoke: () => undefined },
      now: () => new Date(now),
      stateTtlMs: 100,
      maxOperations: 2,
    });
    const first = await coordinator.prepare(request("bounded-1"));
    await coordinator.complete(first, { providerSessionRevoked: true });
    const second = await coordinator.prepare(request("bounded-2"));
    await coordinator.complete(second, { providerSessionRevoked: true });
    const third = await coordinator.prepare(request("bounded-3"));
    await coordinator.complete(third, { providerSessionRevoked: true });

    const state = coordinator as unknown as {
      operations: { size: number };
      fingerprints: { size: number };
      preparing: { size: number };
      revokedByOperation: { size: number };
      failedOperations: { size: number };
      completedOperations: { size: number };
      inFlight: { size: number };
    };
    expect(state.operations.size).toBe(0);
    expect(state.fingerprints.size).toBe(0);
    expect(state.preparing.size).toBe(0);
    expect(state.revokedByOperation.size).toBe(0);
    expect(state.failedOperations.size).toBe(0);
    expect(state.inFlight.size).toBe(0);
    expect(state.completedOperations.size).toBeLessThanOrEqual(2);
  });

  it("expires coordinator state and keeps failure retryable", async () => {
    let now = 0;
    let attempts = 0;
    const coordinator = new OidcLogoutCoordinator({
      resolveClient: async () => ({ post_logout_redirect_uris: [redirectUri] }),
      sessionRevocation: {
        revoke: (input: OidcSessionRevocationInput) => {
          attempts += 1;
          if (attempts === 1) throw new Error("temporary failure");
          return input.targets;
        },
      },
      grantRevocation: { revoke: (input: { targets: readonly string[] }) => input.targets },
      now: () => new Date(now),
      stateTtlMs: 10,
    });
    const operation = await coordinator.prepare(request("expiring-retry"));
    const failed = await coordinator.complete(operation);
    expect(failed.completed).toBe(false);
    expect((coordinator as unknown as { operations: { size: number } }).operations.size).toBe(0);
    now = 11;
    const retry = await coordinator.complete(failed.operation);
    expect(retry.completed).toBe(true);
    expect((coordinator as unknown as { operations: { size: number } }).operations.size).toBe(0);
  });

  it("fails closed when a required port is absent", async () => {
    const coordinator = new OidcLogoutCoordinator({
      resolveClient: async () => ({ post_logout_redirect_uris: [redirectUri] }),
      sessionRevocation: { revoke: () => undefined },
    });
    const operation = await coordinator.prepare(request("logout-no-grant"));
    const result = await coordinator.complete(operation, { providerSessionRevoked: true });

    expect(result.completed).toBe(false);
    expect(result.operation.status).toBe("failed");
  });

  it("clears the Better Auth cookie through the default session adapter", async () => {
    const headers: Record<string, string> = {};
    const responseHeaders = new Headers();
    responseHeaders.append("set-cookie", "better-auth.session_token=; Max-Age=0; Path=/; HttpOnly");
    const auth = {
      options: {},
      api: { getSession: async () => null },
      handler: async () => new Response("ok", { headers: responseHeaders }),
    };
    const port = createBetterAuthOidcSessionRevocationPort(auth, "https://id.example.test/oidc");
    const result = await port.revoke({
      operation: {
        contractVersion: 1,
        operationId: "operation-1",
        tenantId: "tenant-1",
        clientId: "client-1",
        status: "pending",
        idempotencyKey: "logout-cookie",
        targets: ["better_auth", "bff_cookie"],
        createdAt: "2026-01-01T00:00:00.000Z",
        updatedAt: "2026-01-01T00:00:00.000Z",
      },
      targets: ["better_auth", "bff_cookie"],
      context: { response: { append: (name: string, value: string) => { headers[name] = value; } } },
    });

    expect(result).toEqual(["better_auth", "bff_cookie"]);
    expect(headers["Set-Cookie"]).toContain("better-auth.session_token=");
  });
});
