import { describe, expect, it } from "vitest";
import { normalizeOpaqueSession, OpaqueSessionStore, OPAQUE_SESSION_STORAGE_KEY } from "../src/auth/session";
import { createMemoryStorage } from "../src/types/runtime";

const reference = "opaque_abcdefghijklmnopqrstuvwxyz123456";
const expiresAt = "2099-01-01T00:00:00.000Z";

describe("opaque client session", () => {
  it("persists only the opaque reference and public data", () => {
    const storage = createMemoryStorage();
    const store = new OpaqueSessionStore({ storage, now: () => Date.parse("2028-01-01T00:00:00.000Z") });
    store.save({
      sessionReference: reference,
      expiresAt,
      user: { id: "user_1", name: "Customer", email: "user@example.com", emailVerified: true },
    });

    const raw = storage.get(OPAQUE_SESSION_STORAGE_KEY);
    expect(raw).toBeDefined();
    expect(raw).not.toContain("access_token");
    expect(raw).not.toContain("refresh_token");
    expect(raw).not.toContain("session_key");
    expect(raw).not.toContain("client_secret");
    expect(store.get()).toEqual({
      sessionReference: reference,
      expiresAt,
      user: { id: "user_1", name: "Customer", email: "user@example.com", emailVerified: true },
    });
  });

  it("normalizes a platform login result without retaining provider fields", () => {
    const result = normalizeOpaqueSession({
      user: { id: "user_1", name: "Customer", email: null, emailVerified: false },
      session: { sessionReference: reference, expiresAt, clientKind: "mp_weixin" },
      client: "mini_program",
    });

    expect(result).toEqual({
      sessionReference: reference,
      expiresAt,
      clientKind: "mp_weixin",
      user: { id: "user_1", name: "Customer", email: null, emailVerified: false },
    });
  });

  it("rejects provider credentials in an authentication response", () => {
    expect(() => normalizeOpaqueSession({ sessionReference: reference, expiresAt, session_key: "provider-value" })).toThrow();
    expect(() => normalizeOpaqueSession({ sessionReference: reference, expiresAt, access_token: "provider-value" })).toThrow();
    expect(() => normalizeOpaqueSession({ sessionReference: reference, expiresAt, client_secret: "provider-value" })).toThrow();
  });

  it("clears an expired local session", () => {
    const storage = createMemoryStorage();
    storage.set(OPAQUE_SESSION_STORAGE_KEY, JSON.stringify({ sessionReference: reference, expiresAt: "2020-01-01T00:00:00.000Z" }));
    const store = new OpaqueSessionStore({ storage });

    expect(store.load()).toBeNull();
    expect(storage.get(OPAQUE_SESSION_STORAGE_KEY)).toBeUndefined();
  });
});
