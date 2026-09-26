import { describe, expect, it } from "vitest";
import { buildTableMap, CORE_MODELS } from "../src/tables.js";
import { defineIdaasConfig } from "../src/config.js";
import { createAuditDatabaseHooks, createMemoryAuditSink, sanitize } from "../src/audit.js";

describe("buildTableMap", () => {
  it("prefixes every core model", () => {
    const map = buildTableMap({ prefix: "gb_idaas_" });
    expect(map.user).toBe("gb_idaas_user");
    expect(map.session).toBe("gb_idaas_session");
    expect(map.twoFactor).toBe("gb_idaas_two_factor");
    expect(map.organization).toBe("gb_idaas_organization");
    expect(Object.keys(map).length).toBe(CORE_MODELS.length);
  });

  it("applies overrides", () => {
    const map = buildTableMap({ prefix: "gb_idaas_", overrides: { user: "accounts" } });
    expect(map.user).toBe("accounts");
    expect(map.session).toBe("gb_idaas_session");
  });

  it("rejects unsafe override names", () => {
    expect(() => buildTableMap({ overrides: { user: "DROP TABLE users;--" } })).toThrow();
  });

  it("rejects duplicate table names", () => {
    expect(() =>
      buildTableMap({ overrides: { user: "x", session: "x" } }),
    ).toThrow(/duplicate/);
  });
});

describe("defineIdaasConfig", () => {
  it("fills defaults", () => {
    const config = defineIdaasConfig({});
    expect(config.tables.prefix).toBe("gb_idaas_");
    expect(config.session.expiresInDays).toBe(7);
    expect(config.password.minLength).toBe(8);
    expect(config.lockout.maxAttempts).toBe(10);
    expect(config.audit.enabled).toBe(true);
    expect(config.audit.redactPersonalData).toBe(true);
    expect(config.features.twoFactor).toBe(true);
    expect(config.profile).toBe("development");
    expect(config.registration).toEqual({
      publicSignUp: true,
      requireEmailVerification: false,
    });
    expect(config.email).toEqual({
      requireEmailVerification: false,
      sendOnSignUp: false,
      resetPasswordEnabled: false,
    });
    expect(config.trustedOrigins).toEqual([]);
  });

  it("keeps the registration policy serializable", () => {
    const config = defineIdaasConfig({
      profile: "test",
      registration: { publicSignUp: false, requireEmailVerification: true },
      trustedOrigins: ["https://app.example.com"],
    });

    expect(JSON.parse(JSON.stringify(config.registration))).toEqual({
      publicSignUp: false,
      requireEmailVerification: true,
    });
  });

  it("keeps the email policy serializable", () => {
    const config = defineIdaasConfig({
      email: {
        requireEmailVerification: true,
        sendOnSignUp: true,
        resetPasswordEnabled: true,
      },
    });

    expect(JSON.parse(JSON.stringify(config.email))).toEqual({
      requireEmailVerification: true,
      sendOnSignUp: true,
      resetPasswordEnabled: true,
    });
  });

  it("allows personal data to be retained only when explicitly disabled", () => {
    const config = defineIdaasConfig({ audit: { redactPersonalData: false } });
    expect(config.audit.redactPersonalData).toBe(false);
  });

  it("rejects invalid values", () => {
    expect(() => defineIdaasConfig({ password: { minLength: 4 } as never })).toThrow();
    expect(() => defineIdaasConfig({ tables: { prefix: "9bad-" } as never })).toThrow();
    expect(() => defineIdaasConfig({ profile: "invalid" as never })).toThrow();
  });
});

describe("audit", () => {
  it("sanitizes sensitive fields", () => {
    expect(sanitize({ password: "x", email: "a@b.c", token: "t" })).toEqual({
      password: "[redacted]",
      token: "[redacted]",
      email: "a@b.c",
    });
  });

  it("redacts personal data recursively by default in database hooks", async () => {
    const sink = createMemoryAuditSink();
    const hooks = createAuditDatabaseHooks(sink, () => new Date(0));

    await hooks.user.create!.after!({
      email: "person@example.com",
      phone: "+8613000000000",
      sessionToken: "session-secret",
      nested: {
        phoneNumber: "+8613000000001",
        ipAddress: "203.0.113.10",
        userAgent: "Mozilla/5.0",
        username: "person",
        session: { sessionToken: "nested-session-secret" },
      },
    });

    const detail = sink.events[0].detail!;
    const nested = detail.nested as Record<string, unknown>;
    const session = nested.session as Record<string, unknown>;
    expect(detail.email).toBe("[redacted]");
    expect(detail.phone).toBe("[redacted]");
    expect(detail.sessionToken).toBe("[redacted]");
    expect(nested.phoneNumber).toBe("[redacted]");
    expect(nested.ipAddress).toBe("[redacted]");
    expect(nested.userAgent).toBe("[redacted]");
    expect(nested.username).toBe("[redacted]");
    expect(session.sessionToken).toBe("[redacted]");
  });

  it("retains personal data when explicitly disabled while redacting tokens", async () => {
    const sink = createMemoryAuditSink();
    const hooks = createAuditDatabaseHooks(sink, () => new Date(0), { redactPersonalData: false });

    await hooks.session.create!.after!({
      email: "retained@example.com",
      nested: { phoneNumber: "+8613000000002", userAgent: "retained-agent" },
      sessionToken: "session-secret",
    });

    const detail = sink.events[0].detail!;
    const nested = detail.nested as Record<string, unknown>;
    expect(detail.email).toBe("retained@example.com");
    expect(nested.phoneNumber).toBe("+8613000000002");
    expect(nested.userAgent).toBe("retained-agent");
    expect(detail.sessionToken).toBe("[redacted]");
  });

  it("recursively sanitizes nested values and handles errors and cycles", () => {
    const error = Object.assign(new Error("boom"), { accessToken: "access", self: undefined as unknown });
    error.self = error;
    const detail: Record<string, unknown> = {
      nested: { PaSsWoRd: "x", items: [{ ToKeN: "t" }] },
      error,
    };
    detail.self = detail;

    const result = sanitize(detail, { maxDepth: 6, maxLength: 32 });
    const nested = result.nested as Record<string, unknown>;
    const items = nested.items as Array<Record<string, unknown>>;
    const sanitizedError = result.error as Record<string, unknown>;

    expect(nested.PaSsWoRd).toBe("[redacted]");
    expect(items[0].ToKeN).toBe("[redacted]");
    expect(sanitizedError.accessToken).toBe("[redacted]");
    expect(sanitizedError.message).toBe("boom");
    expect(sanitizedError.self).toBe("[circular]");
    expect(result.self).toBe("[circular]");
    expect(() => JSON.stringify(result)).not.toThrow();
  });

  it("limits depth and value length", () => {
    let deep: Record<string, unknown> = { value: "end" };
    for (let index = 0; index < 5; index++) deep = { next: deep };

    const limited = sanitize(deep, { maxDepth: 2, maxLength: 12 });
    const long = sanitize({ value: "x".repeat(100) }, { maxLength: 12 });

    expect(JSON.stringify(limited)).toContain("[max depth]");
    expect((long.value as string).length).toBeLessThanOrEqual(12);
  });

  it("memory sink records events", () => {
    const sink = createMemoryAuditSink();
    const hooks = createAuditDatabaseHooks(sink, () => new Date(0));
    hooks.user.create!.after!({ userId: "u1", password: "x" });
    hooks.session.delete!.after!({ userId: "u2" });
    expect(sink.events).toHaveLength(2);
    expect(sink.events[0].event).toBe("user.created");
    expect(sink.events[0].detail!.password).toBe("[redacted]");
    expect(sink.events[1].event).toBe("session.revoked");
  });
});
