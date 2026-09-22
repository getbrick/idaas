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
    expect(config.features.twoFactor).toBe(true);
  });

  it("rejects invalid values", () => {
    expect(() => defineIdaasConfig({ password: { minLength: 4 } as never })).toThrow();
    expect(() => defineIdaasConfig({ tables: { prefix: "9bad-" } as never })).toThrow();
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
