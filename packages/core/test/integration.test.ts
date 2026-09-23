import { describe, expect, it } from "vitest";
import { memoryAdapter } from "better-auth/adapters/memory";
import { createIdaas } from "../src/preset.js";
import { createMemoryAuditSink } from "../src/audit.js";
import { buildTableMap } from "../src/tables.js";

function memoryDb() {
  const tables = buildTableMap();
  const data: Record<string, unknown[]> = {};
  for (const name of Object.values(tables)) data[name] = [];
  return memoryAdapter(data);
}

describe("createIdaas smoke", () => {
  it("builds a working auth instance with mapped tables", async () => {
    const sink = createMemoryAuditSink();
    const auth = createIdaas({
      config: { appName: "TestApp" },
      database: memoryDb(),
      auditSink: sink,
    });

    const result = await auth.api.signUpEmail({
      body: {
        email: "user@example.com",
        password: "supersecret123",
        name: "Test User",
      },
    });

    expect(result.user.email).toBe("user@example.com");
    const userCreated = sink.events.find((e) => e.event === "user.created");
    expect(userCreated).toBeTruthy();
    expect(userCreated!.userId).toBeTruthy();
    expect(Object.entries(userCreated!.detail ?? {}).every(([k, v]) => v !== undefined ? k !== "password" || v === "[redacted]" : true)).toBe(true);
    expect(sink.events.some((e) => e.event === "session.created")).toBe(true);
  });

  it("rejects weak passwords per policy", async () => {
    const auth = createIdaas({
      config: { appName: "TestApp", password: { minLength: 12 } as never },
      database: memoryDb(),
    });
    await expect(
      auth.api.signUpEmail({
        body: { email: "u@example.com", password: "short", name: "U" },
      }),
    ).rejects.toThrow();
  });

  it("supports organization create and member flows with mapped tables", async () => {
    const sink = createMemoryAuditSink();
    const auth = createIdaas({
      config: { appName: "TestApp", features: { organization: true } },
      database: memoryDb(),
      auditSink: sink,
    });

    const signUp = await auth.api.signUpEmail({
      body: { email: "owner@example.com", password: "supersecret123", name: "Owner" },
    });
    const signIn = await auth.api.signInEmail({
      body: { email: "owner@example.com", password: "supersecret123" },
      returnHeaders: true,
    });
    const headers = new Headers({
      cookie: signIn.headers
        .getSetCookie()
        .map((c) => c.split(";")[0])
        .join("; "),
    });

    const org = await (auth.api as unknown as { createOrganization: (args: unknown) => Promise<{ name?: string; id?: string }> }).createOrganization({
      body: { name: "Acme", slug: "acme" },
      headers,
    });
    expect(org?.name).toBe("Acme");

    await auth.api.signUpEmail({
      body: { email: "member@example.com", password: "supersecret123", name: "Member" },
    });
    const invite = await (auth.api as unknown as { createInvitation: (args: unknown) => Promise<{ email?: string }> }).createInvitation({
      body: { email: "member@example.com", role: "member", organizationId: org!.id },
      headers,
    });
    expect(invite?.email).toBe("member@example.com");

    expect(signUp.user.email).toBe("owner@example.com");
  });
});
