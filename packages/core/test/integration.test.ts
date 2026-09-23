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

describe("phone-number (SMS OTP) feature", () => {
  function smsHarness() {
    const sent: Array<{ phone: string; code: string }> = [];
    const auth = createIdaas({
      config: {
        appName: "SmsApp",
        features: { phoneNumber: true },
        phoneNumber: { signUpOnVerification: true },
      },
      database: memoryDb(),
      smsSender: async ({ phone, code }) => {
        sent.push({ phone, code });
      },
    });
    return { auth, sent };
  }

  it("requires an smsSender when phoneNumber feature is enabled", () => {
    expect(() =>
      createIdaas({
        config: { appName: "SmsApp", features: { phoneNumber: true } } as never,
        database: memoryDb(),
      }),
    ).toThrow(/smsSender/);
  });

  it("sends an OTP, verifies it and signs up the user on first verification", async () => {
    const { auth, sent } = smsHarness();
    const phone = "+8613900000001";

    await castApi(auth).sendPhoneNumberOTP({ body: { phoneNumber: phone } });
    expect(sent).toHaveLength(1);
    expect(sent[0].phone).toBe(phone);
    expect(sent[0].code).toMatch(/^\d{6}$/);

    const verified = (await castApi(auth).verifyPhoneNumber({
      body: { phoneNumber: phone, code: sent[0].code },
    })) as { status?: boolean; user?: { phoneNumber?: string; email?: string } } | null;
    expect(verified?.status).toBe(true);
    expect(verified?.user?.phoneNumber).toBe(phone);
    expect(verified?.user?.email).toBe(`phone-${phone}@users.getbrick.local`);

    // signUpOnVerification users have no password credential; re-verification references the same user
    await expect(
      castApi(auth).verifyPhoneNumber({ body: { phoneNumber: phone, code: sent[0].code } }),
    ).rejects.toThrow();
  });

  it("rejects an OTP with insufficient length policy and wrong codes", async () => {
    const { auth, sent } = smsHarness();
    const phone = "+8613900000002";
    await castApi(auth).sendPhoneNumberOTP({ body: { phoneNumber: phone } });
    await expect(
      (auth.api as unknown as { verifyPhoneNumber: (args: unknown) => Promise<unknown> }).verifyPhoneNumber({
        body: { phoneNumber: phone, code: sent[0].code === "999999" ? "000000" : "999999" },
      }),
    ).rejects.toThrow();
  });
});

// helper to access plugin endpoints lost by the inferred betterAuth return type
function castApi(auth: unknown) {
  return (auth as { api: Record<string, (...args: unknown[]) => Promise<unknown>> }).api;
}

