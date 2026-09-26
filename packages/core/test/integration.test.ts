import { describe, expect, it, vi } from "vitest";
import { memoryAdapter } from "better-auth/adapters/memory";
import { createIdaas, type EmailSenderPayload } from "../src/preset.js";
import { createMemoryAuditSink } from "../src/audit.js";
import { buildTableMap } from "../src/tables.js";

function memoryDb() {
  const tables = buildTableMap();
  const data: Record<string, unknown[]> = {};
  for (const name of Object.values(tables)) data[name] = [];
  return memoryAdapter(data);
}

function productionConfig() {
  return {
    profile: "production" as const,
    baseURL: "https://auth.example.com",
    secret: "s".repeat(32),
    registration: { publicSignUp: false, requireEmailVerification: true },
    trustedOrigins: ["https://app.example.com"],
  };
}

function emailHarness() {
  const sent: EmailSenderPayload[] = [];
  const auth = createIdaas({
    config: {
      appName: "EmailApp",
      baseURL: "https://auth.example.com",
      trustedOrigins: ["https://app.example.com"],
      registration: { publicSignUp: true },
      email: {
        requireEmailVerification: true,
        sendOnSignUp: true,
        resetPasswordEnabled: true,
      },
    },
    database: memoryDb(),
    emailSender: async (payload) => {
      sent.push(payload);
    },
  });
  return { auth, sent };
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
    expect(userCreated!.detail?.email).toBe("[redacted]");
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

describe("profile configuration", () => {
  it("maps registration policy to Better Auth", () => {
    const auth = createIdaas({
      config: {
        profile: "test",
        registration: { publicSignUp: false, requireEmailVerification: true },
        trustedOrigins: ["https://app.example.com"],
      },
      database: memoryDb(),
      emailSender: async () => {},
    });

    expect(auth.options.emailAndPassword?.disableSignUp).toBe(true);
    expect(auth.options.emailAndPassword?.requireEmailVerification).toBe(true);
    expect(auth.options.trustedOrigins).toEqual(["https://app.example.com"]);
  });

  it("rejects a weak production secret without exposing it", () => {
    const secret = "short-production-secret";
    let message = "";
    try {
      createIdaas({
        config: { ...productionConfig(), secret },
        database: memoryDb(),
      });
    } catch (error) {
      message = error instanceof Error ? error.message : String(error);
    }

    expect(message).toMatch(/production.*secret.*32/i);
    expect(message).not.toContain(secret);
  });

  it("rejects a non-HTTPS production baseURL", () => {
    expect(() =>
      createIdaas({
        config: { ...productionConfig(), baseURL: "http://auth.example.com" },
        database: memoryDb(),
      }),
    ).toThrow(/production.*HTTPS.*baseURL/i);
  });

  it("rejects public sign-up in production", () => {
    expect(() =>
      createIdaas({
        config: {
          ...productionConfig(),
          registration: { publicSignUp: true, requireEmailVerification: true },
        },
        database: memoryDb(),
      }),
    ).toThrow(/production.*publicSignUp/i);
  });

  it("rejects disabled email verification in production", () => {
    expect(() =>
      createIdaas({
        config: {
          ...productionConfig(),
          registration: { publicSignUp: false, requireEmailVerification: false },
        },
        database: memoryDb(),
      }),
    ).toThrow(/production.*requireEmailVerification/i);
  });

  it("rejects missing production trusted origins", () => {
    expect(() =>
      createIdaas({
        config: { ...productionConfig(), trustedOrigins: [] },
        database: memoryDb(),
      }),
    ).toThrow(/production.*trustedOrigins/i);
  });

  it("does not let extraOptions bypass production security options", () => {
    const auth = createIdaas({
      config: productionConfig(),
      database: memoryDb(),
      emailSender: async () => {},
      extraOptions: {
        secret: "extra-secret",
        baseURL: "http://extra.example.com",
        trustedOrigins: [],
        emailAndPassword: {
          enabled: true,
          disableSignUp: false,
          requireEmailVerification: false,
        },
        advanced: { disableOriginCheck: true },
      },
    });

    expect(auth.options.secret).toBe("s".repeat(32));
    expect(auth.options.baseURL).toBe("https://auth.example.com");
    expect(auth.options.emailAndPassword?.disableSignUp).toBe(true);
    expect(auth.options.emailAndPassword?.requireEmailVerification).toBe(true);
    expect(auth.options.trustedOrigins).toEqual(["https://app.example.com"]);
    expect(auth.options.advanced?.disableOriginCheck).toBe(false);
  });
});

describe("email verification and password reset", () => {
  it("requires an emailSender when verification is required while keeping defaults compatible", () => {
    expect(() =>
      createIdaas({
        config: {
          profile: "development",
          email: { requireEmailVerification: true },
        },
        database: memoryDb(),
      }),
    ).toThrow(/email\.requireEmailVerification.*emailSender/i);

    expect(() =>
      createIdaas({
        config: { profile: "development" },
        database: memoryDb(),
      }),
    ).not.toThrow();
    expect(() =>
      createIdaas({
        config: { email: { requireEmailVerification: false } },
        database: memoryDb(),
      }),
    ).not.toThrow();
  });

  it("does not install a mail transport by default", () => {
    const auth = createIdaas({
      config: { appName: "NoMail" },
      database: memoryDb(),
    });

    expect(auth.options.emailVerification?.sendVerificationEmail).toBeUndefined();
    expect(auth.options.emailAndPassword?.sendResetPassword).toBeUndefined();
  });

  it("rejects unsafe verification and reset URLs before invoking the sender", async () => {
    const sent: EmailSenderPayload[] = [];
    const auth = createIdaas({
      config: {
        baseURL: "https://auth.example.com",
        trustedOrigins: ["https://app.example.com"],
        email: {
          requireEmailVerification: true,
          sendOnSignUp: true,
          resetPasswordEnabled: true,
        },
      },
      database: memoryDb(),
      emailSender: async (payload) => {
        sent.push(payload);
      },
    });
    const verification = auth.options.emailVerification?.sendVerificationEmail;
    const reset = auth.options.emailAndPassword?.sendResetPassword;
    expect(verification).toBeDefined();
    expect(reset).toBeDefined();

    const unsafeURLs = [
      "javascript:alert(1)",
      "data:text/html,token=sensitive",
      "https://user:password@auth.example.com/verify-email?token=sensitive",
      "https://auth.example.com/verify-email?token=sensitive#fragment",
      "https://auth.example.com/verify-email?token=%0d%0asensitive",
      `https://auth.example.com/verify-email?token=${"x".repeat(5000)}`,
    ];

    for (const url of unsafeURLs) {
      await expect(verification!({
        user: { email: "safe@example.com" } as never,
        url,
      } as never)).rejects.toThrow("[getbrick-idaas] email delivery failed");
      await expect(reset!({
        user: { email: "safe@example.com" } as never,
        url,
      } as never)).rejects.toThrow("[getbrick-idaas] email delivery failed");
    }
    expect(sent).toHaveLength(0);

    await verification!({
      user: { email: "safe@example.com" } as never,
      url: "http://localhost:3000/verify-email?token=valid",
    } as never);
    await reset!({
      user: { email: "safe@example.com" } as never,
      url: "http://localhost:3000/reset-password/valid?callbackURL=https%3A%2F%2Fapp.example.com%2Freset%3Fdiscount%3D100%25",
    } as never);
    expect(sent.map((payload) => payload.type)).toEqual(["verification", "password-reset"]);
  });

  it("does not let extraOptions replace email senders or policies", async () => {
    const sentTypes: string[] = [];
    let overrideCalls = 0;
    const verificationOverride = async () => {
      overrideCalls += 1;
    };
    const resetOverride = async () => {
      overrideCalls += 1;
    };
    const auth = createIdaas({
      config: {
        baseURL: "https://auth.example.com",
        trustedOrigins: ["https://app.example.com"],
        email: {
          requireEmailVerification: true,
          sendOnSignUp: true,
          resetPasswordEnabled: true,
        },
      },
      database: memoryDb(),
      emailSender: async ({ type }) => {
        sentTypes.push(type);
      },
      extraOptions: {
        emailVerification: {
          sendVerificationEmail: verificationOverride,
          sendOnSignUp: false,
          sendOnSignIn: true,
          expiresIn: 1,
        },
        emailAndPassword: {
          enabled: false,
          disableSignUp: true,
          requireEmailVerification: false,
          sendResetPassword: resetOverride,
          resetPasswordTokenExpiresIn: 1,
        },
      },
    });
    const verification = auth.options.emailVerification?.sendVerificationEmail;
    const reset = auth.options.emailAndPassword?.sendResetPassword;

    expect(verification).toBeDefined();
    expect(reset).toBeDefined();
    expect(verification).not.toBe(verificationOverride);
    expect(reset).not.toBe(resetOverride);
    expect(auth.options.emailVerification?.sendOnSignUp).toBe(true);
    expect(auth.options.emailVerification?.sendOnSignIn).toBe(false);
    expect(auth.options.emailVerification?.expiresIn).toBe(3600);
    expect(auth.options.emailAndPassword?.enabled).toBe(true);
    expect(auth.options.emailAndPassword?.disableSignUp).toBe(false);
    expect(auth.options.emailAndPassword?.requireEmailVerification).toBe(true);
    expect(auth.options.emailAndPassword?.resetPasswordTokenExpiresIn).toBe(3600);

    await auth.api.signUpEmail({
      body: {
        email: "options@example.com",
        password: "supersecret123",
        name: "Options",
      },
    });
    await auth.api.requestPasswordReset({ body: { email: "options@example.com" } });

    expect(sentTypes).toEqual(["verification", "password-reset"]);
    expect(overrideCalls).toBe(0);
  });

  it("does not let extraOptions install a sender when none was configured", () => {
    const auth = createIdaas({
      config: { appName: "NoTransport" },
      database: memoryDb(),
      extraOptions: {
        emailVerification: { sendVerificationEmail: async () => {} },
        emailAndPassword: { enabled: true, sendResetPassword: async () => {} },
      },
    });

    expect(auth.options.emailVerification?.sendVerificationEmail).toBeUndefined();
    expect(auth.options.emailAndPassword?.sendResetPassword).toBeUndefined();
  });

  it("sends verification on sign-up and verifies before sign-in", async () => {
    const { auth, sent } = emailHarness();
    const email = "verify@example.com";
    const callbackURL = "https://app.example.com/verified?source=email";
    const signup = await auth.api.signUpEmail({
      body: {
        email,
        password: "supersecret123",
        name: "Verify",
        callbackURL,
      },
    });

    expect(signup.token).toBeNull();
    expect(sent).toHaveLength(1);
    expect(sent[0].to).toBe(email);
    expect(sent[0].type).toBe("verification");
    expect(Object.keys(sent[0]).sort()).toEqual(["expiresAt", "to", "type", "url"]);
    expect(sent[0].expiresAt).toBeInstanceOf(Date);
    expect(sent[0].expiresAt.getTime()).toBeGreaterThan(Date.now());

    const resend = await auth.api.sendVerificationEmail({
      body: { email, callbackURL },
    });
    expect(resend.status).toBe(true);
    expect(sent).toHaveLength(2);
    expect(sent[1].type).toBe("verification");

    const verificationURL = new URL(sent[1].url);
    const token = verificationURL.searchParams.get("token");
    expect(verificationURL.origin).toBe("https://auth.example.com");
    expect(verificationURL.searchParams.get("callbackURL")).toBe(callbackURL);
    expect(token).toBeTruthy();
    expect(verificationURL.search).not.toContain("password");

    await auth.api.verifyEmail({ query: { token: token! } });
    const signIn = await auth.api.signInEmail({
      body: { email, password: "supersecret123" },
    });
    expect(signIn.user.email).toBe(email);
  });

  it("sends a safe reset link and allows login with the new password", async () => {
    const { auth, sent } = emailHarness();
    const email = "reset@example.com";
    const redirectTo = "https://app.example.com/reset-password?source=email";
    await auth.api.signUpEmail({
      body: {
        email,
        password: "supersecret123",
        name: "Reset",
        callbackURL: "https://app.example.com/verified",
      },
    });
    const verificationURL = new URL(sent[0].url);
    await auth.api.verifyEmail({ query: { token: verificationURL.searchParams.get("token")! } });

    await auth.api.requestPasswordReset({
      body: { email, redirectTo },
    });

    expect(sent).toHaveLength(2);
    expect(sent[1].to).toBe(email);
    expect(sent[1].type).toBe("password-reset");
    expect(Object.keys(sent[1]).sort()).toEqual(["expiresAt", "to", "type", "url"]);
    const resetURL = new URL(sent[1].url);
    const resetToken = decodeURIComponent(resetURL.pathname.split("/").pop()!);
    expect(resetURL.origin).toBe("https://auth.example.com");
    expect(resetURL.searchParams.get("callbackURL")).toBe(redirectTo);
    expect(resetToken).toBeTruthy();
    expect(resetURL.search).not.toContain("supersecret123");

    const callbackResponse = await auth.handler(
      new Request(
        `https://auth.example.com/api/auth/reset-password/${resetToken}?callbackURL=${encodeURIComponent(redirectTo)}`,
      ),
    );
    expect(callbackResponse.status).toBe(302);
    const callbackLocation = new URL(callbackResponse.headers.get("location")!);
    expect(callbackLocation.origin).toBe("https://app.example.com");
    expect(callbackLocation.searchParams.get("token")).toBe(resetToken);

    await auth.api.resetPassword({
      body: { token: resetToken, newPassword: "newsecret456" },
    });
    await expect(
      auth.api.signInEmail({ body: { email, password: "supersecret123" } }),
    ).rejects.toThrow();
    await expect(
      auth.api.signInEmail({ body: { email, password: "newsecret456" } }),
    ).resolves.toMatchObject({ user: { email } });
  });

  it("rejects untrusted callback and redirect URLs before delivery", async () => {
    const { auth, sent } = emailHarness();
    const email = "safe@example.com";
    await auth.api.signUpEmail({
      body: {
        email,
        password: "supersecret123",
        name: "Safe",
        callbackURL: "https://app.example.com/verified",
      },
    });
    sent.length = 0;

    await expect(
      auth.api.sendVerificationEmail({
        body: { email, callbackURL: "https://evil.example/steal?token=sensitive-token" },
      }),
    ).rejects.toThrow(/callback URL/);
    await expect(
      auth.api.requestPasswordReset({
        body: { email, redirectTo: "https://evil.example/steal" },
      }),
    ).rejects.toThrow(/callback URL/);
    expect(sent).toHaveLength(0);
  });

  it("fails fast when a sender is required", () => {
    expect(() =>
      createIdaas({
        config: productionConfig(),
        database: memoryDb(),
      }),
    ).toThrow(/emailSender/);
    expect(() =>
      createIdaas({
        config: { email: { resetPasswordEnabled: true } },
        database: memoryDb(),
      }),
    ).toThrow(/emailSender/);
  });

  it("does not expose provider errors, tokens, or callback URLs in email failures", async () => {
    const providerError = "provider-raw-error";
    const verificationCallback = "https://app.example.com/verified?source=verification-secret";
    const resetCallback = "https://app.example.com/reset?source=reset-secret";
    const sentURLs: string[] = [];
    const logCalls: unknown[][] = [];
    const consoleError = vi.spyOn(console, "error").mockImplementation(() => {});
    const consoleWarn = vi.spyOn(console, "warn").mockImplementation(() => {});

    try {
      const auth = createIdaas({
        config: {
          baseURL: "https://auth.example.com",
          trustedOrigins: ["https://app.example.com"],
          email: {
            requireEmailVerification: true,
            resetPasswordEnabled: true,
          },
        },
        database: memoryDb(),
        emailSender: async ({ url }) => {
          sentURLs.push(url);
          throw new Error(`${providerError}: ${url}`);
        },
        extraOptions: {
          logger: {
            log: (...args: unknown[]) => {
              logCalls.push(args);
            },
          },
        },
      });
      const email = "failure@example.com";
      await auth.api.signUpEmail({
        body: {
          email,
          password: "supersecret123",
          name: "Failure",
        },
      });

      const verificationResponse = await auth.handler(
        new Request("https://auth.example.com/api/auth/send-verification-email", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ email, callbackURL: verificationCallback }),
        }),
      );
      const verificationBody = await verificationResponse.text();
      const resetResponse = await auth.handler(
        new Request("https://auth.example.com/api/auth/request-password-reset", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ email, redirectTo: resetCallback }),
        }),
      );
      const resetBody = await resetResponse.text();
      const unsafeVerificationCallback = "https://evil.example/steal?token=callback-secret";
      const unsafeResetCallback = "https://evil.example/reset?token=redirect-secret";
      const unsafeVerificationResponse = await auth.handler(
        new Request("https://auth.example.com/api/auth/send-verification-email", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ email, callbackURL: unsafeVerificationCallback }),
        }),
      );
      const unsafeVerificationBody = await unsafeVerificationResponse.text();
      const unsafeResetResponse = await auth.handler(
        new Request("https://auth.example.com/api/auth/request-password-reset", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ email, redirectTo: unsafeResetCallback }),
        }),
      );
      const unsafeResetBody = await unsafeResetResponse.text();
      const output = JSON.stringify({
        verificationBody,
        resetBody,
        unsafeVerificationBody,
        unsafeResetBody,
        logCalls,
        consoleError: consoleError.mock.calls,
        consoleWarn: consoleWarn.mock.calls,
      });

      expect(sentURLs).toHaveLength(2);
      for (const url of sentURLs) {
        const parsed = new URL(url);
        const token = parsed.searchParams.get("token") ?? decodeURIComponent(parsed.pathname.split("/").pop()!);
        expect(output).not.toContain(url);
        expect(output).not.toContain(token);
      }
      expect(output).not.toContain(providerError);
      expect(output).not.toContain(verificationCallback);
      expect(output).not.toContain(resetCallback);
      expect(output).not.toContain(unsafeVerificationCallback);
      expect(output).not.toContain(unsafeResetCallback);
      expect(output).not.toContain("callback-secret");
      expect(output).not.toContain("redirect-secret");
      expect(verificationResponse.status).toBeGreaterThanOrEqual(400);
      expect(resetResponse.status).toBe(200);
      expect(unsafeVerificationResponse.status).toBeGreaterThanOrEqual(400);
      expect(unsafeResetResponse.status).toBeGreaterThanOrEqual(400);
    } finally {
      consoleError.mockRestore();
      consoleWarn.mockRestore();
    }
  });

  it("does not expose sender errors or tokens", async () => {
    const token = "sensitive-email-token";
    const auth = createIdaas({
      config: {
        baseURL: "https://auth.example.com",
        trustedOrigins: ["https://app.example.com"],
        email: { sendOnSignUp: true },
      },
      database: memoryDb(),
      emailSender: async () => {
        throw new Error(`delivery failed for ${token}`);
      },
    });
    const callback = auth.options.emailVerification?.sendVerificationEmail;
    expect(callback).toBeDefined();

    let message = "";
    try {
      await callback!({
        user: { email: "error@example.com" } as never,
        url: `https://auth.example.com/api/auth/verify-email?token=${token}`,
        token,
      } as never);
    } catch (error) {
      message = error instanceof Error ? error.message : String(error);
    }
    expect(message).toBe("[getbrick-idaas] email delivery failed");
    expect(message).not.toContain(token);

    const errorLog = vi.spyOn(console, "error").mockImplementation(() => {});
    try {
      auth.options.logger?.log?.(
        "error",
        `Invalid callbackURL: https://evil.example/steal?token=${token}`,
        new Error(token),
      );
      expect(JSON.stringify(errorLog.mock.calls)).not.toContain(token);
    } finally {
      errorLog.mockRestore();
    }
  });
});

describe("preset hardening", () => {
  it("uses the configured audit sink when no runtime sink is supplied", async () => {
    const events: Array<{ event: string; detail?: Record<string, unknown> }> = [];
    const auth = createIdaas({
      config: {
        appName: "ConfiguredSink",
        audit: { sink: (event) => { events.push(event); } },
      },
      database: memoryDb(),
    });

    await auth.api.signUpEmail({
      body: { email: "configured@example.com", password: "supersecret123", name: "Configured" },
    });

    expect(events.some((event) => event.event === "user.created")).toBe(true);
  });

  it("preserves personal data only with an explicit audit opt-out", async () => {
    const sink = createMemoryAuditSink();
    const auth = createIdaas({
      config: { appName: "AuditOptOut", audit: { redactPersonalData: false } },
      database: memoryDb(),
      auditSink: sink,
    });

    await auth.api.signUpEmail({
      body: { email: "retained@example.com", password: "supersecret123", name: "Retained" },
    });

    const event = sink.events.find((entry) => entry.event === "user.created");
    expect(event?.detail?.email).toBe("retained@example.com");
  });

  it("does not send raw personal data to the default console sink", async () => {
    const info = vi.spyOn(console, "info").mockImplementation(() => {});
    try {
      const auth = createIdaas({
        config: { appName: "ConsoleAudit" },
        database: memoryDb(),
      });

      await auth.api.signUpEmail({
        body: { email: "console@example.com", password: "supersecret123", name: "Console" },
      });

      const output = JSON.stringify(info.mock.calls);
      expect(output).not.toContain("console@example.com");
      expect(output).not.toContain("supersecret123");
      expect(output).toContain("[redacted]");
    } finally {
      info.mockRestore();
    }
  });

  it("appends business plugins while retaining core plugins", () => {
    const businessPlugin = { id: "business" };
    const auth = createIdaas({
      config: { appName: "Plugins" },
      database: memoryDb(),
      extraOptions: { plugins: [businessPlugin] },
    });

    const plugins = auth.options.plugins ?? [];
    expect(plugins.some((plugin) => plugin.id === "business")).toBe(true);
    expect(plugins.some((plugin) => plugin.id === "admin")).toBe(true);
    expect(plugins.some((plugin) => plugin.id === "two-factor")).toBe(true);
  });

  it("merges business hooks without removing audit hooks", async () => {
    const calls: string[] = [];
    const sink = createMemoryAuditSink();
    const auth = createIdaas({
      config: { appName: "Hooks" },
      database: memoryDb(),
      auditSink: sink,
      extraOptions: {
        databaseHooks: {
          user: { create: { after: async () => { calls.push("business"); } } },
        },
      },
    });

    await auth.api.signUpEmail({
      body: { email: "hooks@example.com", password: "supersecret123", name: "Hooks" },
    });

    expect(sink.events.some((event) => event.event === "user.created")).toBe(true);
    expect(calls).toContain("business");
  });

  it("protects core security options while retaining business fields", () => {
    const database = memoryDb();
    const auth = createIdaas({
      config: {
        appName: "Protected",
        baseURL: "https://core.example",
        secret: "core-secret",
        password: { minLength: 12 },
        lockout: { windowSeconds: 30, maxAttempts: 4 },
      },
      database,
      extraOptions: {
        secret: "extra-secret",
        baseURL: "https://extra.example",
        database: memoryDb(),
        emailAndPassword: { enabled: false, minPasswordLength: 1, maxPasswordLength: 99 },
        session: { modelName: "extra_session", expiresIn: 1, storeSessionInDatabase: false },
        user: {
          modelName: "extra_user",
          additionalFields: { department: { type: "string", required: false } },
        },
        advanced: { cookiePrefix: "extra", disableCSRFCheck: true, disableOriginCheck: true },
        rateLimit: {
          enabled: false,
          window: 1,
          max: 1,
          customRules: {
            "/sign-in/*": { window: 1, max: 1 },
            "/business/*": { window: 2, max: 2 },
          },
        },
      },
    });

    expect(auth.options.database).toBe(database);
    expect(auth.options.secret).toBe("core-secret");
    expect(auth.options.baseURL).toBe("https://core.example");
    expect(auth.options.emailAndPassword?.enabled).toBe(true);
    expect(auth.options.emailAndPassword?.minPasswordLength).toBe(12);
    expect(auth.options.emailAndPassword?.maxPasswordLength).toBe(99);
    expect(auth.options.session?.modelName).toBe("gb_idaas_session");
    expect(auth.options.session?.expiresIn).toBe(7 * 86400);
    expect(auth.options.session?.storeSessionInDatabase).toBe(true);
    expect(auth.options.user?.modelName).toBe("gb_idaas_user");
    expect(auth.options.user?.additionalFields).toMatchObject({ department: { type: "string" } });
    expect(auth.options.advanced?.cookiePrefix).toBe("getbrick");
    expect(auth.options.advanced?.disableCSRFCheck).toBe(false);
    expect(auth.options.advanced?.disableOriginCheck).toBe(false);
    expect(auth.options.rateLimit?.enabled).toBe(true);
    expect(auth.options.rateLimit?.window).toBe(30);
    expect(auth.options.rateLimit?.max).toBe(4);
    expect(auth.options.rateLimit?.customRules).toMatchObject({
      "/sign-in/*": { window: 30, max: 4 },
      "/business/*": { window: 2, max: 2 },
    });
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

