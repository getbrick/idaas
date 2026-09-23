import { betterAuth, type BetterAuthOptions } from "better-auth";
import { admin, organization, twoFactor } from "better-auth/plugins";
import { phoneNumber } from "better-auth/plugins/phone-number";
import type { IdaasConfig, IdaasConfigInput } from "./config.js";
import { defineIdaasConfig } from "./config.js";
import { buildTableMap } from "./tables.js";
import { createAuditDatabaseHooks, type DatabaseHooks } from "./audit.js";

export interface CreateIdaasInput {
  config: IdaasConfigInput;
  database: BetterAuthOptions["database"];
  auditSink?: (event: { event: string; userId?: string; detail?: Record<string, unknown>; occurredAt: string }) => void | Promise<void>;
  extraOptions?: Partial<BetterAuthOptions>;
  smsSender?: (payload: { phone: string; code: string }) => Promise<void>;
  phoneValidator?: (phone: string) => boolean | Promise<boolean>;
}

export function createIdaas(input: CreateIdaasInput) {
  const config: IdaasConfig = defineIdaasConfig(input.config);
  const tables = buildTableMap({
    prefix: config.tables.prefix,
    overrides: config.tables.overrides,
  });

  const auditHooks: DatabaseHooks = config.audit.enabled
    ? createAuditDatabaseHooks(input.auditSink ?? defaultAuditSink)
    : {};

  const options: Partial<BetterAuthOptions> = {
    appName: config.appName,
    baseURL: config.baseURL,
    secret: config.secret,
    database: input.database,
    emailAndPassword: {
      enabled: true,
      minPasswordLength: config.password.minLength,
      disableSignUp: false,
      requireEmailVerification: false,
    },
    session: {
      modelName: tables.session,
      expiresIn: config.session.expiresInDays * 86400,
      updateAge: config.session.refreshIntervalDays * 86400,
      storeSessionInDatabase: config.session.storeInDatabase,
    },
    user: {
      modelName: tables.user,
      additionalFields: config.features.phoneNumber
        ? {
            phoneNumber: { type: "string", required: false, unique: true, returned: true },
            phoneNumberVerified: { type: "boolean", required: false, returned: true, input: false },
          }
        : undefined,
    },
    account: {
      modelName: tables.account,
    },
    verification: {
      modelName: tables.verification,
    },
    advanced: {
      cookiePrefix: "getbrick",
    },
    databaseHooks: auditHooks as BetterAuthOptions["databaseHooks"],
    rateLimit: {
      enabled: true,
      window: config.lockout.windowSeconds,
      max: config.lockout.maxAttempts,
      customRules: {
        "/sign-up/*": { window: config.lockout.windowSeconds, max: config.lockout.maxAttempts },
        "/sign-in/*": { window: config.lockout.windowSeconds, max: config.lockout.maxAttempts },
        "/change-password": { window: config.lockout.windowSeconds, max: config.lockout.maxAttempts },
        "/change-email": { window: config.lockout.windowSeconds, max: config.lockout.maxAttempts },
      },
    },
  };

  const merged = deepMerge(options, input.extraOptions ?? {}) as BetterAuthOptions;

  const plugins: any[] = [];
  if (config.features.admin) {
    plugins.push(admin());
  }
  if (config.features.twoFactor) {
    plugins.push(twoFactor({ twoFactorTable: tables.twoFactor }));
  }
  if (config.features.phoneNumber) {
    if (!input.smsSender) {
      throw new Error(
        "[getbrick-idaas] features.phoneNumber requires an smsSender callback: ({ phone, code }) => Promise<void>",
      );
    }
    plugins.push(
      phoneNumber({
        otpLength: config.phoneNumber.otpLength,
        expiresIn: config.phoneNumber.otpExpiresInSeconds,
        requireVerification: config.phoneNumber.requireVerification,
        sendOTP: ({ phoneNumber: phone, code }) => input.smsSender!({ phone, code }),
        sendPasswordResetOTP: ({ phoneNumber: phone, code }) => input.smsSender!({ phone, code }),
        phoneNumberValidator: input.phoneValidator,
        ...(config.phoneNumber.signUpOnVerification
          ? { signUpOnVerification: { getTempEmail: (phone: string) => `phone-${phone}@users.getbrick.local` } }
          : {}),
      }),
    );
  }
  if (config.features.organization) {
    plugins.push(
      organization({
        schema: {
          organization: { modelName: tables.organization },
          member: { modelName: tables.member },
          invitation: { modelName: tables.invitation },
        },
      }),
    );
  }
  if (plugins.length > 0) {
    (merged as BetterAuthOptions).plugins = plugins;
  }

  return betterAuth(merged);
}

function defaultAuditSink(event: { event: string; userId?: string; detail?: Record<string, unknown> }): void {
  console.info(`[getbrick-idaas] ${event.event}`, event);
}

function deepMerge<T>(base: T, override: Record<string, unknown>): T {
  const out: Record<string, unknown> = { ...(base as Record<string, unknown>) };
  for (const [key, value] of Object.entries(override)) {
    const current = out[key];
    if (
      value !== null &&
      typeof value === "object" &&
      !Array.isArray(value) &&
      current !== null &&
      typeof current === "object" &&
      !Array.isArray(current)
    ) {
      out[key] = deepMerge(current as Record<string, unknown>, value as Record<string, unknown>);
    } else {
      out[key] = value;
    }
  }
  return out as T;
}
