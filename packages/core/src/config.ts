import { z } from "zod";
import { oidcConfigSchema, validateOidcConfig } from "./oidc/config.js";

export const profileSchema = z.enum(["development", "test", "staging", "production"]);

export const registrationPolicySchema = z.object({
  publicSignUp: z.boolean().default(true),
  requireEmailVerification: z.boolean().default(false),
});

export const emailPolicySchema = z.object({
  requireEmailVerification: z.boolean().default(false),
  sendOnSignUp: z.boolean().default(false),
  resetPasswordEnabled: z.boolean().default(false),
});

export const PRODUCTION_MIN_SECRET_LENGTH = 32;

export const sessionPolicySchema = z.object({
  expiresInDays: z.number().int().min(1).max(90).default(7),
  refreshIntervalDays: z.number().int().min(1).default(1),
  storeInDatabase: z.boolean().default(true),
});

export const passwordPolicySchema = z.object({
  minLength: z.number().int().min(8).max(128).default(8),
  maxConcurrentSessions: z.number().int().min(1).default(5),
});

export const lockoutPolicySchema = z.object({
  maxAttempts: z.number().int().min(1).default(10),
  windowSeconds: z.number().int().min(10).default(600),
});

export const auditConfigSchema = z.object({
  enabled: z.boolean().default(true),
  sink: z.custom<AuditSink>().optional(),
  redactPersonalData: z.boolean().default(true),
});

export const phoneNumberConfigSchema = z.object({
  otpLength: z.number().int().min(4).max(8).default(6),
  otpExpiresInSeconds: z.number().int().min(60).max(3600).default(300),
  /** sign in requires a verified phone number */
  requireVerification: z.boolean().default(false),
  /** create a user automatically when an unknown phone number verifies */
  signUpOnVerification: z.boolean().default(false),
});

export const rbacRoleSchema = z.object({
  extends: z.array(z.string()).default([]),
  permissions: z.array(z.string()).default([]),
});

export const rbacConfigSchema = z.object({
  roles: z.record(z.string(), rbacRoleSchema).default({}),
});

export const idaasConfigSchema = z.object({
  appName: z.string().min(1).default("Getbrick"),
  profile: profileSchema.default("development"),
  baseURL: z.string().url().optional(),
  secret: z.string().optional(),
  trustedOrigins: z.array(z.string().min(1)).default([]),
  tables: z
    .object({
      prefix: z.string().regex(/^[a-z][a-z0-9_]*$/).default("gb_idaas_"),
      overrides: z.record(z.string(), z.string()).default({}),
    })
    .default({}),
  session: sessionPolicySchema.default({}),
  password: passwordPolicySchema.default({}),
  lockout: lockoutPolicySchema.default({}),
  audit: auditConfigSchema.default({}),
  registration: registrationPolicySchema.default({}),
  email: emailPolicySchema.default({}),
  phoneNumber: phoneNumberConfigSchema.default({}),
  rbac: rbacConfigSchema.default({}),
  oidc: oidcConfigSchema,
  features: z
    .object({
      twoFactor: z.boolean().default(true),
      admin: z.boolean().default(true),
      organization: z.boolean().default(false),
      phoneNumber: z.boolean().default(false),
    })
    .default({}),
});

export type IdaasConfigInput = z.input<typeof idaasConfigSchema>;
export type IdaasConfig = z.output<typeof idaasConfigSchema>;
export type IdaasProfile = z.infer<typeof profileSchema>;
export type RegistrationPolicy = z.infer<typeof registrationPolicySchema>;
export type EmailPolicy = z.infer<typeof emailPolicySchema>;
export type AuditSink = (event: AuditEvent) => void | Promise<void>;

export interface AuditEvent {
  event: string;
  userId?: string;
  detail?: Record<string, unknown>;
  occurredAt: string;
}

export function defineIdaasConfig(input: IdaasConfigInput): IdaasConfig {
  const rawInput = input ?? {};
  const config = idaasConfigSchema.parse(rawInput);
  if (rawInput.profile === undefined && process.env.NODE_ENV === "production") {
    config.profile = "production";
  }
  if (
    rawInput.email?.requireEmailVerification === undefined &&
    rawInput.registration?.requireEmailVerification !== undefined
  ) {
    config.email.requireEmailVerification = rawInput.registration.requireEmailVerification;
  }
  return config;
}

export function validateIdaasConfig(config: IdaasConfig): void {
  if (config.baseURL !== undefined && !isSafeBaseURL(config.baseURL)) {
    throw new Error(
      "[getbrick-idaas] baseURL must be an absolute HTTP(S) URL without credentials, query, or fragment",
    );
  }
  validateOidcConfig(config.oidc, config.profile);
  if (config.profile !== "production") return;
  if (typeof config.secret !== "string" || config.secret.trim().length < PRODUCTION_MIN_SECRET_LENGTH) {
    throw new Error(
      "[getbrick-idaas] production requires secret with at least 32 characters",
    );
  }
  if (!isHttpsUrl(config.baseURL)) {
    throw new Error("[getbrick-idaas] production requires an HTTPS baseURL");
  }
  if (config.registration.publicSignUp) {
    throw new Error("[getbrick-idaas] production requires registration.publicSignUp=false");
  }
  if (!config.email.requireEmailVerification) {
    throw new Error(
      "[getbrick-idaas] production requires email.requireEmailVerification=true",
    );
  }
  if (config.trustedOrigins.length === 0) {
    throw new Error(
      "[getbrick-idaas] production requires at least one trustedOrigins entry",
    );
  }
}

function isHttpsUrl(value: string | undefined): boolean {
  if (!value) return false;
  try {
    const parsed = new URL(value);
    return parsed.protocol === "https:" && isSafeBaseURL(value);
  } catch {
    return false;
  }
}

function isSafeBaseURL(value: string): boolean {
  try {
    const parsed = new URL(value);
    return (
      (parsed.protocol === "http:" || parsed.protocol === "https:") &&
      parsed.username === "" &&
      parsed.password === "" &&
      parsed.search === "" &&
      parsed.hash === "" &&
      !/[\u0000-\u001f\u007f]/u.test(value) &&
      !value.includes("\\")
    );
  } catch {
    return false;
  }
}
