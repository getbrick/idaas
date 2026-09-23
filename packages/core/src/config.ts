import { z } from "zod";

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
  baseURL: z.string().url().optional(),
  secret: z.string().optional(),
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
  rbac: rbacConfigSchema.default({}),
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
export type AuditSink = (event: AuditEvent) => void | Promise<void>;

export interface AuditEvent {
  event: string;
  userId?: string;
  detail?: Record<string, unknown>;
  occurredAt: string;
}

export function defineIdaasConfig(input: IdaasConfigInput): IdaasConfig {
  return idaasConfigSchema.parse(input ?? {});
}
