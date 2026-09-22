import type { AuditEvent, AuditSink } from "./config.js";

export type DatabaseHooks = {
  [model: string]: {
    create?: { before?: (data: any) => Promise<any>; after?: (data: any) => Promise<void> };
    update?: { before?: (data: any) => Promise<any>; after?: (data: any) => Promise<void> };
    delete?: { before?: (data: any) => Promise<any>; after?: (data: any) => Promise<void> };
  };
};

export const SENSITIVE_FIELDS = new Set([
  "password",
  "hash",
  "secret",
  "token",
  "twoFactorSecret",
  "mfa_secret",
]);

export function sanitize(detail: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(detail)) {
    out[key] = SENSITIVE_FIELDS.has(key.toLowerCase()) ? "[redacted]" : value;
  }
  return out;
}

export function createMemoryAuditSink(): AuditSink & { events: AuditEvent[] } {
  const events: AuditEvent[] = [];
  const sink = (event: AuditEvent) => {
    events.push(event);
  };
  return Object.assign(sink, { events });
}

export function createAuditDatabaseHooks(
  sink: AuditSink,
  now: () => Date = () => new Date(),
): DatabaseHooks {
  const emit = async (event: string, data: Record<string, unknown> | undefined) => {
    const rawUserId = data?.userId ?? data?.id;
    const userId = typeof rawUserId === "string" ? rawUserId : undefined;
    await sink({
      event,
      userId,
      detail: sanitize(data ?? {}),
      occurredAt: now().toISOString(),
    });
  };
  return {
    user: {
      create: { after: (data) => emit("user.created", data) },
      update: { after: (data) => emit("user.updated", data) },
      delete: { after: (data) => emit("user.deleted", data) },
    },
    session: {
      create: { after: (data) => emit("session.created", data) },
      delete: { after: (data) => emit("session.revoked", data) },
    },
  };
}
