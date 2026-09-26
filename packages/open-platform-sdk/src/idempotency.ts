import { randomUUID } from "node:crypto";

const DEFAULT_PREFIX = "op";
const MAX_IDEMPOTENCY_KEY_LENGTH = 128;

export function generateIdempotencyKey(prefix = DEFAULT_PREFIX): string {
  const normalizedPrefix = normalizePrefix(prefix);
  const key = `${normalizedPrefix}-${randomUUID()}`;
  if (key.length > MAX_IDEMPOTENCY_KEY_LENGTH) {
    throw new Error("Generated idempotency key is too long");
  }
  return key;
}

export const createIdempotencyKey = generateIdempotencyKey;
export const newIdempotencyKey = generateIdempotencyKey;

export function assertIdempotencyKey(value: unknown): string {
  if (typeof value !== "string") {
    throw new Error("Idempotency key is invalid");
  }
  const normalized = value.trim();
  if (
    normalized.length < 1 ||
    normalized.length > MAX_IDEMPOTENCY_KEY_LENGTH ||
    /[\u0000-\u001f\u007f]/u.test(normalized)
  ) {
    throw new Error("Idempotency key is invalid");
  }
  return normalized;
}

function normalizePrefix(value: string): string {
  if (typeof value !== "string") {
    throw new Error("Idempotency key prefix is invalid");
  }
  const normalized = value.trim();
  if (
    normalized.length < 1 ||
    normalized.length > 32 ||
    !/^[A-Za-z0-9][A-Za-z0-9._:-]*$/u.test(normalized)
  ) {
    throw new Error("Idempotency key prefix is invalid");
  }
  return normalized;
}
