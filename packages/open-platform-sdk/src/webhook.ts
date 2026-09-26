import { createHmac, timingSafeEqual } from "node:crypto";
import {
  OPEN_PLATFORM_WEBHOOK_SECRET_VERSION_HEADER,
  OPEN_PLATFORM_WEBHOOK_SIGNATURE_HEADER,
  OPEN_PLATFORM_WEBHOOK_SIGNATURE_VERSION,
  OPEN_PLATFORM_WEBHOOK_TIMESTAMP_HEADER,
  type OpenPlatformWebhookSignatureInput,
} from "./types.js";

export const OPEN_PLATFORM_WEBHOOK_SIGNATURE_ALGORITHM = "hmac-sha256" as const;
export const OPEN_PLATFORM_WEBHOOK_SIGNATURE_PREFIX = `${OPEN_PLATFORM_WEBHOOK_SIGNATURE_VERSION}=` as const;

export function createOpenPlatformWebhookSigningPayload(input: {
  readonly timestamp: string | number;
  readonly body: string | Uint8Array;
  readonly secretVersion: string | number;
}): string {
  return `${normalizeTimestamp(input.timestamp)}.${normalizeVersion(input.secretVersion)}.${bodyText(input.body)}`;
}

export function signOpenPlatformWebhook(input: OpenPlatformWebhookSignatureInput): string {
  const digest = createHmac("sha256", normalizeSecret(input.secret))
    .update(createOpenPlatformWebhookSigningPayload(input), "utf8")
    .digest("hex");
  return `${OPEN_PLATFORM_WEBHOOK_SIGNATURE_VERSION}=${digest}`;
}

export const createOpenPlatformWebhookSignature = signOpenPlatformWebhook;
export const signOpenPlatformWebhookPayload = signOpenPlatformWebhook;
export const createWebhookSignature = signOpenPlatformWebhook;

export function verifyOpenPlatformWebhookSignature(input: {
  readonly body: string | Uint8Array;
  readonly signature: string;
  readonly timestamp: string | number;
  readonly secretVersion: string | number;
  readonly secret: string;
  readonly toleranceSeconds?: number;
  readonly now?: Date;
}): boolean {
  try {
    const timestamp = normalizeTimestamp(input.timestamp);
    const tolerance = normalizeTolerance(input.toleranceSeconds ?? 300);
    const now = input.now ?? new Date();
    if (!(now instanceof Date) || !Number.isFinite(now.getTime())) return false;
    if (Math.abs(now.getTime() - Date.parse(timestamp)) > tolerance * 1000) return false;
    const expected = Buffer.from(signOpenPlatformWebhook({
      timestamp,
      body: input.body,
      secret: input.secret,
      secretVersion: input.secretVersion,
    }), "utf8");
    const candidates = parseCandidates(input.signature);
    let valid = false;
    for (const candidate of candidates) {
      const bytes = Buffer.from(candidate, "utf8");
      valid = (expected.length === bytes.length && timingSafeEqual(expected, bytes)) || valid;
    }
    return valid;
  } catch {
    return false;
  }
}

export const verifyWebhookSignature = verifyOpenPlatformWebhookSignature;
export const verifyOpenPlatformWebhook = verifyOpenPlatformWebhookSignature;
export const createOpenPlatformWebhookSigningString = createOpenPlatformWebhookSigningPayload;

export function verifyOpenPlatformWebhookHeaders(input: {
  readonly headers: Headers | Record<string, string | string[] | undefined>;
  readonly body: string | Uint8Array;
  readonly secret: string;
  readonly toleranceSeconds?: number;
  readonly now?: Date;
}): boolean {
  const signature = header(input.headers, OPEN_PLATFORM_WEBHOOK_SIGNATURE_HEADER);
  const timestamp = header(input.headers, OPEN_PLATFORM_WEBHOOK_TIMESTAMP_HEADER);
  const version = header(input.headers, OPEN_PLATFORM_WEBHOOK_SECRET_VERSION_HEADER);
  if (signature === undefined || timestamp === undefined || version === undefined) return false;
  return verifyOpenPlatformWebhookSignature({
    body: input.body,
    signature,
    timestamp,
    secretVersion: version,
    secret: input.secret,
    ...(input.toleranceSeconds === undefined ? {} : { toleranceSeconds: input.toleranceSeconds }),
    ...(input.now === undefined ? {} : { now: input.now }),
  });
}

function parseCandidates(value: unknown): string[] {
  if (typeof value !== "string" || value.length < 16 || value.length > 512 || /[\u0000-\u001f\u007f]/u.test(value)) return [];
  const output: string[] = [];
  for (const part of value.split(",")) {
    const item = part.trim();
    const separator = item.indexOf("=");
    if (separator >= 0 && item.slice(0, separator).trim().toLowerCase() !== OPEN_PLATFORM_WEBHOOK_SIGNATURE_VERSION) continue;
    const raw = separator < 0 ? item : item.slice(separator + 1);
    if (/^[a-f0-9]{64}$/u.test(raw)) output.push(`${OPEN_PLATFORM_WEBHOOK_SIGNATURE_VERSION}=${raw}`);
    if (/^[A-Za-z0-9_-]{43,44}$/u.test(raw)) {
      const decoded = Buffer.from(raw, "base64url").toString("hex");
      if (/^[a-f0-9]{64}$/u.test(decoded)) output.push(`${OPEN_PLATFORM_WEBHOOK_SIGNATURE_VERSION}=${decoded}`);
    }
  }
  return [...new Set(output)];
}

function header(
  headers: Headers | Record<string, string | string[] | undefined>,
  name: string,
): string | undefined {
  if (typeof Headers !== "undefined" && headers instanceof Headers) return headers.get(name) ?? undefined;
  const record = headers as Record<string, string | string[] | undefined>;
  const entry = Object.entries(record).find(([key]) => key.toLowerCase() === name.toLowerCase());
  const value = entry?.[1];
  return Array.isArray(value) ? value[0] : value;
}

function bodyText(value: string | Uint8Array): string {
  return typeof value === "string" ? value : Buffer.from(value).toString("utf8");
}

function normalizeTimestamp(value: string | number): string {
  if (typeof value === "number" && Number.isFinite(value)) return new Date(value).toISOString();
  if (typeof value !== "string" || !Number.isFinite(Date.parse(value))) throw new Error("Invalid webhook timestamp");
  return new Date(Date.parse(value)).toISOString();
}

function normalizeVersion(value: string | number): string {
  const normalized = typeof value === "number" ? String(value) : value.trim();
  if (!/^[1-9][0-9]{0,8}$/u.test(normalized)) throw new Error("Invalid webhook secret version");
  return String(Number(normalized));
}

function normalizeSecret(value: unknown): string {
  if (typeof value !== "string" || value.length < 1 || value.length > 4096 || /[\u0000-\u001f\u007f]/u.test(value)) throw new Error("Invalid webhook secret");
  return value;
}

function normalizeTolerance(value: unknown): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0 || value > 86_400) throw new Error("Invalid webhook timestamp tolerance");
  return value;
}
