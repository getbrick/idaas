import { createHash } from "node:crypto";
import {
  OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES,
  oidcAdapterError,
} from "./errors.js";
import type {
  OidcRevocationLookup,
  OidcRevocationPort,
  OidcRevocationReason,
} from "./contracts.js";

export class InMemoryOidcRevocationStore implements OidcRevocationPort {
  readonly productionReady = false;
  readonly readiness = () => true;
  private readonly revoked = new Set<string>();

  isRevoked(input: OidcRevocationLookup): boolean {
    assertLookup(input);
    return lookupKeys(input).some((key) => this.revoked.has(key));
  }

  revoke(input: OidcRevocationLookup, _reason: OidcRevocationReason): void {
    assertLookup(input);
    for (const key of lookupKeys(input)) this.revoked.add(key);
  }

  invalidate(): void {}

  clear(): void {
    this.revoked.clear();
  }

  size(): number {
    return this.revoked.size;
  }
}

export function createInMemoryOidcRevocationStore(): InMemoryOidcRevocationStore {
  return new InMemoryOidcRevocationStore();
}

export function oidcTokenFingerprint(value: string): string {
  if (typeof value !== "string" || value.length < 1 || value.length > 16_384) {
    throw oidcAdapterError(OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.INVALID_TOKEN);
  }
  return createHash("sha256").update(value, "utf8").digest("base64url");
}

export function oidcValueHash(value: string): string {
  if (typeof value !== "string" || value.length < 1 || value.length > 2048) {
    throw oidcAdapterError(OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.INVALID_TOKEN);
  }
  return createHash("sha256").update(value, "utf8").digest("base64url");
}

function lookupKeys(input: OidcRevocationLookup): string[] {
  const keys: string[] = [];
  const prefix = `${input.issuer}\u0000${input.tenantId}\u0000${input.clientId}\u0000`;
  if (input.tokenFingerprint !== undefined) keys.push(`${prefix}token:${input.tokenFingerprint}`);
  if (input.tokenIdHash !== undefined) keys.push(`${prefix}id:${input.tokenIdHash}`);
  if (input.sessionIdHash !== undefined) keys.push(`${prefix}session:${input.sessionIdHash}`);
  return keys;
}

function isHash(value: string): boolean {
  return value.length >= 43 && value.length <= 128 && /^[A-Za-z0-9_-]+$/u.test(value);
}

function assertLookup(input: OidcRevocationLookup): void {
  if (
    input === null ||
    typeof input !== "object" ||
    typeof input.issuer !== "string" ||
    input.issuer.length === 0 ||
    typeof input.tenantId !== "string" ||
    input.tenantId.length === 0 ||
    typeof input.clientId !== "string" ||
    input.clientId.length === 0 ||
    (
      input.tokenFingerprint === undefined &&
      input.tokenIdHash === undefined &&
      input.sessionIdHash === undefined
    ) ||
    (input.tokenFingerprint !== undefined && !isHash(input.tokenFingerprint)) ||
    (input.tokenIdHash !== undefined && !isHash(input.tokenIdHash)) ||
    (input.sessionIdHash !== undefined && !isHash(input.sessionIdHash))
  ) {
    throw oidcAdapterError(OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.CONFIGURATION);
  }
}
