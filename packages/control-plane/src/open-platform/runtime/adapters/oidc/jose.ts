import { isIP } from "node:net";
import { validateOidcClientJwks } from "@getbrick/idaas-core";
import {
  OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES,
  oidcAdapterError,
} from "./errors.js";
import { normalizeIssuer, normalizeOidcMode } from "./shared.js";
import type {
  OidcBearerJwtVerifierPort,
  OidcJoseApi,
  OidcJoseVerifierOptions,
  OidcJwtVerificationInput,
  OidcJwtVerificationResult,
  OidcRuntimeMode,
  OidcRuntimeSigningAlgorithm,
  OidcServiceClientJwtVerifierPort,
} from "./contracts.js";

const DEFAULT_JWKS_CACHE_TTL_MS = 300_000;
const MAX_JWKS_CACHE_TTL_MS = 3_600_000;
const DEFAULT_MAX_JWKS_CACHE_ENTRIES = 32;
const MAX_JWKS_CACHE_ENTRIES = 256;
const DEFAULT_MAX_UNKNOWN_KIDS = 256;
const MAX_UNKNOWN_KIDS = 4_096;
const DEFAULT_RESOLVER_REFRESH_INTERVAL_MS = 30_000;
const MAX_RESOLVER_REFRESH_INTERVAL_MS = 3_600_000;
const MAX_JWKS_KEYS = 32;
const MAX_TOKEN_LENGTH = 16_384;
const PRIVATE_JWK_FIELDS = ["d", "p", "q", "dp", "dq", "qi", "oth", "k"];
const BLOCKED_HOST_SUFFIXES = [
  ".localhost",
  ".local",
  ".internal",
  ".intranet",
  ".lan",
  ".home",
  ".home.arpa",
  ".onion",
  ".invalid",
];
const METADATA_HOSTS = new Set([
  "metadata",
  "metadata.google.internal",
  "instance-data",
  "instance-data.ec2.internal",
]);
const LOOPBACK_HOSTS = new Set([
  "localhost",
  "localhost.localdomain",
  "ip6-localhost",
  "ip6-loopback",
]);

interface JoseIssuerCacheEntry {
  readonly issuer: string;
  readonly key: unknown;
  readonly keyIds: ReadonlySet<string>;
  readonly allowsUnkiddedKey: boolean;
  readonly expiresAt: number;
  readonly lastRefreshAt: number;
  readonly refreshed: boolean;
  readonly unknownKids: Map<string, number>;
}

interface JoseKeyResolution {
  readonly entry: JoseIssuerCacheEntry;
  readonly key: unknown;
  readonly known: boolean;
}

interface JwksSecurityPolicy {
  readonly mode: OidcRuntimeMode;
  readonly remote: boolean;
  readonly endpoint?: URL;
  readonly issuerAllowlist: ReadonlySet<string>;
  readonly trustedHosts: ReadonlySet<string>;
  readonly resolveHost?: (hostname: string) => Promise<readonly string[]> | readonly string[];
}

export interface OidcJwksEndpointPolicyOptions {
  readonly mode?: OidcRuntimeMode;
  readonly trustedHosts?: readonly string[];
}

export function createOidcJoseBearerJwtVerifier(
  options: OidcJoseVerifierOptions,
): OidcBearerJwtVerifierPort {
  return createJoseVerifier(options, "bearer") as OidcBearerJwtVerifierPort;
}

export function createOidcJoseServiceClientJwtVerifier(
  options: OidcJoseVerifierOptions,
): OidcServiceClientJwtVerifierPort {
  return createJoseVerifier(options, "serviceClient") as OidcServiceClientJwtVerifierPort;
}

export function createOidcJoseJwtVerifier(
  options: OidcJoseVerifierOptions,
): OidcBearerJwtVerifierPort | OidcServiceClientJwtVerifierPort {
  return createJoseVerifier(options, options.kind ?? "bearer");
}

export function assertSafeOidcJwksEndpoint(
  value: unknown,
  options: OidcJwksEndpointPolicyOptions = {},
): URL {
  const mode = normalizeOidcMode(options.mode);
  const trustedHosts = normalizeHostAllowlist(options.trustedHosts ?? []);
  const endpoint = parseJwksEndpoint(value, mode);
  if (trustedHosts.size === 0 || !trustedHosts.has(normalizeHost(endpoint.hostname))) {
    throw oidcAdapterError(OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.CONFIGURATION);
  }
  assertSafeHostname(normalizeHost(endpoint.hostname));
  return endpoint;
}

export function isUnsafeOidcJwksAddress(value: string): boolean {
  const address = value.trim().toLowerCase().split("%", 1)[0] ?? "";
  const kind = isIP(address);
  if (kind === 4) return isUnsafeIpv4(address);
  if (kind === 6) return isUnsafeIpv6(address);
  return true;
}

function createJoseVerifier(
  options: OidcJoseVerifierOptions,
  kind: "bearer" | "serviceClient",
): OidcBearerJwtVerifierPort | OidcServiceClientJwtVerifierPort {
  assertJoseOptions(options);
  const effectiveMode: OidcRuntimeMode =
    options.mode ?? (options.productionReady === true ? "production" : "test");
  const security = createJwksSecurityPolicy({ ...options, mode: effectiveMode }, kind);
  const clock = options.clock ?? (() => new Date());
  const cacheTtlMs = normalizeLimit(
    options.cacheTtlMs,
    DEFAULT_JWKS_CACHE_TTL_MS,
    0,
    MAX_JWKS_CACHE_TTL_MS,
  );
  const maxCacheEntries = normalizeLimit(
    options.maxJwksCacheEntries,
    DEFAULT_MAX_JWKS_CACHE_ENTRIES,
    1,
    MAX_JWKS_CACHE_ENTRIES,
  );
  const maxUnknownKids = normalizeLimit(
    options.maxUnknownKids,
    DEFAULT_MAX_UNKNOWN_KIDS,
    1,
    MAX_UNKNOWN_KIDS,
  );
  const resolverRefreshIntervalMs = normalizeLimit(
    options.resolverRefreshIntervalMs,
    DEFAULT_RESOLVER_REFRESH_INTERVAL_MS,
    1,
    MAX_RESOLVER_REFRESH_INTERVAL_MS,
  );
  const cache = new Map<string, JoseIssuerCacheEntry>();
  const resolverAttempts = new Map<string, number>();
  const productionReady =
    options.productionReady === true &&
    options.jwks.productionReady === true &&
    (security.mode !== "production" || options.jwks.readiness !== undefined);

  const getEntry = (issuer: string): JoseIssuerCacheEntry | undefined => {
    const entry = cache.get(issuer);
    if (entry !== undefined) {
      cache.delete(issuer);
      cache.set(issuer, entry);
    }
    return entry;
  };

  const setEntry = (entry: JoseIssuerCacheEntry): void => {
    cache.delete(entry.issuer);
    while (cache.size >= maxCacheEntries) {
      const oldest = cache.keys().next().value;
      if (oldest === undefined) break;
      cache.delete(oldest);
    }
    cache.set(entry.issuer, entry);
  };

  const canRefresh = (entry: JoseIssuerCacheEntry, now: number): boolean =>
    !entry.refreshed || now - entry.lastRefreshAt >= resolverRefreshIntervalMs;

  const canAttemptResolver = (issuer: string, now: number): boolean => {
    const previous = resolverAttempts.get(issuer);
    if (previous !== undefined && now - previous < resolverRefreshIntervalMs) {
      return false;
    }
    resolverAttempts.delete(issuer);
    while (resolverAttempts.size >= maxCacheEntries) {
      const oldest = resolverAttempts.keys().next().value;
      if (oldest === undefined) break;
      resolverAttempts.delete(oldest);
    }
    resolverAttempts.set(issuer, now);
    return true;
  };

  const cacheUnknownKid = (
    entry: JoseIssuerCacheEntry,
    keyId: string,
    now: number,
  ): void => {
    entry.unknownKids.delete(keyId);
    while (entry.unknownKids.size >= maxUnknownKids) {
      const oldest = entry.unknownKids.keys().next().value;
      if (oldest === undefined) break;
      entry.unknownKids.delete(oldest);
    }
    const unknownTtl = Math.max(
      resolverRefreshIntervalMs,
      Math.min(cacheTtlMs || resolverRefreshIntervalMs, MAX_JWKS_CACHE_TTL_MS),
    );
    entry.unknownKids.set(keyId, now + unknownTtl);
  };

  const resolveJwks = async (
    input: OidcJwtVerificationInput,
    keyId: string | undefined,
  ): Promise<JoseIssuerCacheEntry> => {
    const now = nowMilliseconds(clock);
    if (!canAttemptResolver(input.issuer, now)) {
      throw oidcAdapterError(
        OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.VERIFIER_UNAVAILABLE,
        true,
      );
    }
    await assertIssuerAllowed(security, input.issuer, kind);
    if (security.remote && security.endpoint !== undefined) {
      await assertRemoteHost(security, normalizeHost(security.endpoint.hostname));
    }
    let jwks: unknown;
    try {
      jwks = await options.jwks.resolve({
        issuer: input.issuer,
        ...(keyId === undefined ? {} : { keyId }),
      });
    } catch {
      throw oidcAdapterError(
        OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.VERIFIER_UNAVAILABLE,
        true,
      );
    }
    let validatedJwks: unknown;
    try {
      validatedJwks = validateOidcClientJwks(jwks);
    } catch {
      throw oidcAdapterError(
        OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.VERIFIER_UNAVAILABLE,
        true,
      );
    }
    assertPublicJwks(validatedJwks);
    let key: unknown;
    try {
      key = options.jose.createLocalJWKSet(validatedJwks);
    } catch {
      throw oidcAdapterError(
        OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.VERIFIER_UNAVAILABLE,
        true,
      );
    }
    const keyIds = new Set<string>();
    let allowsUnkiddedKey = false;
    for (const value of (validatedJwks as { keys: Record<string, unknown>[] }).keys) {
      if (typeof value.kid === "string") keyIds.add(value.kid);
      else allowsUnkiddedKey = true;
    }
    const previous = getEntry(input.issuer);
    const unknownKids = new Map<string, number>();
    if (previous !== undefined) {
      for (const [unknownKeyId, expiresAt] of previous.unknownKids) {
        if (expiresAt > now) unknownKids.set(unknownKeyId, expiresAt);
      }
    }
    if (keyId !== undefined && !keyIds.has(keyId)) {
      cacheUnknownKid(
        {
          issuer: input.issuer,
          key: undefined,
          keyIds: new Set<string>(),
          allowsUnkiddedKey: false,
          expiresAt: now,
          lastRefreshAt: now,
          refreshed: true,
          unknownKids,
        },
        keyId,
        now,
      );
    } else {
      unknownKids.delete(keyId ?? "");
    }
    const entry: JoseIssuerCacheEntry = {
      issuer: input.issuer,
      key,
      keyIds,
      allowsUnkiddedKey,
      expiresAt: now + cacheTtlMs,
      lastRefreshAt: now,
      refreshed: true,
      unknownKids,
    };
    setEntry(entry);
    return entry;
  };

  const getKey = async (
    input: OidcJwtVerificationInput,
    keyId: string | undefined,
  ): Promise<JoseKeyResolution> => {
    const now = nowMilliseconds(clock);
    let entry = getEntry(input.issuer);
    if (entry === undefined || (entry.expiresAt <= now && canRefresh(entry, now))) {
      entry = await resolveJwks(input, keyId);
    }
    if (keyId !== undefined) {
      const unknownExpiresAt = entry.unknownKids.get(keyId);
      if (unknownExpiresAt !== undefined && unknownExpiresAt > now) {
        return { entry, key: entry.key, known: false };
      }
      entry.unknownKids.delete(keyId);
      if (!entry.keyIds.has(keyId)) {
        cacheUnknownKid(entry, keyId, now);
        return { entry, key: entry.key, known: false };
      }
    }
    return {
      entry,
      key: entry.key,
      known: keyId === undefined ? entry.allowsUnkiddedKey || entry.keyIds.size > 0 : true,
    };
  };

  const verifyWithKey = async (
    input: OidcJwtVerificationInput,
    key: unknown,
  ): Promise<unknown> => options.jose.jwtVerify(input.token, key, {
    issuer: input.issuer,
    audience: input.audience,
    algorithms: [...input.algorithms],
    currentDate: new Date(input.now * 1000),
    clockTolerance: 0,
  });

  const verify = async (
    input: OidcJwtVerificationInput,
  ): Promise<OidcJwtVerificationResult> => {
    const header = readCompactHeader(input.token);
    const keyId = readKeyId(header.kid);
    if (
      typeof header.alg !== "string" ||
      !isSafeHeaderValue(header.alg) ||
      !input.algorithms.includes(header.alg as OidcRuntimeSigningAlgorithm) ||
      header.jku !== undefined ||
      header.x5u !== undefined ||
      header.crit !== undefined
    ) {
      throw oidcAdapterError(OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.INVALID_TOKEN);
    }
    const resolution = await getKey(input, keyId);
    if (!resolution.known) {
      throw oidcAdapterError(OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.INVALID_TOKEN);
    }
    try {
      return normalizeJoseResult(await verifyWithKey(input, resolution.key));
    } catch (error) {
      if (isOidcAdapterError(error)) throw error;
      const now = nowMilliseconds(clock);
      if (!canRefresh(resolution.entry, now)) {
        throw oidcAdapterError(OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.INVALID_TOKEN);
      }
      const refreshed = await resolveJwks(input, keyId);
      if (keyId !== undefined && !refreshed.keyIds.has(keyId)) {
        cacheUnknownKid(refreshed, keyId, now);
        throw oidcAdapterError(OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.INVALID_TOKEN);
      }
      try {
        return normalizeJoseResult(await verifyWithKey(input, refreshed.key));
      } catch (retryError) {
        if (isOidcAdapterError(retryError)) throw retryError;
        throw oidcAdapterError(OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.INVALID_TOKEN);
      }
    }
  };

  const invalidate = async (input: {
    readonly issuer?: string;
    readonly keyId?: string;
  }): Promise<void> => {
    if (input.issuer !== undefined) {
      cache.delete(input.issuer);
      resolverAttempts.delete(input.issuer);
    } else if (input.keyId !== undefined) {
      for (const [issuer, entry] of cache) {
        if (entry.keyIds.has(input.keyId) || entry.unknownKids.has(input.keyId)) {
          cache.delete(issuer);
          resolverAttempts.delete(issuer);
        }
      }
    } else {
      cache.clear();
      resolverAttempts.clear();
    }
    if (options.jwks.invalidateCache !== undefined) {
      await options.jwks.invalidateCache(input);
    }
  };

  const readiness = async (): Promise<boolean> => {
    if (options.jwks.readiness === undefined) return false;
    try {
      return (await options.jwks.readiness()) === true;
    } catch {
      return false;
    }
  };

  return {
    kind,
    productionReady,
    readiness,
    verify,
    invalidateCache: invalidate,
  } as OidcBearerJwtVerifierPort | OidcServiceClientJwtVerifierPort;
}

function assertJoseOptions(options: OidcJoseVerifierOptions): void {
  if (
    options === null ||
    typeof options !== "object" ||
    options.jose === null ||
    typeof options.jose !== "object" ||
    typeof options.jose.createLocalJWKSet !== "function" ||
    typeof options.jose.jwtVerify !== "function" ||
    options.jwks === null ||
    typeof options.jwks !== "object" ||
    typeof options.jwks.resolve !== "function" ||
    (options.source !== undefined && options.source !== "preconfigured" && options.source !== "remote") ||
    (options.jwks.source !== undefined && options.jwks.source !== "preconfigured" && options.jwks.source !== "remote") ||
    (options.jwks.readiness !== undefined && typeof options.jwks.readiness !== "function") ||
    (options.jwks.invalidateCache !== undefined && typeof options.jwks.invalidateCache !== "function") ||
    (options.jwks.resolveHost !== undefined && typeof options.jwks.resolveHost !== "function") ||
    (options.kind !== undefined && options.kind !== "bearer" && options.kind !== "serviceClient") ||
    (options.clock !== undefined && typeof options.clock !== "function")
  ) {
    throw oidcAdapterError(OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.CONFIGURATION);
  }
  normalizeOidcMode(options.mode);
  const uris = [options.jwksUri, options.jwksUrl, options.jwks.jwksUri, options.jwks.jwksUrl]
    .filter((value): value is string => value !== undefined);
  if (new Set(uris).size > 1) {
    throw oidcAdapterError(OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.CONFIGURATION);
  }
  if (
    options.source !== undefined &&
    options.jwks.source !== undefined &&
    options.source !== options.jwks.source
  ) {
    throw oidcAdapterError(OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.CONFIGURATION);
  }
}

function createJwksSecurityPolicy(
  options: OidcJoseVerifierOptions,
  kind: "bearer" | "serviceClient",
): JwksSecurityPolicy {
  const mode = normalizeOidcMode(options.mode);
  const configuredUri = options.jwksUri ?? options.jwksUrl ?? options.jwks.jwksUri ?? options.jwks.jwksUrl;
  const source = options.source ?? options.jwks.source ?? (configuredUri === undefined ? "preconfigured" : "remote");
  const issuerAllowlist = normalizeIssuerAllowlist(
    options.issuerAllowlist ?? options.allowedIssuers ?? options.jwks.issuerAllowlist,
    mode,
  );
  const trustedHosts = normalizeHostAllowlist([
    ...(options.trustedJwksHosts ?? []),
    ...(options.allowedJwksHosts ?? []),
    ...(options.trustedHosts ?? []),
    ...(options.allowedHosts ?? []),
    ...(options.jwks.trustedHosts ?? []),
    ...(options.jwks.allowedHosts ?? []),
  ]);
  if (source === "preconfigured") {
    if (configuredUri !== undefined) {
      throw oidcAdapterError(OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.CONFIGURATION);
    }
    if (
      mode === "production" &&
      options.source !== "preconfigured" &&
      options.jwks.source !== "preconfigured"
    ) {
      throw oidcAdapterError(OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.CONFIGURATION);
    }
    return {
      mode,
      remote: false,
      issuerAllowlist,
      trustedHosts,
      ...(options.jwks.resolveHost === undefined
        ? {}
        : { resolveHost: options.jwks.resolveHost }),
    };
  }
  if (configuredUri === undefined) {
    throw oidcAdapterError(OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.CONFIGURATION);
  }
  const endpoint = parseJwksEndpoint(configuredUri, mode);
  const endpointHost = normalizeHost(endpoint.hostname);
  if (trustedHosts.size === 0 || !trustedHosts.has(endpointHost)) {
    throw oidcAdapterError(OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.CONFIGURATION);
  }
  assertSafeHostname(endpointHost);
  if (mode === "production") {
    if (
      options.allowRemoteJwks !== true ||
      issuerAllowlist.size === 0 ||
      (isIP(endpointHost) === 0 && options.jwks.resolveHost === undefined)
    ) {
      throw oidcAdapterError(OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.CONFIGURATION);
    }
  }
  if (
    kind === "serviceClient" &&
    mode === "production" &&
    issuerAllowlist.size === 0
  ) {
    throw oidcAdapterError(OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.CONFIGURATION);
  }
  return {
    mode,
    remote: true,
    endpoint,
    issuerAllowlist,
    trustedHosts,
    ...(options.jwks.resolveHost === undefined
      ? {}
      : { resolveHost: options.jwks.resolveHost }),
  };
}

async function assertIssuerAllowed(
  policy: JwksSecurityPolicy,
  issuer: string,
  kind: "bearer" | "serviceClient",
): Promise<void> {
  if (policy.issuerAllowlist.size > 0 && !policy.issuerAllowlist.has(issuer)) {
    throw oidcAdapterError(OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.CONFIGURATION);
  }
  if (!policy.remote) return;
  let parsed: URL;
  try {
    parsed = new URL(issuer);
  } catch {
    if (kind === "serviceClient" && policy.mode !== "production") return;
    throw oidcAdapterError(OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.CONFIGURATION);
  }
  const host = normalizeHost(parsed.hostname);
  if (policy.mode === "production" && parsed.port !== "" && parsed.port !== "443") {
    throw oidcAdapterError(OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.CONFIGURATION);
  }
  assertSafeHostname(host);
  if (policy.trustedHosts.size > 0 && !policy.trustedHosts.has(host)) {
    throw oidcAdapterError(OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.CONFIGURATION);
  }
  await assertRemoteHost(policy, host);
}

async function assertRemoteHost(
  policy: JwksSecurityPolicy,
  host: string,
): Promise<void> {
  assertSafeHostname(host);
  if (policy.resolveHost === undefined) {
    if (policy.mode === "production" && isIP(host) === 0) {
      throw oidcAdapterError(OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.CONFIGURATION);
    }
    return;
  }
  let addresses: unknown;
  try {
    addresses = await policy.resolveHost(host);
  } catch {
    throw oidcAdapterError(
      OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.VERIFIER_UNAVAILABLE,
      true,
    );
  }
  if (
    !Array.isArray(addresses) ||
    addresses.length === 0 ||
    addresses.some((address) =>
      typeof address !== "string" || isUnsafeOidcJwksAddress(address)
    )
  ) {
    throw oidcAdapterError(OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.CONFIGURATION);
  }
}

function parseJwksEndpoint(value: unknown, mode: OidcRuntimeMode): URL {
  if (typeof value !== "string" || value.length < 1 || value.length > 2048) {
    throw oidcAdapterError(OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.CONFIGURATION);
  }
  let endpoint: URL;
  try {
    endpoint = new URL(value);
  } catch {
    throw oidcAdapterError(OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.CONFIGURATION);
  }
  if (
    (endpoint.protocol !== "https:" && endpoint.protocol !== "http:") ||
    (mode === "production" && endpoint.protocol !== "https:") ||
    endpoint.hostname === "" ||
    endpoint.username !== "" ||
    endpoint.password !== "" ||
    endpoint.hash !== "" ||
    endpoint.search !== "" ||
    (mode === "production" && endpoint.port !== "" && endpoint.port !== "443")
  ) {
    throw oidcAdapterError(OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.CONFIGURATION);
  }
  return endpoint;
}

function normalizeIssuerAllowlist(
  values: readonly string[] | undefined,
  mode: OidcRuntimeMode,
): ReadonlySet<string> {
  if (values === undefined) return new Set<string>();
  if (!Array.isArray(values) || values.length === 0 || values.length > 64) {
    throw oidcAdapterError(OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.CONFIGURATION);
  }
  const output = new Set<string>();
  for (const value of values) {
    const issuer = normalizeIssuer(value, mode);
    const parsed = new URL(issuer);
    assertSafeHostname(normalizeHost(parsed.hostname));
    output.add(issuer);
  }
  return output;
}

function normalizeHostAllowlist(values: readonly string[]): ReadonlySet<string> {
  if (!Array.isArray(values) || values.length > 64) {
    throw oidcAdapterError(OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.CONFIGURATION);
  }
  const output = new Set<string>();
  for (const value of values) {
    const host = normalizeHost(value);
    assertSafeHostname(host);
    output.add(host);
  }
  return output;
}

function normalizeHost(value: unknown): string {
  if (typeof value !== "string") {
    throw oidcAdapterError(OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.CONFIGURATION);
  }
  let host = value.trim().toLowerCase();
  if (host.startsWith("[") && host.endsWith("]")) host = host.slice(1, -1);
  while (host.endsWith(".")) host = host.slice(0, -1);
  if (
    host.length < 1 ||
    host.length > 253 ||
    host.includes("*") ||
    host.includes("/") ||
    host.includes("@") ||
    /[\u0000-\u0020\u007f]/u.test(host)
  ) {
    throw oidcAdapterError(OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.CONFIGURATION);
  }
  return host;
}

function assertSafeHostname(host: string): void {
  if (
    METADATA_HOSTS.has(host) ||
    LOOPBACK_HOSTS.has(host) ||
    BLOCKED_HOST_SUFFIXES.some((suffix) => host.endsWith(suffix)) ||
    (isIP(host) !== 0 && isUnsafeIpv4(host)) ||
    (isIP(host) === 6 && isUnsafeIpv6(host))
  ) {
    throw oidcAdapterError(OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.CONFIGURATION);
  }
}

function isUnsafeIpv4(value: string): boolean {
  const parts = value.split(".");
  if (parts.length !== 4) return true;
  const octets = parts.map((part) => Number(part));
  if (octets.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) return true;
  const [a, b] = octets;
  return a === 0 ||
    a === 10 ||
    a === 127 ||
    a === 169 && b === 254 ||
    a === 172 && b >= 16 && b <= 31 ||
    a === 192 && b === 168 ||
    a === 192 && b === 0 ||
    a === 198 && (b === 18 || b === 19) ||
    a === 198 && b === 51 && octets[2] === 100 ||
    a === 203 && b === 0 && octets[2] === 113 ||
    a === 100 && b >= 64 && b <= 127 ||
    a >= 224;
}

function isUnsafeIpv6(value: string): boolean {
  const normalized = value.toLowerCase();
  if (
    normalized === "::" ||
    normalized === "::1" ||
    normalized.startsWith("fc") ||
    normalized.startsWith("fd") ||
    /^fe[89ab]/u.test(normalized) ||
    normalized.startsWith("ff") ||
    normalized.startsWith("2001:db8")
  ) {
    return true;
  }
  const mapped = normalized.match(/::(?:ffff:)?(\d+\.\d+\.\d+\.\d+)$/u)?.[1];
  return mapped === undefined ? false : isUnsafeIpv4(mapped);
}

function normalizeJoseResult(value: unknown): OidcJwtVerificationResult {
  if (!isRecord(value) || !isRecord(value.payload) || !isRecord(value.protectedHeader)) {
    throw oidcAdapterError(OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.INVALID_TOKEN);
  }
  return Object.freeze({
    signatureVerified: true,
    claims: freezeRecord(value.payload),
    protectedHeader: freezeRecord(value.protectedHeader),
  });
}

function assertPublicJwks(value: unknown): void {
  if (
    !isRecord(value) ||
    !Array.isArray(value.keys) ||
    value.keys.length === 0 ||
    value.keys.length > MAX_JWKS_KEYS
  ) {
    throw oidcAdapterError(
      OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.VERIFIER_UNAVAILABLE,
      true,
    );
  }
  for (const key of value.keys) {
    if (!isRecord(key) || typeof key.kty !== "string") {
      throw oidcAdapterError(
        OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.VERIFIER_UNAVAILABLE,
        true,
      );
    }
    if (PRIVATE_JWK_FIELDS.some((field) => Object.prototype.hasOwnProperty.call(key, field))) {
      throw oidcAdapterError(
        OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.VERIFIER_UNAVAILABLE,
        true,
      );
    }
    if (key.use !== undefined && key.use !== "sig") {
      throw oidcAdapterError(
        OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.VERIFIER_UNAVAILABLE,
        true,
      );
    }
    if (key.key_ops !== undefined) {
      if (
        !Array.isArray(key.key_ops) ||
        !key.key_ops.every((operation) => typeof operation === "string") ||
        !key.key_ops.includes("verify") ||
        key.key_ops.includes("sign")
      ) {
        throw oidcAdapterError(
          OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.VERIFIER_UNAVAILABLE,
          true,
        );
      }
    }
  }
}

function readCompactHeader(token: string): Record<string, unknown> {
  if (typeof token !== "string" || token.length < 3 || token.length > MAX_TOKEN_LENGTH) {
    throw oidcAdapterError(OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.INVALID_TOKEN);
  }
  const parts = token.split(".");
  if (parts.length !== 3 || parts.some((part) => part.length === 0)) {
    throw oidcAdapterError(OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.INVALID_TOKEN);
  }
  let decoded: unknown;
  try {
    decoded = JSON.parse(Buffer.from(parts[0], "base64url").toString("utf8"));
  } catch {
    throw oidcAdapterError(OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.INVALID_TOKEN);
  }
  if (!isRecord(decoded)) {
    throw oidcAdapterError(OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.INVALID_TOKEN);
  }
  return decoded;
}

function readKeyId(value: unknown): string | undefined {
  if (value === undefined) return undefined;
  if (
    typeof value !== "string" ||
    value.length < 1 ||
    value.length > 256 ||
    /[\u0000-\u0020\u007f]/u.test(value)
  ) {
    throw oidcAdapterError(OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.INVALID_TOKEN);
  }
  return value;
}

function freezeRecord(value: Record<string, unknown>): Readonly<Record<string, unknown>> {
  const output: Record<string, unknown> = {};
  for (const [key, nested] of Object.entries(value)) {
    if (typeof nested === "string") output[key] = nested;
    else if (typeof nested === "number" && Number.isFinite(nested)) output[key] = nested;
    else if (typeof nested === "boolean") output[key] = nested;
    else if (nested === null) output[key] = null;
    else if (Array.isArray(nested)) {
      output[key] = Object.freeze(
        nested.filter((item) =>
          typeof item === "string" ||
          typeof item === "number" ||
          typeof item === "boolean" ||
          item === null,
        ),
      );
    }
  }
  return Object.freeze(output);
}

function isSafeHeaderValue(value: string): boolean {
  return value.length > 0 && value.length <= 32 && /^[A-Za-z0-9._-]+$/u.test(value);
}

function nowMilliseconds(clock: () => Date): number {
  const value = clock();
  if (!(value instanceof Date) || !Number.isFinite(value.getTime())) {
    throw oidcAdapterError(OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.CONFIGURATION);
  }
  return value.getTime();
}

function normalizeLimit(
  value: number | undefined,
  fallback: number,
  minimum: number,
  maximum: number,
): number {
  if (value === undefined) return fallback;
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw oidcAdapterError(OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.CONFIGURATION);
  }
  return value;
}

function isOidcAdapterError(value: unknown): boolean {
  return value instanceof Error && value.name === "OpenPlatformOidcAdapterError";
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
