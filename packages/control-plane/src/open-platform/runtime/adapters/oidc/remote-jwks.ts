import { isIP } from "node:net";
import { validateOidcClientJwks } from "@getbrick/idaas-core";
import {
  OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES,
  oidcAdapterError,
} from "./errors.js";
import {
  assertSafeOidcJwksEndpoint,
  isUnsafeOidcJwksAddress,
} from "./jose.js";
import { normalizeIssuer, normalizeOidcMode } from "./shared.js";
import type {
  OidcJwksResolverPort,
  OidcRemoteJwksResolverOptions,
} from "./contracts.js";

const DEFAULT_TIMEOUT_MS = 5_000;
const MAX_TIMEOUT_MS = 120_000;
const DEFAULT_MAX_RESPONSE_BYTES = 1_048_576;
const MAX_RESPONSE_BYTES = 16_777_216;

export function createRemoteOidcJwksResolver(
  options: OidcRemoteJwksResolverOptions,
): OidcJwksResolverPort {
  if (options === null || typeof options !== "object") {
    throw oidcAdapterError(OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.CONFIGURATION);
  }
  const mode = normalizeOidcMode(options.mode ?? "production");
  const trustedHosts = normalizeHosts(options.trustedHosts);
  const endpoint = assertSafeOidcJwksEndpoint(options.jwksUri, {
    mode,
    trustedHosts: [...trustedHosts],
  });
  const issuerAllowlist = normalizeIssuers(options.issuerAllowlist, mode);
  for (const issuer of issuerAllowlist) {
    assertSafeOidcJwksEndpoint(issuer, {
      mode,
      trustedHosts: [...trustedHosts],
    });
  }
  const issuerRequiresResolver = [...issuerAllowlist].some((value) => {
    const host = new URL(value).hostname.replace(/^\[|\]$/gu, "");
    return mode === "production" && isIP(host) === 0;
  });
  if (
    issuerAllowlist.size === 0 ||
    options.allowRemoteJwks !== true ||
    ((isIP(endpoint.hostname.replace(/^\[|\]$/gu, "")) === 0 || issuerRequiresResolver) &&
      options.resolveHost === undefined &&
      mode === "production")
  ) {
    throw oidcAdapterError(OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.CONFIGURATION);
  }
  const fetcher = options.fetch ?? globalThis.fetch;
  if (typeof fetcher !== "function") {
    throw oidcAdapterError(OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.CONFIGURATION);
  }
  const timeoutMs = normalizeLimit(
    options.timeoutMs,
    DEFAULT_TIMEOUT_MS,
    1,
    MAX_TIMEOUT_MS,
  );
  const maxResponseBytes = normalizeLimit(
    options.maxResponseBytes,
    DEFAULT_MAX_RESPONSE_BYTES,
    1_024,
    MAX_RESPONSE_BYTES,
  );
  const productionReady =
    options.productionReady === true &&
    (mode !== "production" || options.readiness !== undefined);
  return {
    source: "remote",
    jwksUri: endpoint.href,
    issuerAllowlist: [...issuerAllowlist],
    trustedHosts: [...trustedHosts],
    productionReady,
    ...(options.resolveHost === undefined ? {} : { resolveHost: options.resolveHost }),
    ...(options.readiness === undefined ? {} : { readiness: options.readiness }),
    async invalidateCache() {},
    async resolve(input) {
      if (!issuerAllowlist.has(input.issuer)) {
        throw oidcAdapterError(OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.CONFIGURATION);
      }
      const issuerHost = readIssuerHost(input.issuer, mode);
      await assertHost(issuerHost, mode, trustedHosts, options.resolveHost);
      await assertHost(
        endpoint.hostname,
        mode,
        trustedHosts,
        options.resolveHost,
      );
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), timeoutMs);
      try {
        let response: Response;
        try {
          response = await fetcher(endpoint.href, {
            method: "GET",
            headers: { Accept: "application/json" },
            redirect: "error",
            signal: controller.signal,
          });
        } catch {
          throw oidcAdapterError(
            OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.VERIFIER_UNAVAILABLE,
            true,
          );
        }
        const value = await readJsonResponse(response, maxResponseBytes);
        try {
          return validateOidcClientJwks(value);
        } catch {
          throw oidcAdapterError(
            OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.VERIFIER_UNAVAILABLE,
            true,
          );
        }
      } finally {
        clearTimeout(timeout);
      }
    },
  };
}

async function assertHost(
  value: string,
  mode: ReturnType<typeof normalizeOidcMode>,
  trustedHosts: ReadonlySet<string>,
  resolveHost: OidcRemoteJwksResolverOptions["resolveHost"],
): Promise<void> {
  const host = value.trim().toLowerCase().replace(/^\[|\]$/gu, "");
  assertSafeOidcJwksEndpoint(`https://${host.includes(":") ? `[${host}]` : host}/`, {
    mode,
    trustedHosts: [...trustedHosts],
  });
  if (resolveHost === undefined) {
    if (mode === "production" && isIP(host) === 0) {
      throw oidcAdapterError(OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.CONFIGURATION);
    }
    return;
  }
  let addresses: unknown;
  try {
    addresses = await resolveHost(host);
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

function readIssuerHost(value: string, mode: ReturnType<typeof normalizeOidcMode>): string {
  const issuer = normalizeIssuer(value, mode);
  return new URL(issuer).hostname.replace(/^\[|\]$/gu, "");
}

async function readJsonResponse(
  response: Response,
  maxResponseBytes: number,
): Promise<unknown> {
  if (!response.ok) {
    throw oidcAdapterError(
      OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.VERIFIER_UNAVAILABLE,
      true,
    );
  }
  const contentType = response.headers.get("content-type")?.split(";", 1)[0]?.trim().toLowerCase();
  if (
    contentType !== "application/json" &&
    !contentType?.endsWith("+json")
  ) {
    throw oidcAdapterError(
      OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.VERIFIER_UNAVAILABLE,
      true,
    );
  }
  const contentLength = response.headers.get("content-length");
  if (contentLength !== null) {
    const length = Number(contentLength);
    if (!Number.isSafeInteger(length) || length < 0 || length > maxResponseBytes) {
      throw oidcAdapterError(
        OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.VERIFIER_UNAVAILABLE,
        true,
      );
    }
  }
  let bytes: ArrayBuffer;
  try {
    bytes = await response.arrayBuffer();
  } catch {
    throw oidcAdapterError(
      OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.VERIFIER_UNAVAILABLE,
      true,
    );
  }
  if (bytes.byteLength > maxResponseBytes) {
    throw oidcAdapterError(
      OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.VERIFIER_UNAVAILABLE,
      true,
    );
  }
  try {
    return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch {
    throw oidcAdapterError(
      OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.VERIFIER_UNAVAILABLE,
      true,
    );
  }
}

function normalizeIssuers(
  values: readonly string[] | undefined,
  mode: ReturnType<typeof normalizeOidcMode>,
): ReadonlySet<string> {
  if (!Array.isArray(values) || values.length === 0 || values.length > 64) {
    throw oidcAdapterError(OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.CONFIGURATION);
  }
  const output = new Set<string>();
  for (const value of values) output.add(normalizeIssuer(value, mode));
  return output;
}

function normalizeHosts(values: readonly string[] | undefined): ReadonlySet<string> {
  if (!Array.isArray(values) || values.length === 0 || values.length > 64) {
    throw oidcAdapterError(OPEN_PLATFORM_OIDC_ADAPTER_ERROR_CODES.CONFIGURATION);
  }
  return new Set(values.map((value) => value.trim().toLowerCase()));
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
