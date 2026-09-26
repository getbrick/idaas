import { createPublicKey, type JsonWebKey as NodeJsonWebKey } from "node:crypto";

export type OidcClientJwks = {
  keys: Record<string, unknown>[];
};

export type OidcClientJwksInput = OidcClientJwks | { keys: unknown[] };

export type OidcClientJwksResolver = (
  clientId: string,
) => OidcClientJwksInput | undefined | Promise<OidcClientJwksInput | undefined>;

export interface OidcClientJwksOptions {
  algorithm?: string;
}

const PRIVATE_JWK_FIELDS = ["d", "p", "q", "dp", "dq", "qi", "oth", "k"];
const SUPPORTED_ALGORITHMS = new Set(["RS256", "PS256", "ES256", "EdDSA"]);

export function validateOidcClientJwks(
  value: unknown,
  options: OidcClientJwksOptions = {},
): OidcClientJwks {
  if (!isRecord(value) || !Array.isArray(value.keys) || value.keys.length === 0 || value.keys.length > 16) {
    throw new Error("[getbrick-idaas] managed OIDC client JWKS is invalid");
  }
  const seen = new Set<string>();
  const keys = value.keys.map((key) => {
    if (!isRecord(key)) throw new Error("[getbrick-idaas] managed OIDC client JWKS contains an invalid key");
    const kid = key.kid;
    if (typeof kid !== "string" || kid.length === 0 || kid.length > 256 || /\s/u.test(kid) || /[\u0000-\u001f\u007f]/u.test(kid)) {
      throw new Error("[getbrick-idaas] managed OIDC client JWKS keys require a valid kid");
    }
    if (seen.has(kid)) throw new Error("[getbrick-idaas] managed OIDC client JWKS contains duplicate kid values");
    seen.add(kid);
    if (key.use !== undefined && key.use !== "sig") {
      throw new Error("[getbrick-idaas] managed OIDC client JWKS keys must be signing keys");
    }
    if (key.key_ops !== undefined) {
      if (
        !Array.isArray(key.key_ops) ||
        !key.key_ops.every((operation) => typeof operation === "string") ||
        !key.key_ops.includes("verify") ||
        key.key_ops.includes("sign")
      ) {
        throw new Error("[getbrick-idaas] managed OIDC client JWKS key operations are invalid");
      }
    }
    if (PRIVATE_JWK_FIELDS.some((field) => Object.prototype.hasOwnProperty.call(key, field))) {
      throw new Error("[getbrick-idaas] managed OIDC client JWKS must contain public keys only");
    }
    if (typeof key.kty !== "string" || !["RSA", "EC", "OKP"].includes(key.kty)) {
      throw new Error("[getbrick-idaas] managed OIDC client JWKS key type is invalid");
    }
    if (key.alg !== undefined && (typeof key.alg !== "string" || !SUPPORTED_ALGORITHMS.has(key.alg))) {
      throw new Error("[getbrick-idaas] managed OIDC client JWKS algorithm is invalid");
    }
    if (
      key.alg !== undefined &&
      ((["RS256", "PS256"].includes(key.alg) && key.kty !== "RSA") ||
        (key.alg === "ES256" && key.kty !== "EC") ||
        (key.alg === "EdDSA" && key.kty !== "OKP"))
    ) {
      throw new Error("[getbrick-idaas] managed OIDC client JWKS algorithm does not match key type");
    }
    if (options.algorithm !== undefined && key.alg !== undefined && key.alg !== options.algorithm) {
      throw new Error("[getbrick-idaas] managed OIDC client JWKS algorithm does not match client authentication");
    }
    if (options.algorithm !== undefined) {
      const expectedKeyType = options.algorithm === "ES256" ? "EC" : options.algorithm === "EdDSA" ? "OKP" : "RSA";
      if (key.kty !== expectedKeyType) {
        throw new Error("[getbrick-idaas] managed OIDC client JWKS key type does not match client authentication");
      }
    }
    validatePublicKey(key);
    return { ...key };
  });
  return { keys };
}

export function cloneOidcClientJwks(value: unknown, options: OidcClientJwksOptions = {}): OidcClientJwks {
  return validateOidcClientJwks(JSON.parse(JSON.stringify(value)), options);
}

function validatePublicKey(key: Record<string, unknown>): void {
  if (key.kty === "RSA") {
    if (typeof key.n !== "string" || typeof key.e !== "string" || key.n.length === 0 || key.e.length === 0) {
      throw new Error("[getbrick-idaas] managed OIDC client RSA JWKS key is invalid");
    }
  } else if (key.kty === "EC") {
    if (typeof key.crv !== "string" || typeof key.x !== "string" || typeof key.y !== "string") {
      throw new Error("[getbrick-idaas] managed OIDC client EC JWKS key is invalid");
    }
  } else if (key.kty === "OKP") {
    if (key.crv !== "Ed25519" && key.crv !== "Ed448") {
      throw new Error("[getbrick-idaas] managed OIDC client OKP JWKS curve is invalid");
    }
    if (typeof key.x !== "string" || key.x.length === 0) {
      throw new Error("[getbrick-idaas] managed OIDC client OKP JWKS key is invalid");
    }
  } else {
    throw new Error("[getbrick-idaas] managed OIDC client JWKS key type is invalid");
  }
  try {
    const imported = createPublicKey({ key: key as NodeJsonWebKey, format: "jwk" });
    if (key.kty === "RSA" && imported.asymmetricKeyType !== "rsa") {
      throw new Error("invalid key type");
    }
    if (key.kty === "RSA" && (imported.asymmetricKeyDetails?.modulusLength ?? 0) < 2048) {
      throw new Error("RSA key is too small");
    }
    if (key.kty === "EC" && (imported.asymmetricKeyType !== "ec" || !["P-256", "prime256v1"].includes(imported.asymmetricKeyDetails?.namedCurve ?? ""))) {
      throw new Error("invalid key curve");
    }
    if (key.kty === "OKP" && (imported.asymmetricKeyType !== "ed25519" && imported.asymmetricKeyType !== "ed448")) {
      throw new Error("invalid OKP key type");
    }
  } catch {
    throw new Error("[getbrick-idaas] managed OIDC client JWKS key could not be imported");
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
