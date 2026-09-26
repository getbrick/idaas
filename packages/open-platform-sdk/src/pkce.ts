import { createHash, randomBytes } from "node:crypto";

export interface PkcePair {
  readonly codeVerifier: string;
  readonly codeChallenge: string;
  readonly codeChallengeMethod: "S256";
}

export interface PkceOptions {
  readonly byteLength?: number;
}

export function generateCodeVerifier(byteLength = 32): string {
  if (!Number.isSafeInteger(byteLength) || byteLength < 32 || byteLength > 96) {
    throw new Error("PKCE verifier byte length is invalid");
  }
  const verifier = randomBytes(byteLength).toString("base64url");
  assertCodeVerifier(verifier);
  return verifier;
}

export function generateCodeChallenge(codeVerifier: string): string {
  assertCodeVerifier(codeVerifier);
  return createHash("sha256").update(codeVerifier, "utf8").digest("base64url");
}

export function generatePkcePair(options: PkceOptions | number = {}): PkcePair {
  const byteLength = typeof options === "number" ? options : options.byteLength ?? 32;
  const codeVerifier = generateCodeVerifier(byteLength);
  return {
    codeVerifier,
    codeChallenge: generateCodeChallenge(codeVerifier),
    codeChallengeMethod: "S256",
  };
}

export const createPkcePair = generatePkcePair;
export const createPkce = generatePkcePair;
export const generatePkce = generatePkcePair;
export const createPkceVerifier = generateCodeVerifier;
export const createPkceChallenge = generateCodeChallenge;
export const generatePkceVerifier = generateCodeVerifier;
export const generatePkceChallenge = generateCodeChallenge;
export const generateVerifier = generateCodeVerifier;
export const generateChallenge = generateCodeChallenge;

export function assertCodeVerifier(value: unknown): string {
  if (
    typeof value !== "string" ||
    value.length < 43 ||
    value.length > 128 ||
    !/^[A-Za-z0-9._~-]+$/u.test(value)
  ) {
    throw new Error("PKCE code verifier is invalid");
  }
  return value;
}

export function assertCodeChallenge(value: unknown): string {
  if (
    typeof value !== "string" ||
    value.length !== 43 ||
    !/^[A-Za-z0-9_-]+$/u.test(value)
  ) {
    throw new Error("PKCE code challenge is invalid");
  }
  return value;
}
