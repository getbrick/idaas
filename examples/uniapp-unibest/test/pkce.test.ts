import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { createPkceTransaction, OidcTransactionStore } from "../src/auth/pkce";
import { createMemoryStorage } from "../src/types/runtime";

function bytes(seed: number, length: number): Uint8Array {
  return new Uint8Array(Array.from({ length }, (_, index) => (seed + index) % 256));
}

async function sha256(value: Uint8Array): Promise<ArrayBuffer> {
  return createHash("sha256").update(value).digest().buffer as ArrayBuffer;
}

describe("OIDC PKCE", () => {
  it("creates a verifier and S256 challenge", async () => {
    const transaction = await createPkceTransaction({
      redirectUri: "https://client.example.com/oidc/callback",
      randomBytes: (length) => bytes(17, length),
      sha256,
    });

    expect(transaction.state).toMatch(/^[A-Za-z0-9_-]+$/u);
    expect(transaction.nonce).toMatch(/^[A-Za-z0-9_-]+$/u);
    expect(transaction.startGeneration).toBe(0);
    expect(transaction.attempt).toBe(1);
    expect(transaction.codeVerifier.length).toBeGreaterThanOrEqual(43);
    expect(transaction.codeChallenge).toBe(
      Buffer.from(await sha256(new TextEncoder().encode(transaction.codeVerifier)))
        .toString("base64")
        .replace(/\+/gu, "-")
        .replace(/\//gu, "_")
        .replace(/=+$/u, ""),
    );
  });

  it("consumes a transaction once", async () => {
    const storage = createMemoryStorage();
    const transaction = await createPkceTransaction({
      redirectUri: "https://client.example.com/oidc/callback",
      randomBytes: (length) => bytes(29, length),
      sha256,
    });
    const store = new OidcTransactionStore({ storage, now: () => transaction.createdAt });
    store.save(transaction);

    expect(store.consume()).toEqual(transaction);
    expect(store.consume()).toBeNull();
  });

  it("rejects an expired transaction", async () => {
    const storage = createMemoryStorage();
    const transaction = await createPkceTransaction({
      redirectUri: "https://client.example.com/oidc/callback",
      randomBytes: (length) => bytes(31, length),
      sha256,
      now: () => 1000,
    });
    const store = new OidcTransactionStore({ storage, now: () => 1000 + 11 * 60 * 1000 });

    expect(() => store.save(transaction)).toThrow("OIDC transaction");
    expect(store.load()).toBeNull();
  });
});
