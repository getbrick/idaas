import { describe, expect, it } from "vitest";
import { normalizeOidcCallback, parseWebViewCallback } from "../src/auth/callback";

describe("OIDC callback", () => {
  it("accepts a code and state", () => {
    expect(normalizeOidcCallback({ code: "code_123", state: "state_123" })).toEqual({ code: "code_123", state: "state_123" });
  });

  it("does not expose provider error details", () => {
    expect(() => normalizeOidcCallback({ error: "access_denied", errorDescription: "provider detail" })).toThrow("authorization");
  });

  it("parses a web-view message", () => {
    const message = JSON.stringify({ type: "getbrick-oidc-callback", code: "code_123", state: "state_123" });
    expect(parseWebViewCallback([message])).toEqual({ code: "code_123", state: "state_123" });
  });

  it("parses a one-time web-view ticket with state binding", () => {
    const ticket = "gbt_abcdefghijklmnopqrstuvwxyz123456";
    expect(parseWebViewCallback({ type: "getbrick-oidc-callback", ticket, state: "state_123" })).toEqual({ ticketReference: ticket, state: "state_123" });
  });
});
