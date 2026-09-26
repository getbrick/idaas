import { describe, expect, it, vi } from "vitest";
import {
  createGetbrickApiClient,
  parseGetbrickErrorEnvelope,
} from "../src/client.js";
import { getAdminErrorMessage } from "../src/admin/index.js";

describe("admin API client", () => {
  it("uses PATCH for ordinary updates and parses the shared error envelope", async () => {
    const fetchMock = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      expect(init?.method).toBe("PATCH");
      expect(new Headers(init?.headers).get("if-match")).toBe('"application:app-1:4"');
      return new Response(JSON.stringify({ id: "app-1", name: "Updated", slug: "updated", status: "active" }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    });
    const client = createGetbrickApiClient({ baseURL: "https://control.example.test", fetch: fetchMock as typeof fetch });
    await expect(client.updateApplication("app-1", { name: "Updated" }, '"application:app-1:4"')).resolves.toMatchObject({ name: "Updated" });
  });

  it("sends quoted ETags and parses JSON error responses without a content type", async () => {
    const fetchMock = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      expect(init?.method).toBe("POST");
      expect(new Headers(init?.headers).get("if-match")).toBe('"application:app-1:4"');
      return new Response(JSON.stringify({
        error: { code: "CONFLICT", message: "Version changed" },
        requestId: "request-2",
      }), { status: 409 });
    });
    const client = createGetbrickApiClient({ baseURL: "https://control.example.test", fetch: fetchMock as typeof fetch });
    await expect(client.restoreApplication("app-1", "application:app-1:4")).rejects.toMatchObject({
      status: 409,
      code: "CONFLICT",
      requestId: "request-2",
    });
  });

  it("does not expose details or secret-bearing messages", () => {
    const error = parseGetbrickErrorEnvelope({
      error: {
        code: "CONFLICT",
        message: "Invalid secretRef vault://private",
        details: { secret: "raw-secret" },
      },
      requestId: "request-1",
    }, 409);
    expect(error.status).toBe(409);
    expect(error.code).toBe("CONFLICT");
    expect(error.message).toBe("Request failed");
    expect(getAdminErrorMessage(error)).toBe("Request failed");
    expect(JSON.stringify(error.envelope)).not.toContain("raw-secret");
    expect(parseGetbrickErrorEnvelope({
      error: { code: "CONFLICT", message: "Conflict" },
      requestId: "vault://request-secret",
    }, 409).requestId).toBeUndefined();
  });
});
