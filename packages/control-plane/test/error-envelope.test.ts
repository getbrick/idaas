import "reflect-metadata";
import { BadRequestException } from "@nestjs/common";
import { describe, expect, it, vi } from "vitest";
import { ControlPlaneExceptionFilter } from "../src/filter.js";

function host(response: Record<string, unknown>, request: Record<string, unknown>) {
  return {
    switchToHttp: () => ({
      getResponse: () => response,
      getRequest: () => request,
    }),
  } as never;
}

describe("control-plane error envelope", () => {
  it("normalizes HTTP errors, masks details, and preserves a safe request id", () => {
    const json = vi.fn();
    const setHeader = vi.fn();
    const response = {
      status: vi.fn(() => response),
      json,
      setHeader,
    };
    new ControlPlaneExceptionFilter().catch(
      new BadRequestException({ code: "INVALID_REQUEST", message: "Invalid value", details: { secret: "raw", field: "name" } }),
      host(response, { headers: { "X-Request-ID": " request-1 " } }),
    );
    expect(response.status).toHaveBeenCalledWith(400);
    expect(setHeader).toHaveBeenCalledWith("x-request-id", "request-1");
    expect(json).toHaveBeenCalledWith({
      error: { code: "INVALID_REQUEST", message: "Invalid value", details: { field: "name" } },
      requestId: "request-1",
    });
  });

  it("does not forward an untrusted custom error code or message", () => {
    const json = vi.fn();
    const response = { status: vi.fn(() => response), json };
    new ControlPlaneExceptionFilter().catch(
      new BadRequestException({ code: "PLATFORM_SECRET_FAILURE", message: "secret vault://value" }),
      host(response, {}),
    );
    expect(json).toHaveBeenCalledWith({
      error: { code: "INVALID_REQUEST", message: "Invalid request" },
    });
  });
});
