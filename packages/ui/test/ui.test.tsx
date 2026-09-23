import { describe, expect, it, vi } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { AuthForm } from "../src/AuthForm.js";
import { GetbrickAuthProvider } from "../src/provider.js";
import { themeToCssVars } from "../src/theme.js";

const fetchMock = vi.fn();
globalThis.fetch = fetchMock as typeof fetch;

function jsonResponse(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

describe("AuthForm", () => {
  it("submits sign-in to the auth endpoint and reports success", async () => {
    fetchMock.mockImplementation(async (input: any) => {
      const url = String(input);
      if (url.includes("/sign-in/email")) return jsonResponse({ user: { email: "u@example.com" } });
      return jsonResponse({});
    });
    const onSuccess = vi.fn();
    render(
      <GetbrickAuthProvider baseURL="http://localhost:3000">
        <AuthForm mode="sign-in" onSuccess={onSuccess} />
      </GetbrickAuthProvider>,
    );
    const email = document.querySelector('input[type="email"]') as HTMLInputElement;
    const password = document.querySelector('input[type="password"]') as HTMLInputElement;
    const form = document.querySelector("form") as HTMLFormElement;
    email.value = "u@example.com";
    email.dispatchEvent(new Event("input", { bubbles: true }));
    password.value = "supersecret123";
    password.dispatchEvent(new Event("input", { bubbles: true }));
    form.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));

    await waitFor(() => expect(onSuccess).toHaveBeenCalled());
    const calledUrl = String(fetchMock.mock.calls.find((c) => String(c[0]).includes("sign-in"))?.[0]);
    expect(calledUrl).toContain("sign-in/email");
  });

  it("shows server error message on failure", async () => {
    fetchMock.mockImplementation(async (input: any) => {
      const url = String(input);
      if (url.includes("/sign-in/email")) {
        return jsonResponse({ message: "Invalid email or password" }, 401);
      }
      return jsonResponse({});
    });
    render(
      <GetbrickAuthProvider baseURL="http://localhost:3000">
        <AuthForm mode="sign-in" />
      </GetbrickAuthProvider>,
    );
    const email = document.querySelector('input[type="email"]') as HTMLInputElement;
    const password = document.querySelector('input[type="password"]') as HTMLInputElement;
    const form = document.querySelector("form") as HTMLFormElement;
    email.value = "u@example.com";
    email.dispatchEvent(new Event("input", { bubbles: true }));
    password.value = "wrongpass123";
    password.dispatchEvent(new Event("input", { bubbles: true }));
    form.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));

    await waitFor(() => {
      expect(document.querySelector(".gb-auth-form__error")?.textContent).toContain("Invalid email or password");
    });
  });
});

describe("theme", () => {
  it("maps tokens to css variables", () => {
    const vars = themeToCssVars({ primary: "#ff0000" });
    expect(vars["--gb-primary"]).toBe("#ff0000");
    expect(vars["--gb-text"]).toBeTruthy();
  });
});
