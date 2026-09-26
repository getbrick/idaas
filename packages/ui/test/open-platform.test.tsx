import { afterEach, describe, expect, it, vi } from "vitest";
import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import {
  ApiProductCard,
  AppLifecycleStatusBadge,
  ComplianceDataAssetList,
  CompliancePrivacyRequestList,
  ComplianceReportPanel,
  CredentialRevealPanel,
  DeveloperPortalShell,
  DomainEventMonitor,
  EmptyState,
  ErrorState,
  InvoiceTable,
  LoadingState,
  MarketplaceListingCard,
  OpenPlatformAuditEventList,
  OpenPlatformOperationsShell,
  OutboxStatusList,
  UsageMeter,
  WebhookEndpointList,
  createOpenPlatformClient,
  getAppLifecycleStatus,
  getOpenPlatformErrorCode,
  getOpenPlatformErrorMessage,
  maskOpenPlatformAddress,
  maskOpenPlatformBankAccount,
  maskOpenPlatformPhone,
  maskOpenPlatformSecretReference,
  maskOpenPlatformSettlementReference,
  maskOpenPlatformSubjectRef,
  sanitizeOpenPlatformExternalHref,
  sanitizeOpenPlatformHref,
  sanitizeOpenPlatformInternalHref,
  type ApiProduct,
  type DeveloperPortalNavigationItem,
  type OpenPlatformComplianceDataAsset,
  type OpenPlatformCompliancePrivacyRequest,
  type OpenPlatformComplianceReport,
  type OpenPlatformDomainEventRetrySummary,
  type OpenPlatformDomainEventSummary,
} from "../src/open-platform/index.js";

afterEach(() => {
  cleanup();
  vi.useRealTimers();
});

describe("DeveloperPortalShell", () => {
  it("renders an accessible, busy shell and emits typed navigation", () => {
    const onNavigate = vi.fn();
    const onSelect = vi.fn();
    const overview: DeveloperPortalNavigationItem = { id: "overview", label: "Overview", onSelect };
    const { container } = render(
      <DeveloperPortalShell
        title="Identity API"
        productName="Acme Developer"
        description="Build with identity"
        classNamespace="tenant/portal"
        navigationLabel="Portal sections"
        navigation={[
          overview,
          { id: "settings", label: "Settings", href: "/settings?tab=security" },
          { id: "docs", label: "Documentation", href: "https://docs.example.test" },
          { id: "unsafe", label: "Unsafe", href: "javascript:alert(1)" },
          { id: "userinfo", label: "Userinfo", href: "https://user:password@docs.example.test" },
          { id: "disabled", label: "Disabled", href: "https://disabled.example.test", disabled: true },
        ]}
        activeItemId="docs"
        onNavigate={onNavigate}
        headerActions={<button type="button">Account</button>}
        footer={<span>Service status</span>}
        busy
      >
        <p>Portal content</p>
      </DeveloperPortalShell>,
    );

    expect(screen.getByRole("navigation", { name: "Portal sections" })).toBeTruthy();
    expect(screen.getByRole("main", { name: "Identity API" })).toBeTruthy();
    expect(screen.getByRole("link", { name: "Skip to content" })).toBeTruthy();
    expect(screen.getByRole("link", { name: "Settings" }).getAttribute("href")).toBe("/settings?tab=security");
    expect(screen.getByRole("link", { name: "Documentation" }).getAttribute("href")).toBe("https://docs.example.test/");
    expect(screen.getByRole("link", { name: "Documentation" }).getAttribute("aria-current")).toBe("page");
    expect(screen.getByRole("button", { name: "Unsafe" }).hasAttribute("href")).toBe(false);
    expect(screen.getByRole("button", { name: "Userinfo" }).hasAttribute("href")).toBe(false);
    const disabled = screen.getByRole("button", { name: "Disabled" }) as HTMLButtonElement;
    expect(disabled.disabled).toBe(true);
    expect(disabled.hasAttribute("href")).toBe(false);
    expect(screen.queryByRole("link", { name: "Disabled" })).toBeNull();
    expect(container.querySelector(".gb-open-platform__developer-portal-shell")).toBeTruthy();
    expect(container.querySelector("[data-developer-portal-shell]")?.getAttribute("aria-busy")).toBe("true");
    expect(container.innerHTML).not.toContain("tenant/portal");
    expect(container.querySelector('a[href^="javascript:"]')).toBeNull();
    expect(container.querySelector('a[href*="user:password"]')).toBeNull();

    fireEvent.click(screen.getByRole("button", { name: "Overview" }));
    expect(onSelect).toHaveBeenCalledWith(overview);
    expect(onNavigate).toHaveBeenCalledWith(overview, expect.anything());
  });
});

describe("open platform URL sanitization", () => {
  it("allows only internal references or approved external HTTPS URLs", () => {
    expect(sanitizeOpenPlatformInternalHref("/settings?tab=security")).toBe("/settings?tab=security");
    expect(sanitizeOpenPlatformInternalHref("../docs")).toBe("../docs");
    expect(sanitizeOpenPlatformInternalHref("#usage")).toBe("#usage");
    expect(sanitizeOpenPlatformInternalHref("?tab=usage")).toBe("?tab=usage");
    expect(sanitizeOpenPlatformInternalHref("//evil.example.test/path")).toBeUndefined();
    expect(sanitizeOpenPlatformInternalHref("https://example.test/path")).toBeUndefined();
    expect(sanitizeOpenPlatformInternalHref("/docs\\@evil.example.test")).toBeUndefined();

    expect(sanitizeOpenPlatformExternalHref("https://docs.example.test:443/guide")).toBe(
      "https://docs.example.test/guide",
    );
    expect(sanitizeOpenPlatformHref("https://docs.example.test")).toBe("https://docs.example.test/");
    expect(sanitizeOpenPlatformHref("/settings")).toBe("/settings");
  });

  it("rejects backslashes, userinfo, unapproved protocols, entities, encoded separators, and dangerous ports", () => {
    const unsafeUrls = [
      "https://example.test\\@evil.test",
      "https://example.test/%5c@evil.test",
      "https://user@example.test",
      "https://user:password@example.test",
      "https://example.test:22",
      "https://example.test:444",
      "https://example.test:3306",
      "https://example.test:6379",
      "http://example.test",
      "mailto:user@example.test",
      "tel:+123456789",
      "data:text/html,unsafe",
      "file:///etc/passwd",
      "ftp://example.test",
      "https:&#x2f;&#x2f;evil.test",
      "https://example.test/%2fadmin",
    ];
    for (const href of unsafeUrls) {
      expect(sanitizeOpenPlatformHref(href)).toBeUndefined();
    }
  });
});

describe("AppLifecycleStatusBadge", () => {
  it("maps known and unknown lifecycle states to stable labels and data attributes", () => {
    const { container } = render(
      <>
        <AppLifecycleStatusBadge status="active" />
        <AppLifecycleStatusBadge status="pending_review" />
        <AppLifecycleStatusBadge status="disabled" />
        <AppLifecycleStatusBadge status="unexpected-status" />
      </>,
    );

    expect(getAppLifecycleStatus("active")).toEqual({ status: "active", label: "Active", tone: "success" });
    expect(getAppLifecycleStatus("submitted")).toEqual({ status: "pending_review", label: "In review", tone: "warning" });
    expect(getAppLifecycleStatus("disabled")).toEqual({ status: "disabled", label: "Disabled", tone: "warning" });
    expect(getAppLifecycleStatus("unexpected-status")).toEqual({ status: "unknown", label: "Unknown", tone: "neutral" });
    expect(container.querySelector('[data-lifecycle-status="active"]')?.textContent).toBe("Active");
    expect(screen.getByLabelText("Application status: Active")).toBeTruthy();
    expect(screen.getByText("In review")).toBeTruthy();
    expect(screen.getByText("Unknown")).toBeTruthy();
  });
});

describe("ApiProductCard", () => {
  it("renders generic product metadata and preserves the callback product type", () => {
    interface Product extends ApiProduct {
      region: string;
    }

    const onOpen = vi.fn();
    const product: Product = {
      id: "identity-api",
      name: "Identity API",
      description: "Issue and inspect access tokens",
      category: "Identity",
      version: "2026-01",
      status: "active",
      region: "global",
    };
    const { container } = render(
      <ApiProductCard
        product={product}
        openLabel="View Identity API"
        onOpen={onOpen}
        actions={(value) => <span>{value.region}</span>}
      />,
    );

    const card = screen.getByRole("article", { name: "Identity API" });
    expect(within(card).getByText("Issue and inspect access tokens")).toBeTruthy();
    expect(within(card).getByText("Identity")).toBeTruthy();
    expect(within(card).getByText("2026-01")).toBeTruthy();
    expect(within(card).getByText("global")).toBeTruthy();
    expect(within(card).getByLabelText("Application status: Active")).toBeTruthy();
    expect(container.querySelector('[data-api-product-id="identity-api"]')).toBe(card);

    fireEvent.click(within(card).getByRole("button", { name: "View Identity API" }));
    expect(onOpen).toHaveBeenCalledWith(product, expect.anything());
  });

  it("renders a disabled product action as a button without a navigable href", () => {
    const onOpen = vi.fn();
    render(
      <ApiProductCard
        product={{ id: "disabled-api", name: "Disabled API", href: "https://docs.example.test/disabled" }}
        disabled
        onOpen={onOpen}
      />,
    );

    const action = screen.getByRole("button", { name: "Open API" }) as HTMLButtonElement;
    expect(action.disabled).toBe(true);
    expect(action.hasAttribute("href")).toBe(false);
    expect(screen.queryByRole("link", { name: "Open API" })).toBeNull();
    fireEvent.click(action);
    expect(onOpen).not.toHaveBeenCalled();
  });
});

describe("UsageMeter", () => {
  it("exposes clamped meter semantics, custom value text, and a warning level", () => {
    const { container, rerender } = render(
      <UsageMeter
        label="API calls"
        description="Current billing period"
        value={85}
        max={100}
        high={80}
        formatValue={(value, max) => `${value}/${max} calls`}
      />,
    );

    const meter = screen.getByRole("meter", { name: "API calls" });
    expect(meter.getAttribute("aria-valuemin")).toBe("0");
    expect(meter.getAttribute("aria-valuemax")).toBe("100");
    expect(meter.getAttribute("aria-valuenow")).toBe("85");
    expect(meter.getAttribute("aria-valuetext")).toBe("85/100 calls");
    expect(meter.getAttribute("data-usage-level")).toBe("warning");
    expect(meter.getAttribute("data-usage-value")).toBe("85");
    expect(screen.getByText("Current billing period")).toBeTruthy();
    expect(container.querySelector("meter")?.getAttribute("aria-hidden")).toBe("true");

    rerender(<UsageMeter label="API calls" value={150} max={100} />);
    expect(screen.getByRole("meter").getAttribute("aria-valuenow")).toBe("100");
    expect(screen.getByRole("meter").getAttribute("data-usage-level")).toBe("limit");
  });
});

describe("CredentialRevealPanel", () => {
  it("keeps a provided credential hidden until reveal, avoids live regions, and clears it after copy", async () => {
    const secret = "secret-value-for-tests";
    const onReveal = vi.fn();
    const onHide = vi.fn();
    const onCopy = vi.fn();
    const { container } = render(
      <CredentialRevealPanel
        label="Client secret"
        value={secret}
        autoHideDelayMs={false}
        onReveal={onReveal}
        onHide={onHide}
        onCopy={onCopy}
      />,
    );

    const panel = screen.getByRole("group", { name: "Client secret" });
    expect(panel.getAttribute("data-credential-revealed")).toBe("false");
    expect(container.innerHTML).not.toContain(secret);
    expect(screen.queryByRole("button", { name: "Copy credential" })).toBeNull();

    const reveal = screen.getByRole("button", { name: "Reveal credential" });
    expect(reveal.getAttribute("aria-expanded")).toBe("false");
    fireEvent.click(reveal);
    expect(onReveal).toHaveBeenCalledTimes(1);
    const revealedValue = screen.getByText(secret);
    expect(revealedValue.closest("[aria-live]")).toBeNull();
    expect(panel.getAttribute("data-credential-revealed")).toBe("true");

    fireEvent.click(screen.getByRole("button", { name: "Copy credential" }));
    await waitFor(() => expect(onCopy).toHaveBeenCalledWith(secret, secret));
    await waitFor(() => expect(container.innerHTML).not.toContain(secret));
    expect(panel.getAttribute("data-credential-revealed")).toBe("false");
    expect(onHide).toHaveBeenCalledTimes(1);
    expect((await screen.findByRole("status")).textContent).toBe("Copied");

    fireEvent.click(screen.getByRole("button", { name: "Reveal credential" }));
    expect(screen.getByText(secret)).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Hide credential" }));
    expect(onReveal).toHaveBeenCalledTimes(2);
    expect(onHide).toHaveBeenCalledTimes(2);
    expect(container.innerHTML).not.toContain(secret);
  });

  it("auto-hides a revealed credential after the configured delay", () => {
    vi.useFakeTimers();
    const secret = "auto-hide-secret";
    const onHide = vi.fn();
    const { container } = render(
      <CredentialRevealPanel label="Client secret" value={secret} autoHideDelayMs={1_000} onHide={onHide} />,
    );

    fireEvent.click(screen.getByRole("button", { name: "Reveal credential" }));
    expect(screen.getByText(secret)).toBeTruthy();
    act(() => vi.advanceTimersByTime(999));
    expect(screen.getByText(secret)).toBeTruthy();
    act(() => vi.advanceTimersByTime(1));
    expect(container.innerHTML).not.toContain(secret);
    expect(screen.getByRole("button", { name: "Reveal credential" }).getAttribute("aria-expanded")).toBe("false");
    expect(onHide).toHaveBeenCalledTimes(1);
  });

  it("loads an async credential only after an explicit request and reports safe failures", async () => {
    const secret = "async-secret-value";
    const loadValue = vi.fn(async () => secret);
    const { rerender } = render(<CredentialRevealPanel label="Signing key" loadValue={loadValue} />);

    expect(loadValue).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole("button", { name: "Reveal credential" }));
    expect(loadValue).toHaveBeenCalledTimes(1);
    expect(await screen.findByText(secret)).toBeTruthy();

    const failedLoad = vi.fn(async () => {
      throw new Error("raw token abc123");
    });
    rerender(<CredentialRevealPanel key="failed" label="Signing key" loadValue={failedLoad} />);
    fireEvent.click(screen.getByRole("button", { name: "Reveal credential" }));
    expect((await screen.findByRole("alert")).textContent).toBe("Unable to reveal credential.");
    expect(document.body.innerHTML).not.toContain("raw token abc123");
  });

  it("does not render a credential that resolves after unmount", async () => {
    const secret = "late-secret-value";
    let resolveCredential: (value: string) => void = () => undefined;
    const credentialPromise = new Promise<string>((resolve) => {
      resolveCredential = resolve;
    });
    const loadValue = vi.fn(() => credentialPromise);
    const view = render(<CredentialRevealPanel label="Client secret" loadValue={loadValue} />);

    fireEvent.click(screen.getByRole("button", { name: "Reveal credential" }));
    expect(loadValue).toHaveBeenCalledTimes(1);
    view.unmount();
    await act(async () => {
      resolveCredential(secret);
      await credentialPromise;
    });
    expect(document.body.innerHTML).not.toContain(secret);
  });
});

describe("open platform states", () => {
  it("renders accessible loading, retryable stable-code errors, and actionable empty states", () => {
    const onRetry = vi.fn();
    const { rerender } = render(<LoadingState label="Loading products" classNamespace="tenant/portal" />);
    const loading = screen.getByRole("status", { name: "Loading products" });
    expect(loading.getAttribute("aria-busy")).toBe("true");
    expect(loading.getAttribute("data-open-platform-state")).toBe("loading");

    rerender(
      <ErrorState
        error={{ code: "network_error", message: "connect ECONNREFUSED 10.0.0.1:3306" }}
        title="Unable to load"
        retryLabel="Try again"
        onRetry={onRetry}
      />,
    );
    const error = screen.getByRole("alert", {
      name: "Unable to load: Unable to reach the service. Check your connection and try again.",
    });
    expect(error.getAttribute("aria-live")).toBe("assertive");
    expect(error.getAttribute("data-error-code")).toBe("network_error");
    expect(document.body.innerHTML).not.toContain("10.0.0.1:3306");
    fireEvent.click(screen.getByRole("button", { name: "Try again" }));
    expect(onRetry).toHaveBeenCalledTimes(1);

    rerender(
      <ErrorState
        error={{
          code: "ECONNREFUSED",
          message: "Bearer top-secret password=hunter2",
          response: { body: { error: { code: "unrecognized", message: "client secret abc123" } } },
        }}
        title="Failed with token top-secret"
      />,
    );
    expect(getOpenPlatformErrorCode({ error: { code: "RATE_LIMITED", message: "raw server text" } })).toBe("rate_limited");
    expect(getOpenPlatformErrorMessage({ error: { code: "RATE_LIMITED", message: "raw server text" } })).toBe(
      "Too many requests. Please try again later.",
    );
    expect(getOpenPlatformErrorMessage("Request failed with Bearer top-secret")).toBe("Something went wrong.");
    expect(screen.getByRole("alert").getAttribute("data-error-code")).toBe("unknown");
    expect(screen.getByRole("alert").textContent).toBe("Something went wrongSomething went wrong.");
    expect(document.body.innerHTML).not.toContain("hunter2");
    expect(document.body.innerHTML).not.toContain("abc123");
    expect(document.body.innerHTML).not.toContain("raw server text");

    rerender(
      <EmptyState title="No API products" message="Create a product to get started">
        <button type="button">Create product</button>
      </EmptyState>,
    );
    expect(screen.getByRole("status", { name: "No API products" }).textContent).toContain("Create a product to get started");
    expect(screen.getByRole("button", { name: "Create product" })).toBeTruthy();
  });
});

describe("open platform fetch client", () => {
  it("uses the injected browser fetch, tenant, token, pagination, and no-store policy", async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = new URL(String(input));
      expect(url.pathname).toBe("/api/open/v1/audit-events");
      expect(url.searchParams.get("cursor")).toBe("cursor-1");
      expect(url.searchParams.get("limit")).toBe("2");
      expect(init?.cache).toBe("no-store");
      const headers = new Headers(init?.headers);
      expect(headers.get("cache-control")).toBe("no-store");
      expect(headers.get("x-tenant-id")).toBe("tenant-a");
      expect(headers.get("authorization")).toBe("Bearer token-a");
      return new Response(JSON.stringify({
        items: [{ id: "audit-1", action: "invoice.paid" }],
        next_cursor: "cursor-2",
        has_more: true,
        total: 3,
      }), { status: 200, headers: { "content-type": "application/json" } });
    });
    const client = createOpenPlatformClient({
      baseURL: "https://api.example.test",
      tenant: "tenant-a",
      token: "token-a",
      fetch: fetchMock,
    });

    await expect(client.listAuditEvents({ cursor: "cursor-1", limit: 2 })).resolves.toMatchObject({
      items: [{ id: "audit-1", action: "invoice.paid" }],
      nextCursor: "cursor-2",
      hasMore: true,
      total: 3,
    });
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("rejects insecure remote base URLs unless explicitly allowed", () => {
    const fetchMock = vi.fn(async () => new Response(JSON.stringify({ items: [], hasMore: false }), { status: 200 }));
    expect(() => createOpenPlatformClient({ baseURL: "http://api.example.test", fetch: fetchMock })).toThrow();
    expect(() => createOpenPlatformClient({ baseURL: "http://localhost:3000", fetch: fetchMock })).not.toThrow();
    expect(() => createOpenPlatformClient({
      baseURL: "http://api.example.test",
      allowInsecureHttp: true,
      fetch: fetchMock,
    })).not.toThrow();
  });

  it("reads webhooks, marketplace listings, and invoices without importing an SDK", async () => {
    const paths: string[] = [];
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const path = new URL(String(input)).pathname;
      paths.push(path);
      if (path.endsWith("/webhooks")) return new Response(JSON.stringify({ items: [{ id: "webhook-1" }], hasMore: false }), { status: 200 });
      if (path.endsWith("/marketplace/listings")) return new Response(JSON.stringify({ items: [{ id: "listing-1" }], hasMore: false }), { status: 200 });
      return new Response(JSON.stringify({ items: [{ id: "invoice-1" }], hasMore: false }), { status: 200 });
    });
    const client = createOpenPlatformClient({ baseUrl: "https://api.example.test/api/open/v1", fetch: fetchMock });

    await expect(client.listWebhooks()).resolves.toMatchObject({ items: [{ id: "webhook-1" }] });
    await expect(client.listMarketplaceListings()).resolves.toMatchObject({ items: [{ id: "listing-1" }] });
    await expect(client.listInvoices()).resolves.toMatchObject({ items: [{ id: "invoice-1" }] });
    expect(paths).toEqual([
      "/api/open/v1/webhooks",
      "/api/open/v1/marketplace/listings",
      "/api/open/v1/billing/invoices",
    ]);
  });

  it("does not expose server error bodies or response internals", async () => {
    const fetchMock = vi.fn(async () => new Response(JSON.stringify({
      error: { code: "INTERNAL_ERROR", message: "postgres password=hunter2" },
      details: { token: "raw-token" },
    }), { status: 500 }));
    const client = createOpenPlatformClient({ baseURL: "https://api.example.test", fetch: fetchMock });

    const error = await client.listInvoices().catch((value: unknown) => value);
    expect(error).toMatchObject({ status: 500, code: "internal_error" });
    expect(String((error as Error).message)).not.toContain("hunter2");
    expect(JSON.stringify(error)).not.toContain("raw-token");
  });
});

describe("open platform operations components", () => {
  it("composes the operations shell with loading, error, and safe empty states", () => {
    const onRetry = vi.fn();
    const { container, rerender } = render(
      <OpenPlatformOperationsShell title="Operations" loading loadingLabel="Loading invoices" />,
    );
    expect(screen.getByRole("status", { name: "Loading invoices" })).toBeTruthy();
    expect(container.querySelector("[data-open-platform-operations-shell]")).toBeTruthy();

    rerender(
      <OpenPlatformOperationsShell
        title="Operations"
        error={{ code: "network_error", message: "Bearer raw-token at 10.0.0.1" }}
        errorTitle="Unable to load"
        onRetry={onRetry}
      />,
    );
    expect(screen.getByRole("alert", { name: "Unable to load: Unable to reach the service. Check your connection and try again." })).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Retry" }));
    expect(onRetry).toHaveBeenCalledTimes(1);
    expect(container.innerHTML).not.toContain("raw-token");

    rerender(
      <OpenPlatformOperationsShell
        title="Operations"
        empty
        emptyTitle="No invoices"
        emptyMessage="internal response: postgres stack trace"
      />,
    );
    expect(screen.getByRole("status", { name: "No invoices" })).toBeTruthy();
    expect(container.innerHTML).not.toContain("postgres");
  });

  it("renders webhook and audit lists with cursor pagination", () => {
    const onWebhookCursor = vi.fn();
    const onAuditCursor = vi.fn();
    const { container } = render(
      <>
        <WebhookEndpointList
          webhooks={[{
            id: "webhook-1",
            name: "Order events",
            endpointUrl: "https://client.example.test/hooks/orders",
            status: "active",
            events: ["invoice.paid"],
            signingSecretReference: "vault://webhooks/orders",
          }]}
          cursor="cursor-1"
          nextCursor="cursor-2"
          hasMore
          onCursorChange={onWebhookCursor}
        />
        <OpenPlatformAuditEventList
          events={[{
            id: "audit-1",
            action: "invoice.paid",
            actor: { id: "operator-1", displayName: "Operator" },
            target: { type: "invoice", id: "invoice-1" },
            outcome: "success",
            occurredAt: "2026-01-01T00:00:00.000Z",
            metadata: { region: "cn-east", secretReference: "vault://audit/secret" },
          }]}
          cursor="audit-cursor-1"
          nextCursor="audit-cursor-2"
          hasMore
          onCursorChange={onAuditCursor}
        />
      </>,
    );

    expect(screen.getByRole("table", { name: "Webhook endpoints" })).toBeTruthy();
    expect(screen.getByRole("link", { name: "https://client.example.test/hooks/orders" })).toBeTruthy();
    expect(screen.getAllByText("invoice.paid")).toHaveLength(2);
    expect(screen.getByRole("table", { name: "Audit events" })).toBeTruthy();
    expect(screen.getByText("Operator")).toBeTruthy();
    expect(screen.getByText("region: cn-east")).toBeTruthy();
    expect(container.innerHTML).not.toContain("vault://webhooks/orders");
    expect(container.innerHTML).not.toContain("vault://audit/secret");

    const nextButtons = screen.getAllByRole("button", { name: "Next" });
    fireEvent.click(nextButtons[0]);
    fireEvent.click(nextButtons[1]);
    expect(onWebhookCursor).toHaveBeenCalledWith("cursor-2");
    expect(onAuditCursor).toHaveBeenCalledWith("audit-cursor-2");
  });

  it("renders a marketplace card and masks invoice settlement fields", () => {
    const onOpen = vi.fn();
    const { container } = render(
      <>
        <MarketplaceListingCard
          listing={{
            id: "listing-1",
            title: "Identity verification",
            description: "Reusable verification API",
            status: "published",
            partnerAccountId: "partner-1",
            productId: "product-1",
            priceIds: ["price-1"],
          }}
          onOpen={onOpen}
        />
        <InvoiceTable
          invoices={[{
            id: "invoice-1",
            status: "paid",
            periodStart: "2026-01-01T00:00:00.000Z",
            periodEnd: "2026-01-31T00:00:00.000Z",
            total: { amountMinor: 12345, currency: "CNY" },
            mainlandChina: {
              buyerName: "Example buyer",
              buyerBankAccount: "6222021234567890",
              buyerAddress: "Shanghai secret address",
              buyerPhone: "13800138000",
              settlementReference: "settlement-account-raw",
              secretReference: "vault://invoice/secret",
            },
          }]}
        />
      </>,
    );

    expect(screen.getByRole("article", { name: "Identity verification" })).toBeTruthy();
    expect(screen.getByText("Reusable verification API")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: /Open listing/ }));
    expect(onOpen).toHaveBeenCalled();
    expect(screen.getByRole("table", { name: "Invoices" })).toBeTruthy();
    expect(screen.getByText("CNY 123.45")).toBeTruthy();
    expect(screen.getByText("****7890")).toBeTruthy();
    expect(screen.getByText("****8000 · [redacted]")).toBeTruthy();
    expect(screen.getByText("[redacted] · [redacted]")).toBeTruthy();
    expect(container.innerHTML).not.toContain("6222021234567890");
    expect(container.innerHTML).not.toContain("Shanghai secret address");
    expect(container.innerHTML).not.toContain("13800138000");
    expect(container.innerHTML).not.toContain("settlement-account-raw");
    expect(container.innerHTML).not.toContain("vault://invoice/secret");
  });

  it("provides page pagination controls without coupling display to data loading", () => {
    const onPageChange = vi.fn();
    render(
      <InvoiceTable
        invoices={[{ id: "invoice-1", status: "draft", total: { amountMinor: 100, currency: "CNY" } }]}
        page={1}
        pageSize={1}
        total={2}
        onPageChange={onPageChange}
      />,
    );
    expect(screen.getByText("Page 1 of 2")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Next" }));
    expect(onPageChange).toHaveBeenCalledWith(2);
  });
  it("keeps list loading, error, and empty states presentation-only", () => {
    const onRetry = vi.fn();
    const { rerender } = render(<InvoiceTable invoices={[]} loading loadingLabel="Loading invoices" />);
    expect(screen.getByRole("status", { name: "Loading invoices" })).toBeTruthy();

    rerender(
      <InvoiceTable
        invoices={[]}
        error={{ code: "service_unavailable", message: "raw response body: postgres" }}
        errorTitle="Unable to load invoices"
        onRetry={onRetry}
      />,
    );
    expect(screen.getByRole("alert", { name: "Unable to load invoices: The service is temporarily unavailable." })).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Retry" }));
    expect(onRetry).toHaveBeenCalledTimes(1);

    rerender(<InvoiceTable invoices={[]} emptyTitle="No invoices" emptyMessage="No billing records" />);
    expect(screen.getByRole("status", { name: "No invoices" })).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Retry" })).toBeNull();
  });
});

describe("open platform sensitive value masks", () => {
  it("uses stable masks for bank, contact, address, settlement, and secret fields", () => {
    expect(maskOpenPlatformBankAccount("1234567890")).toBe("****7890");
    expect(maskOpenPlatformPhone("13800138000")).toBe("****8000");
    expect(maskOpenPlatformAddress("Shanghai")).toBe("[redacted]");
    expect(maskOpenPlatformSettlementReference("account-raw")).toBe("[redacted]");
    expect(maskOpenPlatformSecretReference("vault://secret/raw")).toBe("[redacted]");
    expect(maskOpenPlatformSubjectRef("subject-1234567890")).toBe("************7890");
    expect(maskOpenPlatformSubjectRef("ab")).toBe("**");
    expect(maskOpenPlatformSubjectRef("")).toBe("[redacted]");
    expect(maskOpenPlatformSubjectRef(undefined)).toBe("[redacted]");
    expect(maskOpenPlatformSubjectRef("********7890")).toBe("********7890");
  });
});

describe("ComplianceDataAssetList", () => {
  const dataAsset: OpenPlatformComplianceDataAsset = {
    id: "asset-1",
    code: "ASSET-IDV-001",
    name: "Customer identity profile",
    status: "active",
    classification: "personalData",
    personalData: true,
    sensitivePersonalData: true,
    legalBasis: "contract",
    residencyRegions: ["cn-east", "cn-north"],
    retentionPolicyId: "retention-policy-1",
    retentionDays: 365,
    crossBorder: true,
    evidence: [
      { reference: "vault://compliance/evidence/raw-token", kind: "document", recordedAt: "2026-01-01T00:00:00.000Z" },
    ],
    updatedAt: "2026-01-02T00:00:00.000Z",
  };

  it("renders masked data assets with masked evidence and cursor pagination", () => {
    const onCursorChange = vi.fn();
    const onRetry = vi.fn();
    const { container } = render(
      <ComplianceDataAssetList
        dataAssets={[dataAsset]}
        cursor="cursor-1"
        nextCursor="cursor-2"
        hasMore
        onCursorChange={onCursorChange}
        onRetry={onRetry}
      />,
    );

    expect(screen.getByRole("table", { name: "Data assets" })).toBeTruthy();
    expect(screen.getByText("Customer identity profile")).toBeTruthy();
    expect(screen.getByText("ASSET-IDV-001")).toBeTruthy();
    expect(container.querySelector('[data-data-asset-status="active"]')?.textContent).toBe("active");
    expect(container.querySelector('[data-personal-data="Yes"]')?.textContent).toBe("Yes · Sensitive");
    expect(screen.getByText("retention-policy-1 · 365 days")).toBeTruthy();
    expect(screen.getByText("cn-east, cn-north")).toBeTruthy();
    expect(container.querySelector('[data-evidence-kind="document"]')).toBeTruthy();
    expect(container.querySelector('[data-evidence-reference="masked"]')?.textContent).toBe("[redacted]");
    expect(container.innerHTML).not.toContain("vault://compliance/evidence/raw-token");

    fireEvent.click(screen.getByRole("button", { name: "Next" }));
    expect(onCursorChange).toHaveBeenCalledWith("cursor-2");
  });

  it("keeps data asset loading, error, and empty states presentation-only", () => {
    const onRetry = vi.fn();
    const { container, rerender } = render(
      <ComplianceDataAssetList dataAssets={[]} loading loadingLabel="Loading data assets" />,
    );
    expect(screen.getByRole("status", { name: "Loading data assets" })).toBeTruthy();

    rerender(
      <ComplianceDataAssetList
        dataAssets={[]}
        error={{ code: "forbidden", message: "postgres: vault://secret/raw" }}
        errorTitle="Unable to load data assets"
        onRetry={onRetry}
      />,
    );
    expect(
      screen.getByRole("alert", { name: "Unable to load data assets: You do not have permission to view this." }),
    ).toBeTruthy();
    expect(container.innerHTML).not.toContain("postgres");
    expect(container.innerHTML).not.toContain("vault://secret/raw");
    fireEvent.click(screen.getByRole("button", { name: "Retry" }));
    expect(onRetry).toHaveBeenCalledTimes(1);

    rerender(<ComplianceDataAssetList dataAssets={[]} emptyTitle="No data assets" emptyMessage="Register an asset" />);
    expect(screen.getByRole("status", { name: "No data assets" })).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Retry" })).toBeNull();
  });
});

describe("CompliancePrivacyRequestList", () => {
  const privacyRequest: OpenPlatformCompliancePrivacyRequest = {
    id: "privacy-request-1",
    requestType: "access",
    status: "inProgress",
    statusReason: "raw response body from postgres",
    subjectRef: "subject-1234567890",
    subjectRefMasked: "********7890",
    subjectCount: 2,
    dataAssetIds: ["asset-1", "asset-2"],
    identityVerification: {
      status: "verified",
      method: "idDocument",
      attempts: 1,
      verifiedByRef: "operator-raw-ref",
    },
    sla: { policyCode: "30d", responseDays: 30, dueAt: "2026-02-01T00:00:00.000Z", state: "dueSoon" },
    createdAt: "2026-01-01T00:00:00.000Z",
  };

  it("renders masked subject references, status, SLA, and identity state without internal text", () => {
    const { container } = render(<CompliancePrivacyRequestList privacyRequests={[privacyRequest]} />);

    expect(screen.getByRole("table", { name: "Privacy requests" })).toBeTruthy();
    expect(container.querySelector('[data-privacy-request-status="inProgress"]')).toBeTruthy();
    expect(container.querySelector('[data-subject-ref="masked"]')?.textContent).toBe("********7890");
    expect(container.querySelector('[data-identity-status="verified"]')).toBeTruthy();
    expect(container.querySelector('[data-sla-state="dueSoon"]')?.textContent).toBe("dueSoon");
    expect(screen.getByText("2 subjects")).toBeTruthy();
    expect(screen.getByText("asset-1, asset-2")).toBeTruthy();
    expect(container.innerHTML).not.toContain("subject-1234567890");
    expect(container.innerHTML).not.toContain("operator-raw-ref");
    expect(container.innerHTML).not.toContain("postgres");
  });

  it("keeps privacy request loading, error, and empty states presentation-only", () => {
    const onRetry = vi.fn();
    const { container, rerender } = render(
      <CompliancePrivacyRequestList privacyRequests={[]} loading loadingLabel="Loading privacy requests" />,
    );
    expect(screen.getByRole("status", { name: "Loading privacy requests" })).toBeTruthy();

    rerender(
      <CompliancePrivacyRequestList
        privacyRequests={[]}
        error={{ code: "conflict", message: "Bearer raw-token at 10.0.0.1" }}
        errorTitle="Unable to load privacy requests"
        onRetry={onRetry}
      />,
    );
    expect(
      screen.getByRole("alert", {
        name: "Unable to load privacy requests: The resource changed. Refresh and try again.",
      }),
    ).toBeTruthy();
    expect(container.innerHTML).not.toContain("raw-token");
    fireEvent.click(screen.getByRole("button", { name: "Retry" }));
    expect(onRetry).toHaveBeenCalledTimes(1);

    rerender(<CompliancePrivacyRequestList privacyRequests={[]} emptyTitle="No privacy requests" />);
    expect(screen.getByRole("status", { name: "No privacy requests" })).toBeTruthy();
  });
});

describe("ComplianceReportPanel", () => {
  const report: OpenPlatformComplianceReport = {
    contractVersion: 1,
    generatedAt: "2026-01-01T00:00:00.000Z",
    period: { from: "2025-12-01T00:00:00.000Z", to: "2025-12-31T00:00:00.000Z" },
    redaction: { placeholder: "[redacted]", applies: true },
    dataCatalog: {
      assets: { total: 3, counts: { active: 2, retired: 1 } },
      personalDataAssets: 2,
      sensitivePersonalDataAssets: 1,
      crossBorderAssets: 1,
    },
    privacyRequests: {
      requests: { total: 2, counts: { fulfilled: 1, inProgress: 1 } },
      awaitingIdentityVerification: 1,
      breached: 0,
      oldestOpenDays: 4,
    },
    retention: { recordsDeleted: 12, recordsAnonymized: 3 },
    gaps: [{ code: "privacyRequestSlaBreached", count: 1, resourceIds: ["privacy-request-1"] }],
    limitations: ["The report records operator-declared status only."],
  };

  it("renders a redacted report with count breakdowns, gaps, and limitations", () => {
    const { container } = render(<ComplianceReportPanel report={report} caption="December 2025" />);

    expect(screen.getByRole("region", { name: "Compliance report" })).toBeTruthy();
    expect(container.querySelector('[data-report-metric="contractVersion"]')?.textContent).toBe("1");
    expect(container.querySelector('[data-report-metric="generatedAt"]')?.textContent).toBe("2026-01-01T00:00:00.000Z");
    expect(container.querySelector('[data-report-metric="redaction"]')?.getAttribute("data-redaction-applies")).toBe("true");
    expect(container.querySelector('[data-report-section="dataCatalog"] [data-report-total="assets"]')?.textContent).toBe("3");
    expect(container.querySelector('[data-report-count="assets.active"]')?.textContent).toBe("2");
    expect(container.querySelector('[data-report-count="assets.retired"]')?.textContent).toBe("1");
    expect(container.querySelector('[data-report-metric="sensitivePersonalDataAssets"]')?.textContent).toBe("1");
    expect(container.querySelector('[data-report-metric="oldestOpenDays"]')?.textContent).toBe("4");
    expect(container.querySelector('[data-gap-code="privacyRequestSlaBreached"]')?.textContent).toContain("1");
    expect(screen.getByText("The report records operator-declared status only.")).toBeTruthy();
  });

  it("renders report loading, error, and empty states without exposing raw responses", () => {
    const onRetry = vi.fn();
    const { container, rerender } = render(<ComplianceReportPanel loading loadingLabel="Loading report" />);
    expect(screen.getByRole("status", { name: "Loading report" })).toBeTruthy();

    rerender(
      <ComplianceReportPanel
        error={{ code: "service_unavailable", message: "postgres stack trace: password=hunter2" }}
        errorTitle="Unable to load report"
        onRetry={onRetry}
      />,
    );
    expect(
      screen.getByRole("alert", { name: "Unable to load report: The service is temporarily unavailable." }),
    ).toBeTruthy();
    expect(container.innerHTML).not.toContain("hunter2");
    expect(container.innerHTML).not.toContain("postgres");
    fireEvent.click(screen.getByRole("button", { name: "Retry" }));
    expect(onRetry).toHaveBeenCalledTimes(1);

    rerender(<ComplianceReportPanel emptyTitle="No compliance report" />);
    expect(screen.getByRole("status", { name: "No compliance report" })).toBeTruthy();
  });
});

describe("OutboxStatusList and DomainEventMonitor", () => {
  const domainEvent: OpenPlatformDomainEventSummary = {
    eventId: "evt-1",
    type: "webhook.dispatch",
    resource: { type: "webhook", id: "webhook-1" },
    status: "failed",
    attempt: 3,
    occurredAt: "2026-01-01T00:00:00.000Z",
    errorCode: "DELIVERY_TIMEOUT",
    nextAttemptAt: "2026-01-01T01:00:00.000Z",
    payload: { phone: "13800138000" },
    data: { subjectRef: "subject-1234567890" },
    leaseId: "lease-raw-1",
    actorId: "actor-raw-1",
  };

  it("paginates outbox events by sequence and never renders payload, data, lease, or actor", () => {
    const onCursorChange = vi.fn();
    const { container } = render(
      <OutboxStatusList events={[domainEvent]} nextSequence={42} hasMore onCursorChange={onCursorChange} />,
    );

    expect(screen.getByRole("table", { name: "Outbox events" })).toBeTruthy();
    expect(container.querySelector('[data-domain-event-status="failed"]')).toBeTruthy();
    expect(container.querySelector('[data-attempt="3"]')?.textContent).toBe("3");
    expect(container.querySelector('[data-error-code="DELIVERY_TIMEOUT"]')?.textContent).toBe("DELIVERY_TIMEOUT");
    expect(container.innerHTML).not.toContain("13800138000");
    expect(container.innerHTML).not.toContain("subject-1234567890");
    expect(container.innerHTML).not.toContain("lease-raw-1");
    expect(container.innerHTML).not.toContain("actor-raw-1");

    fireEvent.click(screen.getByRole("button", { name: "Next" }));
    expect(onCursorChange).toHaveBeenCalledWith("42");
  });

  it("renders a safe retry summary and keeps retry failures out of the DOM", () => {
    const onRetryEvents = vi.fn();
    const retrySummary: OpenPlatformDomainEventRetrySummary = {
      flushed: 2,
      replayed: true,
      results: [
        { eventId: "evt-1", delivered: 1, deadLettered: false },
        { eventId: "evt-2", delivered: 0, deadLettered: true },
      ],
      leaseId: "lease-raw-1",
      actorId: "actor-raw-1",
      data: { payload: "raw-payload" },
    };
    const { container } = render(
      <DomainEventMonitor
        events={[domainEvent]}
        onRetryEvents={onRetryEvents}
        retrySummary={retrySummary}
      />,
    );

    expect(container.querySelector('[data-retry-metric="flushed"]')?.textContent).toBe("2");
    expect(container.querySelector('[data-retry-metric="replayed"]')?.textContent).toBe("Yes");
    expect(container.querySelector('[data-retry-event-id="evt-1"]')?.textContent).toContain("delivered 1");
    expect(container.querySelector('[data-retry-event-id="evt-2"] [data-retry-dead-lettered="true"]')).toBeTruthy();
    expect(container.innerHTML).not.toContain("lease-raw-1");
    expect(container.innerHTML).not.toContain("actor-raw-1");
    expect(container.innerHTML).not.toContain("raw-payload");

    fireEvent.click(screen.getByRole("button", { name: "Retry delivery" }));
    expect(onRetryEvents).toHaveBeenCalledTimes(1);
  });

  it("keeps outbox loading, error, and empty states presentation-only", () => {
    const onRetry = vi.fn();
    const { container, rerender } = render(<OutboxStatusList events={[]} loading loadingLabel="Loading outbox" />);
    expect(screen.getByRole("status", { name: "Loading outbox" })).toBeTruthy();

    rerender(
      <OutboxStatusList
        events={[]}
        error={{ code: "timeout", message: "connect ECONNREFUSED 127.0.0.1:5432 password=hunter2" }}
        errorTitle="Unable to load outbox"
        onRetry={onRetry}
      />,
    );
    expect(screen.getByRole("alert", { name: "Unable to load outbox: The request timed out. Please try again." })).toBeTruthy();
    expect(container.innerHTML).not.toContain("hunter2");
    expect(container.innerHTML).not.toContain("5432");
    fireEvent.click(screen.getByRole("button", { name: "Retry" }));
    expect(onRetry).toHaveBeenCalledTimes(1);

    rerender(<OutboxStatusList events={[]} emptyTitle="No outbox events" />);
    expect(screen.getByRole("status", { name: "No outbox events" })).toBeTruthy();
  });
});

describe("open platform compliance operations composition", () => {
  it("composes compliance and domain event blocks inside the operations shell", () => {
    const { container } = render(
      <OpenPlatformOperationsShell
        title="Compliance operations"
        activeItemId="compliance"
        navigation={[
          { id: "compliance", label: "Compliance" },
          { id: "outbox", label: "Outbox" },
        ]}
      >
        <ComplianceDataAssetList dataAssets={[{ id: "asset-1", name: "Billing profile", status: "active" }]} />
        <CompliancePrivacyRequestList privacyRequests={[{ id: "privacy-1", status: "fulfilled" }]} />
        <ComplianceReportPanel
          report={{ contractVersion: 1, redaction: { applies: true, placeholder: "[redacted]" } }}
        />
        <DomainEventMonitor events={[{ eventId: "evt-1", status: "published", attempt: 1 }]} />
      </OpenPlatformOperationsShell>,
    );

    expect(screen.getByRole("main", { name: "Compliance operations" })).toBeTruthy();
    expect(screen.getByRole("table", { name: "Data assets" })).toBeTruthy();
    expect(screen.getByRole("table", { name: "Privacy requests" })).toBeTruthy();
    expect(screen.getByRole("region", { name: "Compliance report" })).toBeTruthy();
    expect(screen.getByRole("table", { name: "Outbox events" })).toBeTruthy();
    expect(container.querySelectorAll("[data-open-platform-resource]").length).toBe(4);
    expect(container.querySelector("[data-open-platform-monitor=\"domain-events\"]")).toBeTruthy();
  });
});

describe("open platform compliance and domain event client", () => {
  it("reads compliance resources and domain events with no-store requests", async () => {
    const requests: string[] = [];
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = new URL(String(input));
      requests.push(`${url.pathname}${url.search}`);
      expect(init?.cache).toBe("no-store");
      expect(new Headers(init?.headers).get("cache-control")).toBe("no-store");
      if (url.pathname.endsWith("/compliance/report")) {
        return new Response(JSON.stringify({ contractVersion: 1, generatedAt: "2026-01-01T00:00:00.000Z" }), { status: 200 });
      }
      if (url.pathname.endsWith("/domain-events")) {
        return new Response(JSON.stringify({
          items: [{ eventId: "evt-1", type: "webhook.dispatch", status: "failed" }],
          nextSequence: 7,
          hasMore: true,
        }), { status: 200 });
      }
      return new Response(JSON.stringify({ items: [{ id: "record-1" }], hasMore: false }), { status: 200 });
    });
    const client = createOpenPlatformClient({ baseURL: "https://api.example.test", fetch: fetchMock });

    await expect(client.compliance.dataAssets.list({ limit: 2, status: "active" })).resolves.toMatchObject({
      items: [{ id: "record-1" }],
    });
    await expect(client.compliance.privacyRequests.list({ cursor: "cursor-1" })).resolves.toMatchObject({
      items: [{ id: "record-1" }],
    });
    await expect(client.compliance.report.get({ from: "2025-12-01", to: "2025-12-31" })).resolves.toMatchObject({
      contractVersion: 1,
    });
    await expect(client.domainEvents.list({ limit: 1 })).resolves.toMatchObject({
      items: [{ eventId: "evt-1" }],
      nextCursor: "7",
      nextSequence: 7,
      hasMore: true,
    });

    expect(requests).toEqual([
      "/api/open/v1/compliance/data-assets?limit=2&status=active",
      "/api/open/v1/compliance/privacy-requests?cursor=cursor-1",
      "/api/open/v1/compliance/report?from=2025-12-01&to=2025-12-31",
      "/api/open/v1/domain-events?limit=1",
    ]);
  });

  it("sends an idempotency key and a whitelisted body when relaying domain event retries", async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = new URL(String(input));
      expect(url.pathname).toBe("/api/open/v1/domain-events/retry");
      expect(init?.method).toBe("POST");
      const headers = new Headers(init?.headers);
      expect(headers.get("idempotency-key")).toMatch(/^domain-event-retry-/u);
      expect(JSON.parse(String(init?.body))).toEqual({ eventType: "webhook.dispatch", limit: 5 });
      return new Response(JSON.stringify({
        flushed: 1,
        replayed: false,
        results: [{ eventId: "evt-1", delivered: 2, deadLettered: false }],
      }), { status: 200 });
    });
    const client = createOpenPlatformClient({ baseURL: "https://api.example.test", fetch: fetchMock });

    await expect(client.domainEvents.retry({ eventType: "webhook.dispatch", limit: 5 })).resolves.toEqual({
      flushed: 1,
      replayed: false,
      results: [{ eventId: "evt-1", delivered: 2, deadLettered: false }],
    });
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("rejects unsafe retry payloads and maps compliance failures to stable codes", async () => {
    const fetchMock = vi.fn(async () => new Response(JSON.stringify({
      error: { code: "VALIDATION_ERROR", message: "payload secret=hunter2" },
    }), { status: 403 }));
    const client = createOpenPlatformClient({ baseURL: "https://api.example.test", fetch: fetchMock });

    await expect(client.retryDomainEvents({ eventType: "not a type" })).rejects.toMatchObject({
      code: "request_error",
    });
    const failure = await client.listComplianceDataAssets().catch((value: unknown) => value);
    expect(failure).toMatchObject({ status: 403, code: "forbidden" });
    expect(String((failure as Error).message)).not.toContain("hunter2");
    expect(JSON.stringify(failure)).not.toContain("hunter2");
  });
});
