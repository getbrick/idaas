import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import {
  AdminShell,
  ApplicationClientList,
  ApplicationExternalIdentityList,
  ApplicationList,
  ApplicationPlatformList,
  AuditEventList,
  RoleList,
  UserList,
  type AdminApplicationClient,
  type AdminApplicationPlatform,

 } from "../src/admin/index.js";


afterEach(() => cleanup());

describe("admin components", () => {
  it("renders an accessible shell and safe class namespace", () => {
    const onNavigate = vi.fn();
    const { container } = render(
      <AdminShell
        title="Operations"
        classNamespace="tenant/admin"
        navigation={[{ id: "users", label: "Users" }, { id: "roles", label: "Roles" }]}
        activeItemId="users"
        onNavigate={onNavigate}
      >
        <p>Workspace</p>
      </AdminShell>,
    );

    expect(screen.getByRole("navigation", { name: "Admin navigation" })).toBeTruthy();
    const usersButton = screen.getByRole("button", { name: "Users" });
    expect(usersButton.getAttribute("aria-current")).toBe("page");
    fireEvent.click(usersButton);
    expect(onNavigate).toHaveBeenCalledWith(expect.objectContaining({ id: "users" }));
    expect(container.querySelector(".gb-admin__shell")).toBeTruthy();
    expect(container.innerHTML).not.toContain("tenant/admin");
  });

  it("renders captions and local contracts for each list", () => {
    render(
      <>
        <UserList
          users={[{ id: "user-1", name: "Ada", email: "ada@example.com", status: "active", roles: ["admin"] }]}
        />
        <RoleList roles={[{ id: "role-1", name: "Editor", permissions: ["project:read"] }]} />
        <AuditEventList
          events={[
            {
              id: "event-1",
              event: "user.updated",
              occurredAt: "2026-01-01T00:00:00.000Z",
              userId: "user-1",
              detail: { field: "name" },
            },
          ]}
        />
      </>,
    );

    expect(screen.getByRole("table", { name: "Users" }).querySelector("caption")?.textContent).toBe("Users");
    expect(screen.getByRole("table", { name: "Roles" }).querySelector("caption")?.textContent).toBe("Roles");
    expect(screen.getByRole("table", { name: "Audit events" }).querySelector("caption")?.textContent).toBe(
      "Audit events",
    );
    expect(screen.getByText("ada@example.com")).toBeTruthy();
    expect(screen.getByText("project:read")).toBeTruthy();
    expect(screen.getByText("user.updated")).toBeTruthy();
  });

  it("exposes loading, empty, and error states with named retry controls", () => {
    const onRetry = vi.fn();
    const { rerender } = render(<UserList users={[]} isLoading loadingLabel="Loading users" />);
    expect(screen.getByRole("status", { name: "Loading users" })).toBeTruthy();
    expect(screen.getByRole("table", { name: "Users" }).getAttribute("aria-busy")).toBe("true");

    rerender(<UserList users={[]} />);
    expect(screen.getByRole("status", { name: "Nothing to show" })).toBeTruthy();

    rerender(<UserList users={[]} error="Request failed" retryLabel="Try again" onRetry={onRetry} />);
    expect(screen.getByRole("alert")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Try again" }));
    expect(onRetry).toHaveBeenCalledTimes(1);
  });

  it("renders application summaries, platform details, pagination, and row actions", () => {
    const onApplicationAction = vi.fn();
    const onPlatformAction = vi.fn();
     const onPageChange = vi.fn();
     const unsafePlatform = {
       id: "platform-1",
       applicationId: "app-1",
       type: "wechat_mini_program",
       externalAppId: "wx-alpha",
       displayName: "Alpha WeChat",
       loginMode: "qr",
       status: "disabled",
       credentialConfigured: true,
       secret: "raw-platform-secret",
       secretRef: "vault://applications/alpha",
     } as AdminApplicationPlatform & { secret: string; secretRef: string };
     const { container } = render(

      <>
        <ApplicationList
          applications={[
            {
              id: "app-1",
              name: "Alpha",
              slug: "alpha",
              status: "active",
              description: "Primary application",
              createdAt: "2026-01-01T00:00:00.000Z",
              updatedAt: "2026-01-02T00:00:00.000Z",
            },
          ]}
          page={1}
          pageSize={1}
          total={2}
          onPageChange={onPageChange}
          renderActions={(application) => (
            <button type="button" onClick={() => onApplicationAction(application.id)}>
              Edit application
            </button>
          )}
        />
         <ApplicationPlatformList
           platforms={[unsafePlatform]}

          renderActions={(platform) => (
            <button type="button" onClick={() => onPlatformAction(platform.type)}>
              Edit platform
            </button>
          )}
        />
      </>,
    );

    expect(screen.getByRole("table", { name: "Applications" }).querySelector("caption")?.textContent).toBe(
      "Applications",
    );
    expect(screen.getByRole("table", { name: "Application platforms" }).querySelector("caption")?.textContent).toBe(
      "Application platforms",
    );
    expect(screen.getByText("Alpha")).toBeTruthy();
    expect(screen.getByText("alpha")).toBeTruthy();
    expect(screen.getByText("Primary application")).toBeTruthy();
    expect(screen.getByText("wechat_mini_program")).toBeTruthy();
    expect(screen.getByText("wx-alpha")).toBeTruthy();
    expect(screen.getByText("Alpha WeChat")).toBeTruthy();
    expect(screen.getByText("qr")).toBeTruthy();
    expect(screen.getAllByText("disabled")).toHaveLength(2);
    expect(screen.getByText("Configured")).toBeTruthy();
    expect(container.innerHTML).not.toContain("raw-platform-secret");
    expect(container.innerHTML).not.toContain("vault://applications/alpha");

    fireEvent.click(screen.getByRole("button", { name: "Edit application" }));
    expect(onApplicationAction).toHaveBeenCalledWith("app-1");
    fireEvent.click(screen.getByRole("button", { name: "Edit platform" }));
    expect(onPlatformAction).toHaveBeenCalledWith("wechat_mini_program");
    fireEvent.click(screen.getByRole("button", { name: "Next" }));
    expect(onPageChange).toHaveBeenCalledWith(2);
  });

   it("renders managed OIDC clients without exposing secrets", () => {
     const onClientAction = vi.fn();
     const unsafeClient = {
       id: "client-record-1",
       applicationId: "app-1",
       clientId: "alpha-client",
       status: "active",
         redirectUris: ["https://alpha.example.test/callback?token=raw-uri-secret", "https://alpha.example.test/callback"],
       postLogoutRedirectUris: ["https://alpha.example.test/logout"],
       grantTypes: ["authorization_code", "refresh_token"],
       responseTypes: ["code"],
       scopes: ["openid", "profile"],
       tokenEndpointAuthMethod: "client_secret_basic",
       requirePkce: true,
       hasSecret: true,
       createdAt: "2026-01-01T00:00:00.000Z",
       updatedAt: "2026-01-02T00:00:00.000Z",
       secret: "raw-client-secret",
       secretRef: "vault://applications/alpha/client",
     } as AdminApplicationClient & { secret: string; secretRef: string };
     const { container } = render(

      <ApplicationClientList
        classNamespace="tenant/admin"
         clients={[unsafeClient]}

        renderActions={(client) => (
          <button type="button" onClick={() => onClientAction(client.id)}>
            Edit client
          </button>
        )}
      />,
    );

    const table = screen.getByRole("table", { name: "Application clients" });
    expect(table.querySelector("caption")?.textContent).toBe("Application clients");
    expect(within(table).getByText("alpha-client")).toBeTruthy();
    expect(within(table).getByText("app-1")).toBeTruthy();
     expect(within(table).getAllByText("active")).toHaveLength(2);

    expect(within(table).getByText("authorization_code")).toBeTruthy();
    expect(within(table).getByText("refresh_token")).toBeTruthy();
    expect(within(table).getByText("code")).toBeTruthy();
    expect(within(table).getByText("openid")).toBeTruthy();
    expect(within(table).getByText("profile")).toBeTruthy();
    expect(within(table).getByText("client_secret_basic")).toBeTruthy();
    expect(within(table).getByText("Required")).toBeTruthy();
    expect(within(table).getByText("Configured")).toBeTruthy();
    expect(within(table).getByText("2026-01-01T00:00:00.000Z")).toBeTruthy();
    expect(within(table).getByText("2026-01-02T00:00:00.000Z")).toBeTruthy();
    expect(table.querySelector('[data-require-pkce="true"]')?.textContent).toBe("Required");
    expect(table.querySelector('[data-has-secret="true"]')?.textContent).toBe("Configured");
    expect(container.querySelector(".gb-admin__application-client-list")).toBeTruthy();
    expect(container.innerHTML).not.toContain("tenant/admin");
     expect(container.innerHTML).not.toContain("raw-client-secret");
     expect(container.innerHTML).not.toContain("raw-uri-secret");
     expect(container.innerHTML).not.toContain("vault://applications/alpha/client");

    fireEvent.click(within(table).getByRole("button", { name: "Edit client" }));
    expect(onClientAction).toHaveBeenCalledWith("client-record-1");
  });

  it("renders application type, lifecycle state, readiness, versions, and cursor pagination", () => {
    const onCursorChange = vi.fn();
    const { container } = render(
      <ApplicationList
        applications={[
          {
            id: "app-1",
            name: "Native app",
            slug: "native-app",
            applicationType: "native",
            status: "active",
            lifecycleStatus: "active",
            readiness: {
              status: "not_ready",
              checks: [{ name: "Client credentials", status: "not_ready", message: "raw-secret" }],
            },
            effectiveStatus: "not_ready",
            version: 4,
            etag: "application:app-1:4",
          },
        ]}
        cursor="cursor-1"
        nextCursor="cursor-2"
        hasMore
        onCursorChange={onCursorChange}
      />,
    );

    const table = screen.getByRole("table", { name: "Applications" });
    expect(within(table).getByText("native")).toBeTruthy();
    expect(table.querySelector('[data-effective-status="not_ready"]')).toBeTruthy();
    expect(table.querySelector('[data-readiness="not_ready"]')).toBeTruthy();
    expect(within(table).getByText("4")).toBeTruthy();
    expect(within(table).getByText("application:app-1:4")).toBeTruthy();
    expect(container.querySelector('[data-pagination-mode="cursor"]')).toBeTruthy();
    expect(container.innerHTML).not.toContain("raw-secret");

    fireEvent.click(screen.getByRole("button", { name: "Next" }));
    expect(onCursorChange).toHaveBeenCalledWith("cursor-2");
  });

  it("shows safe client metadata and callback-only rotation controls", () => {
    const onRotateSecret = vi.fn();
    const { container } = render(
      <>
        <ApplicationPlatformList
          platforms={[
            {
              id: "platform-1",
              applicationId: "app-1",
              type: "web",
              status: "active",
              lifecycleStatus: "active",
              readiness: "ready",
              effectiveStatus: "active",
              credentialConfigured: true,
              secretStatus: "rotating",
              secretVersion: 2,
              version: 3,
              etag: "application-platform:platform-1:3",
            },
          ]}
          onRotateSecret={onRotateSecret}
        />
        <ApplicationClientList
          clients={[
            {
              id: "client-1",
              applicationId: "app-1",
              clientId: "private-client",
              status: "active",
              lifecycleStatus: "active",
              readiness: "ready",
              effectiveStatus: "active",
              tokenEndpointAuthMethod: "private_key_jwt",
              tokenEndpointAuthSigningAlg: "ES256",
              jwksUri: "https://client.example.test/jwks.json",
              keyId: "key-1",
              hasSecret: false,
              secretStatus: "not_required",
              secretVersion: 0,
              version: 5,
              etag: "application-client:client-1:5",
              privateKeyRef: "vault://clients/private-client",
              rawPrivateKey: "raw-private-key",
            } as AdminApplicationClient & { privateKeyRef: string; rawPrivateKey: string },
          ]}
          onRotateSecret={onRotateSecret}
        />
      </>,
    );

     expect(screen.getByText("rotating")).toBeTruthy();
     expect(screen.getByText("2")).toBeTruthy();
     expect(screen.getAllByText("Not required")).toHaveLength(2);
     expect(screen.getByText("ES256")).toBeTruthy();
    expect(screen.getByText("https://client.example.test/jwks.json")).toBeTruthy();
    expect(screen.getByText("key-1")).toBeTruthy();
    const rotationButtons = screen.getAllByRole("button", { name: "Rotate secret" });
    expect(rotationButtons).toHaveLength(2);
    expect(rotationButtons[1].hasAttribute("disabled")).toBe(true);

    fireEvent.click(rotationButtons[0]);
    expect(onRotateSecret).toHaveBeenCalledWith({
      kind: "application-platform",
      id: "platform-1",
      applicationId: "app-1",
       version: 3,
       expectedVersion: 3,
       etag: "application-platform:platform-1:3",
     });
    expect(container.innerHTML).not.toContain("vault://clients/private-client");
    expect(container.innerHTML).not.toContain("raw-private-key");
  });

  it("renders external identities as a cursor-paginated read-only list", () => {
    const onCursorChange = vi.fn();
    const { container } = render(
      <ApplicationExternalIdentityList
        identities={[
          {
            id: "identity-1",
            applicationId: "app-1",
            platformId: "platform-1",
            provider: "wechat",
            platform: "wechat_mini_program",
            appId: "wx-app",
            subject: "subject-1",
            openid: "openid-1",
            unionid: "unionid-1",
            displayName: "External user",
            email: "user@example.test",
            scopes: ["profile"],
            version: 2,
            accessToken: "raw-provider-token",
            refreshToken: "raw-refresh-token",
            sessionKey: "raw-session-key",
            privateKeyRef: "vault://identity/key",
          } as never,
        ]}
        cursor="identity-cursor-1"
        nextCursor="identity-cursor-2"
        hasMore
        onCursorChange={onCursorChange}
      />,
    );

    const table = screen.getByRole("table", { name: "External identities" });
    expect(table.getAttribute("aria-readonly")).toBe("true");
    expect(within(table).getByText("wechat")).toBeTruthy();
    expect(within(table).getByText("subject-1")).toBeTruthy();
    expect(within(table).getByText("openid-1")).toBeTruthy();
    expect(within(table).getByText("profile")).toBeTruthy();
    expect(container.querySelector("[data-admin-read-only='true']")).toBeTruthy();
    expect(container.innerHTML).not.toContain("raw-provider-token");
    expect(container.innerHTML).not.toContain("raw-refresh-token");
    expect(container.innerHTML).not.toContain("raw-session-key");
    expect(container.innerHTML).not.toContain("vault://identity/key");

    fireEvent.click(screen.getByRole("button", { name: "Next" }));
    expect(onCursorChange).toHaveBeenCalledWith("identity-cursor-2");
  });

  it("disables rotation for archived resources and normalizes readiness projections", () => {
    const onRotateSecret = vi.fn();
    render(
      <>
        <ApplicationPlatformList
          platforms={[{
            id: "platform-archived",
            applicationId: "app-1",
            type: "web",
            status: "archived",
            lifecycleStatus: "archived",
            credentialConfigured: true,
          }]}
          onRotateSecret={onRotateSecret}
        />
        <ApplicationClientList
          clients={[{
            id: "client-archived",
            applicationId: "app-1",
            clientId: "client-archived",
            status: "archived",
            lifecycleStatus: "archived",
            tokenEndpointAuthMethod: "client_secret_basic",
            hasSecret: true,
          }]}
          onRotateSecret={onRotateSecret}
        />
      </>,
    );
    const buttons = screen.getAllByRole("button", { name: "Rotate secret" });
    expect(buttons).toHaveLength(2);
    expect(buttons.every((button) => button.hasAttribute("disabled"))).toBe(true);
  });
});
