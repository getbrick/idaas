import { createRoot } from "react-dom/client";
import { GetbrickAuthProvider, AuthForm, SignOutButton, useGetbrickAuth, type GetbrickClient } from "@getbrick/idaas-ui";
import { createElement as h, useEffect, useState } from "react";

function SessionBadge() {
  const auth = useGetbrickAuth() as GetbrickClient;
  const [user, setUser] = useState<null | { email?: string; name?: string }>(null);

  useEffect(() => {
    let alive = true;
    void (auth as unknown as { authClient?: unknown }).authClient;
    fetch("http://localhost:3000/api/auth/get-session", { credentials: "include" })
      .then((r) => r.json())
      .then((session: { user?: { email: string; name: string } } | null) => {
        if (alive) setUser(session?.user ?? null);
      })
      .catch(() => undefined);
    return () => {
      alive = false;
    };
  }, [auth]);

  if (!user) return h("p", { className: "gb-auth-card__subtitle" }, "Not signed in");
  return h(
    "div",
    { style: { textAlign: "center" } },
    h("p", { className: "gb-auth-card__subtitle" }, `Signed in as ${user.email}`),
    h(SignOutButton, { onSignedOut: () => window.location.reload() }),
  );
}

function Page() {
  return h(
    "div",
    { style: { minHeight: "100vh", display: "grid", placeItems: "center", background: "#eef2f7" } },
    h(
      "div",
      { style: { display: "grid", gap: 20, justifyItems: "center" } },
      h(
        GetbrickAuthProvider,
        { baseURL: "http://localhost:3000", theme: { primary: "#2563eb" } },
        h("div", { style: { display: "grid", gap: 16, gridTemplateColumns: "auto auto", alignItems: "start" } },
          h(AuthForm, {
            mode: "sign-in",
            subtitle: "demo@getbrick.dev / supersecret123",
            onSuccess: () => window.location.reload(),
          }),
          h(AuthForm, {
            mode: "sign-up",
            subtitle: "Create a new account",
            theme: { primary: "#059669" },
            onSuccess: () => window.location.reload(),
          }),
        ),
      ),
      h(SessionBadge, null),
    ),
  );
}

createRoot(document.getElementById("root")!).render(h(Page, null));
