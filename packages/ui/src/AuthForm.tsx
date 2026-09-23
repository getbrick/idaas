import { useState, type FormEvent, type ReactNode } from "react";
import { useGetbrickAuth } from "./provider.js";
import { AuthCard } from "./AuthCard.js";
import type { ThemeTokens } from "./theme.js";

export type AuthFormMode = "sign-in" | "sign-up";

export interface AuthFormProps {
  mode?: AuthFormMode;
  theme?: ThemeTokens;
  onSuccess?: (result: { data?: unknown; error?: { message?: string } | null }) => void;
  onError?: (message: string) => void;
  renderSwitch?: (mode: AuthFormMode) => ReactNode;
}

export function AuthForm({ mode = "sign-in", theme, onSuccess, onError, renderSwitch }: AuthFormProps) {
  const auth = useGetbrickAuth();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [name, setName] = useState("");
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const isSignUp = mode === "sign-up";

  async function handleSubmit(event: FormEvent) {
    event.preventDefault();
    setError(null);
    setPending(true);
    try {
      const result = isSignUp
        ? await auth.signUp.email({ email, password, name: name || email })
        : await auth.signIn.email({ email, password });
      if (result?.error) {
        const message = result.error.message ?? "Authentication failed";
        setError(message);
        onError?.(message);
      } else {
        onSuccess?.(result);
      }
    } finally {
      setPending(false);
    }
  }

  return (
    <AuthCard
      title={isSignUp ? "Create account" : "Sign in"}
      theme={theme}
      footer={
        renderSwitch ? renderSwitch(isSignUp ? "sign-in" : "sign-up") : null
      }
    >
      <form className="gb-auth-form" onSubmit={handleSubmit}>
        {isSignUp && (
          <label className="gb-auth-form__field">
            <span>Name</span>
            <input
              type="text"
              name="name"
              autoComplete="name"
              value={name}
              onChange={(e) => setName(e.target.value)}
            />
          </label>
        )}
        <label className="gb-auth-form__field">
          <span>Email</span>
          <input
            type="email"
            name="email"
            autoComplete="email"
            required
            value={email}
            onChange={(e) => setEmail(e.target.value)}
          />
        </label>
        <label className="gb-auth-form__field">
          <span>Password</span>
          <input
            type="password"
            name="password"
            autoComplete={isSignUp ? "new-password" : "current-password"}
            required
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
        </label>
        {error && <p className="gb-auth-form__error">{error}</p>}
        <button className="gb-auth-form__submit" type="submit" disabled={pending}>
          {pending ? "Working..." : isSignUp ? "Sign up" : "Sign in"}
        </button>
      </form>
    </AuthCard>
  );
}
