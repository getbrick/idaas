import { useState } from "react";
import { useGetbrickAuth } from "./provider.js";

export interface SignOutButtonProps {
  label?: string;
  onSignedOut?: () => void;
}

export function SignOutButton({ label = "Sign out", onSignedOut }: SignOutButtonProps) {
  const auth = useGetbrickAuth();
  const [pending, setPending] = useState(false);

  async function handleClick() {
    setPending(true);
    try {
      await auth.signOut();
      onSignedOut?.();
    } finally {
      setPending(false);
    }
  }

  return (
    <button className="gb-signout" type="button" onClick={handleClick} disabled={pending}>
      {pending ? "Signing out..." : label}
    </button>
  );
}
