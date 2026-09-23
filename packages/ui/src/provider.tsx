import { createContext, useContext, type CSSProperties, type ReactNode } from "react";
import { createGetbrickClient, getbrickContextKey, type GetbrickClient } from "./client.js";
import { themeToCssVars, type ThemeTokens } from "./theme.js";

const GetbrickAuthContext = createContext<GetbrickClient | null>(null);

export interface GetbrickAuthProviderProps {
  children: ReactNode;
  baseURL?: string;
  client?: GetbrickClient;
  theme?: ThemeTokens;
}

export function GetbrickAuthProvider({ children, baseURL, client, theme }: GetbrickAuthProviderProps) {
  const resolved = client ?? createGetbrickClient(baseURL);
  return (
    <div data-getbrick-provider="" style={{ ...themeToCssVars(theme) } as CSSProperties}>
      <GetbrickAuthContext.Provider value={resolved}>{children}</GetbrickAuthContext.Provider>
    </div>
  );
}

export function useGetbrickAuth(): GetbrickClient {
  const ctx = useContext(GetbrickAuthContext);
  if (ctx) return ctx;
  const globalKey = (globalThis as Record<string, unknown>)[getbrickContextKey];
  if (globalKey) return globalKey as GetbrickClient;
  return createGetbrickClient();
}
