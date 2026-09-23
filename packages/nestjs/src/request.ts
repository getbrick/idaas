import type { GetbrickAuthLike } from "./tokens.js";

export function headersFromRequest(req: { headers?: Record<string, unknown> }): Headers {
  const out = new Headers();
  const headers = req.headers ?? {};
  for (const [key, value] of Object.entries(headers)) {
    if (typeof value === "string") {
      out.set(key, value);
    } else if (Array.isArray(value)) {
      for (const v of value) out.append(key, v);
    }
  }
  return out;
}

export interface GetbrickSession {
  user?: Record<string, unknown>;
  session?: Record<string, unknown>;
  member?: Record<string, unknown>;
  organization?: Record<string, unknown>;
}

export async function getSessionFromRequest(
  auth: GetbrickAuthLike,
  req: { headers?: Record<string, unknown> },
): Promise<GetbrickSession | null> {
  const result = await auth.api.getSession({ headers: headersFromRequest(req) });
  return (result as GetbrickSession) ?? null;
}
