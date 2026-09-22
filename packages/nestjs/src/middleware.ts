import type { NestMiddleware } from "@nestjs/common";
import { Inject } from "@nestjs/common";
import { GETBRICK_AUTH, type GetbrickAuthLike } from "./tokens.js";

const BODY_METHODS = new Set(["POST", "PUT", "PATCH", "DELETE"]);

export class GetbrickAuthMiddleware implements NestMiddleware {
  constructor(@Inject(GETBRICK_AUTH) private readonly auth: GetbrickAuthLike) {}

  async use(req: { originalUrl?: string; url?: string; method: string; headers: Record<string, unknown>; body?: unknown }, res: any, next: () => void): Promise<void> {
    try {
      const url = req.originalUrl ?? req.url ?? "";
      if (!url.startsWith("/api/auth")) {
        next();
        return;
      }
      const webRequest = toWebRequest(req);
      const webResponse = await this.auth.handler(webRequest);
      await writeWebResponse(webResponse, res);
    } catch (err) {
      res.status(500).json({ message: String(err) });
    }
  }
}

export function toWebRequest(req: {
  originalUrl?: string;
  url?: string;
  method: string;
  headers: Record<string, unknown>;
  body?: unknown;
}): Request {
  const host = (req.headers.host as string) ?? "localhost";
  const url = `http://${host}${req.originalUrl ?? req.url ?? "/"}`;
  const headers = new Headers();
  for (const [key, value] of Object.entries(req.headers)) {
    if (key.toLowerCase() === "content-length") continue;
    if (typeof value === "string") headers.set(key, value);
    else if (Array.isArray(value)) for (const v of value) headers.append(key, v);
  }
  const hasBody = BODY_METHODS.has(req.method.toUpperCase()) && req.body !== undefined;
  const body = hasBody ? JSON.stringify(req.body) : undefined;
  if (!hasBody) headers.delete("content-type");
  return new Request(url, {
    method: req.method,
    headers,
    body: body ?? undefined,
  });
}

export async function writeWebResponse(response: Response, res: any): Promise<void> {
  const cookies = typeof response.headers.getSetCookie === "function" ? response.headers.getSetCookie() : [];
  res.status(response.status);
  response.headers.forEach((value, key) => {
    if (key.toLowerCase() === "set-cookie") return;
    res.setHeader(key, value);
  });
  for (const cookie of cookies) {
    res.append("Set-Cookie", cookie);
  }
  const text = await response.text();
  res.send(text);
}
