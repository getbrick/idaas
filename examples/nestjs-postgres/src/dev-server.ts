import { randomBytes } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { join, relative, resolve, isAbsolute } from "node:path";
import { NestFactory } from "@nestjs/core";

process.env.BETTER_AUTH_SECRET ??= randomBytes(32).toString("base64url");
const { auth } = await import("./auth.js");
const { AppModule } = await import("./app.module.js");

const PORT = 3000;
const DEMO_DIR = join(import.meta.dirname, "..", "demo");
const UI_DIST = join(import.meta.dirname, "..", "..", "..", "packages", "ui", "dist");
const MIME: Record<string, string> = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
};

const app = await NestFactory.create(AppModule, { logger: false });
app.use((req: { method?: string; url?: string }, res: {
  statusCode: number;
  setHeader: (name: string, value: string) => void;
  end: (body?: string | Buffer) => void;
}, next: () => void) => {
  if (req.method !== "GET" && req.method !== "HEAD") {
    next();
    return;
  }
  const requestUrl = new URL(req.url ?? "/", `http://localhost:${PORT}`);
  const filePath = resolveStaticPath(requestUrl.pathname);
  if (!filePath || !existsSync(filePath)) {
    next();
    return;
  }
  res.statusCode = 200;
  res.setHeader("content-type", MIME[filePath.slice(filePath.lastIndexOf("."))] ?? "text/plain");
  if (req.method === "HEAD") {
    res.end();
    return;
  }
  res.end(readFileSync(filePath));
});

await auth.api
  .signUpEmail({
    body: { email: "demo@getbrick.dev", password: "supersecret123", name: "Demo User" },
  })
  .catch(() => undefined);

await app.listen(PORT, "127.0.0.1");
console.log(`Getbrick demo: http://localhost:${PORT}`);
console.log("demo account: demo@getbrick.dev / supersecret123");

function resolveStaticPath(pathname: string): string | undefined {
  let decoded: string;
  try {
    decoded = decodeURIComponent(pathname);
  } catch {
    return undefined;
  }
  if (decoded.includes("\0") || decoded.includes("\\")) return undefined;
  if (decoded === "/") return resolve(DEMO_DIR, "index.html");
  if (decoded === "/index.html") return resolve(DEMO_DIR, "index.html");
  if (decoded === "/demo.js") return resolve(DEMO_DIR, "demo.js");
  if (decoded === "/styles.css") return resolve(UI_DIST, "styles.css");
  if (!decoded.startsWith("/")) return undefined;
  const candidate = resolve(DEMO_DIR, `.${decoded}`);
  const relativePath = relative(DEMO_DIR, candidate);
  if (relativePath === ".." || relativePath.startsWith(`..${process.platform === "win32" ? "\\" : "/"}`) || isAbsolute(relativePath)) return undefined;
  return candidate;
}
