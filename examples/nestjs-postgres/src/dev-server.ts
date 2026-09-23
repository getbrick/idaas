import { createServer, type IncomingMessage } from "node:http";
import { readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { Pool } from "pg";
import { createIdaas } from "@getbrick/idaas-core";

const auth = createIdaas({
  config: {
    appName: "Getbrick Example",
    session: { expiresInDays: 7, storeInDatabase: true },
    password: { minLength: 8 },
    features: { twoFactor: true, organization: true },
    rbac: {
      roles: {
        member: { extends: ["user"], permissions: ["project:read:own"] },
        owner: { extends: ["member"], permissions: ["project:write"] },
      },
    },
  },
  database: new Pool({
    connectionString: process.env.DATABASE_URL ?? "postgres://postgres:gbtest@localhost:54329/getbrick",
  }),
});

const PORT = 3000;
const DEMO_DIR = join(import.meta.dirname, "..", "demo");
const UI_DIST = join(import.meta.dirname, "..", "..", "..", "packages", "ui", "dist");

function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve) => {
    let data = "";
    req.on("data", (chunk) => (data += chunk));
    req.on("end", () => resolve(data));
  });
}

const MIME: Record<string, string> = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
};

const server = createServer(async (req, res) => {
  try {
    const url = `http://localhost:${PORT}${req.url ?? "/"}`;
    if (req.url?.startsWith("/api/auth")) {
      const headers = new Headers();
      for (const [key, value] of Object.entries(req.headers)) {
        if (typeof value === "string") headers.set(key, value);
        else if (Array.isArray(value)) headers.append(key, value.join(", "));
      }
      const body = req.method === "GET" || req.method === "HEAD" ? undefined : await readBody(req);
      if (body !== undefined) headers.set("content-type", headers.get("content-type") ?? "application/json");
      const webRes = await auth.handler(new Request(url, { method: req.method, headers, body }));
      res.statusCode = webRes.status;
      webRes.headers.forEach((value, key) => res.setHeader(key, value));
      res.end(Buffer.from(await webRes.arrayBuffer()));
      return;
    }

    let filePath: string;
    if (req.url === "/" || req.url === "/index.html") filePath = join(DEMO_DIR, "index.html");
    else if (req.url === "/demo.js") filePath = join(DEMO_DIR, "demo.js");
    else if (req.url === "/styles.css") filePath = join(UI_DIST, "styles.css");
    else filePath = join(DEMO_DIR, req.url ?? "");

    if (!existsSync(filePath)) {
      res.statusCode = 404;
      res.end("not found");
      return;
    }
    res.setHeader("content-type", MIME[filePath.slice(filePath.lastIndexOf("."))] ?? "text/plain");
    res.end(readFileSync(filePath));
  } catch (err) {
    res.statusCode = 500;
    res.end(String(err));
  }
});

// seed a demo account so the sign-in form works immediately
await auth.api
  .signUpEmail({
    body: { email: "demo@getbrick.dev", password: "supersecret123", name: "Demo User" },
  })
  .catch(() => undefined);

server.listen(PORT, () => {
  console.log(`Getbrick demo: http://localhost:${PORT}`);
  console.log(`demo account: demo@getbrick.dev / supersecret123`);
});
