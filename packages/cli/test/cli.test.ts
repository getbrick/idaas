import { mkdtempSync, existsSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { run, type CliIO } from "../src/cli.js";

function makeIO(cwd: string) {
  const lines: string[] = [];
  return {
    io: {
      cwd,
      log: (line: string) => lines.push(line),
      runMigrate: () => 0,
    } as CliIO,
    lines,
  };
}

describe("getbrick idaas cli", () => {
  it("init writes config template and refuses overwrite without --force", async () => {
    const cwd = mkdtempSync(join(tmpdir(), "gbcli-"));
    const { io } = makeIO(cwd);

    expect(await run(["idaas", "init"], io)).toBe(0);
    expect(existsSync(join(cwd, "getbrick.config.ts"))).toBe(true);

    const again = await run(["idaas", "init"], io);
    expect(again).toBe(1);

    const forced = await run(["idaas", "init", "--force"], io);
    expect(forced).toBe(0);
  });

  it("doctor fails without setup and passes with file + deps", async () => {
    const cwd = mkdtempSync(join(tmpdir(), "gbcli-"));
    const { io } = makeIO(cwd);

    expect(await run(["idaas", "doctor"], io)).toBe(1);

    await run(["idaas", "init"], io);
    const pkg = {
      dependencies: { "@getbrick/idaas-core": "^0.1.0", "better-auth": "^1.7.5" },
    };
    const { writeFileSync } = await import("node:fs");
    writeFileSync(join(cwd, "package.json"), JSON.stringify(pkg));
    expect(await run(["idaas", "doctor"], io)).toBe(0);
  });

  it("migrate forwards auth file path to runner", async () => {
    const cwd = mkdtempSync(join(tmpdir(), "gbcli-"));
    let received: string | undefined;
    const { io } = makeIO(cwd);
    io.runMigrate = (_cwd, authFile) => {
      received = authFile;
      return 0;
    };
    expect(await run(["idaas", "migrate", "--auth-file", "auth/server.ts"], io)).toBe(0);
    expect(received).toBe("auth/server.ts");
    expect(await run(["idaas", "migrate"], io)).toBe(0);
    expect(received).toBe("src/auth.ts");
  });

  it("unknown product exits 1 with usage", async () => {
    const cwd = mkdtempSync(join(tmpdir(), "gbcli-"));
    const { io } = makeIO(cwd);
    expect(await run(["template", "new"], io)).toBe(1);
  });
});
