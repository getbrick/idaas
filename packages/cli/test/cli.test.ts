import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { run, type CliIO, type MigrateOptions } from "../src/cli.js";

type MigrationCall = { cwd: string; authFile: string; options: MigrateOptions };

function makeIO(cwd: string) {
  const lines: string[] = [];
  const calls: MigrationCall[] = [];
  return {
    io: {
      cwd,
      log: (line: string) => lines.push(line),
      runMigrate: (receivedCwd: string, authFile: string, options?: MigrateOptions) => {
        calls.push({ cwd: receivedCwd, authFile, options: options ?? { dryRun: false } });
        return 0;
      },
    } satisfies CliIO,
    lines,
    calls,
  };
}

function writeProject(cwd: string): void {
  mkdirSync(join(cwd, "src"), { recursive: true });
  writeFileSync(join(cwd, "getbrick.config.ts"), [
    'import { defineIdaasConfig } from "@getbrick/idaas-core";',
    'export const idaas = defineIdaasConfig({ appName: "Test" });',
  ].join("\n"));
  writeFileSync(join(cwd, "src", "auth.ts"), "export const auth = {};\n");
  writeFileSync(
    join(cwd, "package.json"),
    JSON.stringify({ dependencies: { "@getbrick/idaas-core": "^0.1.0", "better-auth": "^1.7.5" } }),
  );
}

describe("getbrick idaas cli", () => {
  it("init writes config template and refuses overwrite without --force", async () => {
    const cwd = mkdtempSync(join(tmpdir(), "gbcli-"));
    const { io, lines } = makeIO(cwd);

    expect(await run(["idaas", "init"], io)).toBe(0);
    expect(existsSync(join(cwd, "getbrick.config.ts"))).toBe(true);
    expect(readFileSync(join(cwd, "getbrick.config.ts"), "utf8")).toContain("defineIdaasConfig");

    const again = await run(["idaas", "init"], io);
    expect(again).toBe(1);
    expect(lines.some((line) => line.includes("already exists"))).toBe(true);

    const forced = await run(["idaas", "init", "--force"], io);
    expect(forced).toBe(0);
  });

  it("doctor reports configuration, dependency, and migration errors", async () => {
    const cwd = mkdtempSync(join(tmpdir(), "gbcli-"));
    const { io, lines } = makeIO(cwd);

    expect(await run(["idaas", "doctor"], io)).toBe(1);
    expect(lines.some((line) => line.includes("getbrick.config.ts exists"))).toBe(true);
    expect(lines.some((line) => line.includes("package.json is readable and valid JSON"))).toBe(true);
    expect(lines.some((line) => line.includes("migration parameters are valid"))).toBe(true);

    writeProject(cwd);
    lines.length = 0;
    expect(await run(["idaas", "doctor"], io)).toBe(0);

    writeFileSync(join(cwd, "getbrick.config.ts"), "// defineIdaasConfig\nexport const idaas = {};\n");
    lines.length = 0;
    expect(await run(["idaas", "doctor"], io)).toBe(1);
    expect(lines.some((line) => line.includes("config calls defineIdaasConfig"))).toBe(true);

    writeProject(cwd);
    writeFileSync(join(cwd, "package.json"), JSON.stringify({ dependencies: { "@getbrick/idaas-core": "^0.1.0" } }));
    lines.length = 0;
    expect(await run(["idaas", "doctor"], io)).toBe(1);
    expect(lines.some((line) => line.includes("better-auth is declared"))).toBe(true);

    writeProject(cwd);
    lines.length = 0;
    expect(await run(["idaas", "doctor", "--auth-file"], io)).toBe(1);
    expect(lines.some((line) => line.includes("--auth-file requires a value"))).toBe(true);
  });

  it("rejects missing, unknown, and unsafe migration arguments", async () => {
    const cwd = mkdtempSync(join(tmpdir(), "gbcli-"));
    writeProject(cwd);
    const { io, lines, calls } = makeIO(cwd);

    expect(await run(["idaas", "migrate", "--auth-file"], io)).toBe(1);
    expect(calls).toHaveLength(0);
    expect(lines.some((line) => line.includes("--auth-file requires a value"))).toBe(true);

    expect(await run(["idaas", "migrate", "--config"], io)).toBe(1);
    expect(calls).toHaveLength(0);
    expect(lines.some((line) => line.includes("--config requires a value"))).toBe(true);

    expect(await run(["idaas", "migrate", "--auth-file=--dry-run"], io)).toBe(1);
    expect(calls).toHaveLength(0);
    expect(lines.some((line) => line.includes("--auth-file requires a value"))).toBe(true);

    expect(await run(["idaas", "migrate", "--unknown"], io)).toBe(1);
    expect(calls).toHaveLength(0);
    expect(lines.some((line) => line.includes("unknown argument"))).toBe(true);

    expect(await run(["idaas", "migrate", "--auth-file", "../outside.ts"], io)).toBe(1);
    expect(calls).toHaveLength(0);
    expect(lines.some((line) => line.includes("must stay within the project directory"))).toBe(true);

    expect(await run(["idaas", "migrate", "--auth-file", "src/missing.ts"], io)).toBe(1);
    expect(calls).toHaveLength(0);
    expect(lines.some((line) => line.includes("does not exist"))).toBe(true);
  });

  it("forwards safe auth, config, and dry-run migration options", async () => {
    const cwd = mkdtempSync(join(tmpdir(), "gbcli-"));
    writeProject(cwd);
    mkdirSync(join(cwd, "auth"), { recursive: true });
    writeFileSync(join(cwd, "auth", "server.ts"), "export const auth = {};\n");
    const { io, calls } = makeIO(cwd);

    expect(
      await run(
        ["idaas", "migrate", "--auth-file", "auth/server.ts", "--config", "getbrick.config.ts", "--dry-run"],
        io,
      ),
    ).toBe(0);
    expect(calls).toEqual([
      { cwd, authFile: "auth/server.ts", options: { dryRun: true, config: "getbrick.config.ts" } },
    ]);

    expect(await run(["idaas", "migrate", "--auth-file=auth/server.ts"], io)).toBe(0);
    expect(calls[1]).toEqual({ cwd, authFile: "auth/server.ts", options: { dryRun: false, config: undefined } });

    expect(await run(["idaas", "migrate", "auth/server.ts"], io)).toBe(0);
    expect(calls[2]).toEqual({ cwd, authFile: "auth/server.ts", options: { dryRun: false, config: undefined } });

    expect(await run(["idaas", "migrate", "--config", "src/auth.ts", "--dry-run"], io)).toBe(0);
    expect(calls[3]).toEqual({ cwd, authFile: "src/auth.ts", options: { dryRun: true, config: "src/auth.ts" } });

    expect(await run(["idaas", "migrate"], io)).toBe(0);
    expect(calls[4]).toEqual({ cwd, authFile: "src/auth.ts", options: { dryRun: false, config: undefined } });

    expect(await run(["idaas", "migrate", "--config", "getbrick.config.ts"], io)).toBe(0);
    expect(calls[5]).toEqual({ cwd, authFile: "src/auth.ts", options: { dryRun: false, config: "getbrick.config.ts" } });
  });

  it("rejects unknown init arguments and unknown products", async () => {
    const cwd = mkdtempSync(join(tmpdir(), "gbcli-"));
    const { io } = makeIO(cwd);
    expect(await run(["idaas", "init", "--wat"], io)).toBe(1);
    expect(await run(["template", "new"], io)).toBe(1);
  });
});
