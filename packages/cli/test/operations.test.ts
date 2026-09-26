import { createHash } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { run, type CliIO } from "../src/cli.js";
import { createCliIO } from "../src/main.js";
import { EXIT_TOOL_NOT_FOUND, EXIT_USAGE } from "../src/ops.js";

type CommandCall = {
  command: string;
  args: string[];
  cwd: string;
  env: NodeJS.ProcessEnv;
  stdio: string;
  shell: false;
};

function makeIO(cwd: string, result = 0) {
  const lines: string[] = [];
  const calls: CommandCall[] = [];
  const io = {
    cwd,
    env: { DATABASE_URL: "postgres://runtime.example/source" } as NodeJS.ProcessEnv,
    log: (line: string) => lines.push(line),
    now: () => new Date("2026-01-02T03:04:05.678Z"),
    runCommand: (
      command: string,
      args: string[],
      options: { cwd: string; env: NodeJS.ProcessEnv; stdio: "inherit"; shell: false },
    ) => {
      calls.push({ command, args, ...options });
      if (command === "pg_dump") writeFileSync(args[args.indexOf("--file") + 1], "fixture dump");
      return result;
    },
    runMigrate: () => 0,
  } satisfies CliIO;
  return { io, lines, calls };
}

function digest(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

describe("offline operations", () => {
  it("creates a custom dump and manifest through pg_dump without shell interpolation", async () => {
    const cwd = mkdtempSync(join(tmpdir(), "gbcli-ops-"));
    const output = join(cwd, "backups");
    const { io, lines, calls } = makeIO(cwd);

    expect(await run(["idaas", "backup:create", "--output", output], io)).toBe(0);
    expect(calls).toHaveLength(1);
    expect(calls[0].command).toBe("pg_dump");
    expect(calls[0].args.slice(0, 2)).toEqual(["--format=custom", "--file"]);
    expect(calls[0].args[2]).toMatch(/backup-2026-01-02T03-04-05-678Z\.dump$/);
    expect(calls[0].env).toEqual({ DATABASE_URL: "postgres://runtime.example/source" });
    expect(calls[0].stdio).toBe("inherit");
    expect(calls[0].shell).toBe(false);

    const file = calls[0].args[2];
    const manifest = `${file}.manifest.json`;
    expect(existsSync(file)).toBe(true);
    expect(JSON.parse(readFileSync(manifest, "utf8"))).toMatchObject({
      file: file.slice(file.lastIndexOf("/") + 1),
      sha256: digest("fixture dump"),
    });
    expect(lines.some((line) => line.includes("does not encrypt"))).toBe(true);
  });

  it("requires runtime database environment and preserves a stable missing-tool code", async () => {
    const cwd = mkdtempSync(join(tmpdir(), "gbcli-ops-"));
    const { io, calls } = makeIO(cwd, EXIT_TOOL_NOT_FOUND);
    io.env = {};

    expect(await run(["idaas", "backup:create", "--output", "backups"], io)).toBe(78);
    expect(calls).toHaveLength(0);

    io.env = { PGHOST: "db.example" };
    expect(await run(["idaas", "backup:create", "--output", "backups"], io)).toBe(EXIT_TOOL_NOT_FOUND);
    expect(calls[0].command).toBe("pg_dump");

    const input = join(cwd, "backup.dump");
    writeFileSync(input, "fixture dump");
    const restore = makeIO(cwd, EXIT_TOOL_NOT_FOUND);
    expect(
      await run(
        [
          "idaas",
          "restore:apply",
          "--input",
          input,
          "--target-db",
          "idaas_restore",
          "--confirm",
          digest("fixture dump"),
        ],
        restore.io,
      ),
    ).toBe(EXIT_TOOL_NOT_FOUND);
    expect(restore.calls[0].command).toBe("createdb");
  });

  it("verifies a manifest, an optional explicit digest, and rejects traversal", async () => {
    const cwd = mkdtempSync(join(tmpdir(), "gbcli-ops-"));
    const input = join(cwd, "backup.dump");
    writeFileSync(input, "fixture dump");
    writeFileSync(
      `${input}.manifest.json`,
      JSON.stringify({ sha256: digest("fixture dump"), size: Buffer.byteLength("fixture dump") }),
    );
    const { io, lines, calls } = makeIO(cwd);

    expect(await run(["idaas", "backup:verify", "--input", input], io)).toBe(0);
    expect(calls).toHaveLength(0);
    expect(lines.some((line) => line.includes("backup verified"))).toBe(true);

    writeFileSync(`${input}.manifest.json`, JSON.stringify({ sha256: "0".repeat(64) }));
    expect(await run(["idaas", "backup:verify", "--input", input], io)).toBe(1);
    expect(lines.some((line) => line.includes("does not match the manifest"))).toBe(true);

    writeFileSync(join(cwd, "digest-only.dump"), "digest only");
    expect(
      await run(
        ["idaas", "backup:verify", "--input", join(cwd, "digest-only.dump"), "--digest", digest("digest only")],
        io,
      ),
    ).toBe(0);

    expect(await run(["idaas", "backup:verify", "--input", "../outside.dump"], io)).toBe(EXIT_USAGE);
    expect(lines.some((line) => line.includes("path traversal"))).toBe(true);
  });

  it("plans and applies only to a new database with an explicit digest confirmation", async () => {
    const cwd = mkdtempSync(join(tmpdir(), "gbcli-ops-"));
    const input = join(cwd, "backup.dump");
    writeFileSync(input, "fixture dump");
    const backupDigest = digest("fixture dump");
    const { io, calls } = makeIO(cwd);

    expect(
      await run(["idaas", "restore:plan", "--input", input, "--target-db", "idaas_restore"], io),
    ).toBe(0);
    expect(calls[0]).toMatchObject({
      command: "pg_restore",
      args: ["--list", input],
    });

    expect(
      await run(
        [
          "idaas",
          "restore:apply",
          "--input",
          input,
          "--target-db",
          "idaas_restore",
          "--confirm",
          backupDigest,
        ],
        io,
      ),
    ).toBe(0);
    expect(calls[1]).toMatchObject({
      command: "createdb",
      args: ["--template=template0", "idaas_restore"],
    });
    expect(calls[2]).toMatchObject({
      command: "pg_restore",
      args: ["--exit-on-error", "--dbname", "idaas_restore", input],
    });
  });

  it("rejects missing confirmation, current database targets, invalid paths, and missing arguments", async () => {
    const cwd = mkdtempSync(join(tmpdir(), "gbcli-ops-"));
    const input = join(cwd, "backup.dump");
    writeFileSync(input, "fixture dump");
    const backupDigest = digest("fixture dump");
    const { io, calls } = makeIO(cwd);

    expect(await run(["idaas", "backup:create"], io)).toBe(EXIT_USAGE);
    expect(await run(["idaas", "backup:verify"], io)).toBe(EXIT_USAGE);
    expect(await run(["idaas", "restore:plan", "--input", input], io)).toBe(EXIT_USAGE);
    expect(
      await run(["idaas", "restore:apply", "--input", input, "--target-db", "idaas_restore"], io),
    ).toBe(EXIT_USAGE);
    expect(
      await run(
        [
          "idaas",
          "restore:apply",
          "--input",
          input,
          "--target-db",
          "source",
          "--confirm",
          backupDigest,
        ],
        io,
      ),
    ).toBe(EXIT_USAGE);
    expect(calls).toHaveLength(0);
  });

  it("uses the main spawn seam with shell disabled", async () => {
    const cwd = mkdtempSync(join(tmpdir(), "gbcli-ops-"));
    const calls: Array<{ command: string; args: string[]; shell: boolean }> = [];
    const io = createCliIO(cwd, { DATABASE_URL: "postgres://runtime.example/source" }, (command, args, options) => {
      calls.push({ command, args, shell: options.shell });
      if (command === "pg_dump") writeFileSync(args[args.indexOf("--file") + 1], "main fixture");
      return { status: 0 };
    });
    const lines: string[] = [];
    io.log = (line) => lines.push(line);
    io.now = () => new Date("2026-01-02T03:04:05.678Z");

    expect(await run(["idaas", "backup:create", "--output", "backups"], io)).toBe(0);
    expect(calls[0].command).toBe("pg_dump");
    expect(calls[0].shell).toBe(false);
  });

  it("redacts credentials, manifest data, and secret-bearing paths from operation errors", async () => {
    const cwd = mkdtempSync(join(tmpdir(), "gbcli-ops-"));
    const databaseUrl = "postgres://user:database-secret@db.example/source";
    const pgPassword = "pg-password-secret";
    const pathSecret = "path-secret-7f3a";
    const input = join(cwd, `${pathSecret}.dump`);
    const manifestSecret = `${databaseUrl}/${pgPassword}/${pathSecret}`;
    writeFileSync(input, "fixture dump");
    writeFileSync(`${input}.manifest.json`, `not-json ${manifestSecret}`);
    const { io, lines } = makeIO(cwd);
    io.env = { DATABASE_URL: databaseUrl, PGPASSWORD: pgPassword };

    expect(await run(["idaas", "backup:verify", "--input", input], io)).toBe(1);
    expect(lines.join("\n")).not.toContain(databaseUrl);
    expect(lines.join("\n")).not.toContain(pgPassword);
    expect(lines.join("\n")).not.toContain(pathSecret);
    expect(lines.join("\n")).not.toContain(manifestSecret);

    const throwing = makeIO(cwd);
    throwing.io.env = { DATABASE_URL: databaseUrl, PGPASSWORD: pgPassword };
    throwing.io.runCommand = () => {
      throw new Error(`failed ${databaseUrl} ${pgPassword} ${input}`);
    };
    expect(await run(["idaas", "backup:create", "--output", join(cwd, pathSecret)], throwing.io)).toBe(1);
    expect(throwing.lines.join("\n")).not.toContain(databaseUrl);
    expect(throwing.lines.join("\n")).not.toContain(pgPassword);
    expect(throwing.lines.join("\n")).not.toContain(pathSecret);
  });

  it("does not let --yes bypass a strict digest or a current-database target", async () => {
    const cwd = mkdtempSync(join(tmpdir(), "gbcli-ops-"));
    const input = join(cwd, "backup.dump");
    writeFileSync(input, "fixture dump");
    const backupDigest = digest("fixture dump");
    const databaseUrl = "postgres://user:secret@db.example/SOURCE";
    const { io, lines, calls } = makeIO(cwd);
    io.env = { DATABASE_URL: databaseUrl, PGPASSWORD: "pg-secret" };

    const apply = (target: string, confirm?: string, yes = false): Promise<number> => {
      const args = ["idaas", "restore:apply", "--input", input, "--target-db", target];
      if (confirm !== undefined) args.push("--confirm", confirm);
      if (yes) args.push("--yes");
      return run(args, io);
    };

    expect(await apply("new_db", undefined, true)).toBe(EXIT_USAGE);
    expect(await apply("new_db", `sha256:${backupDigest}`, true)).toBe(EXIT_USAGE);
    expect(await apply("new_db", ` ${backupDigest}`, true)).toBe(EXIT_USAGE);
    expect(await apply("source", backupDigest, true)).toBe(EXIT_USAGE);
    expect(await apply("new_db", "0".repeat(64), true)).toBe(1);
    expect(calls).toHaveLength(0);
    expect(lines.join("\n")).not.toContain("pg-secret");
    expect(lines.join("\n")).not.toContain(databaseUrl);

    const defaultCurrent = makeIO(cwd);
    defaultCurrent.io.env = { PGHOST: "db.example", PGUSER: "source" };
    expect(
      await run(
        ["idaas", "restore:apply", "--input", input, "--target-db", "source", "--confirm", backupDigest],
        defaultCurrent.io,
      ),
    ).toBe(EXIT_USAGE);
    expect(defaultCurrent.calls).toHaveLength(0);

    expect(await apply("new-db", backupDigest, true)).toBe(0);
    expect(calls.map((call) => call.command)).toEqual(["createdb", "pg_restore"]);
    expect(calls.every((call) => call.shell === false)).toBe(true);
  });

  it("rejects unsafe target names and never continues after database creation fails", async () => {
    const cwd = mkdtempSync(join(tmpdir(), "gbcli-ops-"));
    const input = join(cwd, "backup.dump");
    writeFileSync(input, "fixture dump");
    const backupDigest = digest("fixture dump");
    const { io, calls } = makeIO(cwd);

    for (const target of ["new db", "new;drop", "../source", "-source", "a".repeat(64)]) {
      expect(
        await run(
          ["idaas", "restore:apply", "--input", input, "--target-db", target, "--confirm", backupDigest],
          io,
        ),
      ).toBe(EXIT_USAGE);
    }
    expect(calls).toHaveLength(0);

    const failedCreate = makeIO(cwd, 1);
    expect(
      await run(
        ["idaas", "restore:apply", "--input", input, "--target-db", "new_db", "--confirm", backupDigest],
        failedCreate.io,
      ),
    ).toBe(1);
    expect(failedCreate.calls).toHaveLength(1);
    expect(failedCreate.calls[0].command).toBe("createdb");
  });
});
