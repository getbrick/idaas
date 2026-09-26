import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import type { OpenPlatformFetch } from "@getbrick/idaas-open-platform-sdk";
import { run, type CliIO } from "./cli.js";
import {
  EXIT_FAILURE,
  EXIT_TOOL_NOT_FOUND,
  type CommandRunOptions,
} from "./ops.js";

const migrationRunner = resolveMigrationRunner();

function resolveMigrationRunner(): string {
  const compiled = fileURLToPath(new URL("./migrate-runner.js", import.meta.url));
  return existsSync(compiled) ? compiled : fileURLToPath(new URL("./migrate-runner.ts", import.meta.url));
}

export interface SpawnResult {
  status: number | null;
  error?: NodeJS.ErrnoException;
}

export interface SpawnOptions extends CommandRunOptions {
  shell: false;
}

export type SpawnCommand = (command: string, args: string[], options: SpawnOptions) => SpawnResult;

const defaultSpawn: SpawnCommand = (command, args, options) => spawnSync(command, args, options);

export function createCliIO(
  cwd = process.cwd(),
  env = process.env,
  spawn: SpawnCommand = defaultSpawn,
  openPlatformFetch?: OpenPlatformFetch,
): CliIO {
  const log = (line: string): void => console.log(line);
  const runCommand: NonNullable<CliIO["runCommand"]> = (command, args, options) => {
    try {
      const result = spawn(command, args, {
        cwd: options.cwd,
        env: options.env,
        stdio: options.stdio,
        shell: false,
      });
      if (result.error) {
        const missing = result.error.code === "ENOENT";
        log(`✗ failed to run ${command}`);
        return missing ? EXIT_TOOL_NOT_FOUND : EXIT_FAILURE;
      }
      return result.status ?? EXIT_FAILURE;
    } catch {
      log(`✗ failed to run ${command}`);
      return EXIT_FAILURE;
    }
  };

  return {
    cwd,
    env,
    log,
    runCommand,
    ...(openPlatformFetch === undefined ? {} : { openPlatformFetch }),
    runMigrate: (migrationCwd, authFile, options = { dryRun: false }) => {
      const nodeArguments = [migrationRunner, "--", authFile];
      if (options.config) nodeArguments.push("--config", options.config);
      if (options.dryRun) nodeArguments.push("--dry-run");
      const needsTypeScript = [authFile, options.config ?? ""].some((file) => /\.[cm]?tsx?$/.test(file)) || migrationRunner.endsWith(".ts");
      const result = spawnSync(
        process.execPath,
        [...(needsTypeScript ? ["--experimental-strip-types"] : []), ...nodeArguments],
        { stdio: "inherit", cwd: migrationCwd, env, shell: false },
      );
      if (result.error) {
        log("✗ failed to run local migration runner");
        return 1;
      }
      return result.status ?? 1;
    },
  };
}

export async function main(argv: string[]): Promise<number> {
  return run(argv, createCliIO());
}
