import { existsSync, readFileSync, realpathSync, statSync, writeFileSync } from "node:fs";
import { isAbsolute, join, relative, resolve, sep } from "node:path";
import {
  backupCreate,
  backupVerify,
  EXIT_USAGE,
  restoreApply,
  restorePlan,
  type BackupCreateRequest,
  type BackupVerifyRequest,
  type OperationIO,
  type RestoreRequest,
} from "./ops.js";
import { runOpenPlatform, type OpenPlatformIO } from "./open-platform.js";

export {
  parseOpenPlatformArgs,
  parseOpenPlatformCommandArgs,
  runOpenPlatform,
} from "./open-platform.js";
export type {
  OpenPlatformArgs,
  OpenPlatformCommand,
  OpenPlatformCommonArgs,
  OpenPlatformComplianceRecordArgs,
  OpenPlatformComplianceReportArgs,
  OpenPlatformDomainEventRetryArgs,
  OpenPlatformIdArgs,
  OpenPlatformIO,
  OpenPlatformListArgs,
  OpenPlatformParseResult,
  OpenPlatformPrivacyRequestArgs,
  OpenPlatformWebhookTestArgs,
} from "./open-platform.js";

export interface MigrateOptions {
  dryRun: boolean;
  config?: string;
}

export interface CliIO extends OperationIO, OpenPlatformIO {
  runMigrate: (cwd: string, authFile: string, options?: MigrateOptions) => number | Promise<number>;
}

export const CONFIG_FILE = "getbrick.config.ts";
export const DEFAULT_AUTH_FILE = "src/auth.ts";

const USAGE = "Usage: getbrick idaas <init|doctor|migrate|backup:create|backup:verify|restore:plan|restore:apply>";
const MIGRATE_USAGE = "Usage: getbrick idaas migrate [--auth-file <path>] [--config <path>] [--dry-run]";
const BACKUP_CREATE_USAGE = "Usage: getbrick idaas backup:create --output <dir>";
const BACKUP_VERIFY_USAGE = "Usage: getbrick idaas backup:verify --input <file> [--digest <sha256>] [--manifest <file>]";
const RESTORE_PLAN_USAGE = "Usage: getbrick idaas restore:plan --input <file> --target-db <new-database> [--digest <sha256>] [--manifest <file>]";
const RESTORE_APPLY_USAGE = "Usage: getbrick idaas restore:apply --input <file> --target-db <new-database> --confirm <sha256> [--digest <sha256>] [--manifest <file>] [--yes]";

type ParseResult<T> =
  | { ok: true; value: T }
  | { ok: false; error: string };

export async function run(argv: string[], io: CliIO): Promise<number> {
  const [product, command, ...rest] = argv;
  if (product === "open-platform") {
    return runOpenPlatform(command, rest, io);
  }
  if (product !== "idaas") {
    io.log(USAGE);
    return product ? 1 : 0;
  }
  if (command === "init") return cmdInit(rest, io);
  if (command === "doctor") return cmdDoctor(rest, io);
  if (command === "migrate") return cmdMigrate(rest, io);
  if (command === "backup:create") return cmdBackupCreate(rest, io);
  if (command === "backup:verify") return cmdBackupVerify(rest, io);
  if (command === "restore:plan") return cmdRestorePlan(rest, io);
  if (command === "restore:apply") return cmdRestoreApply(rest, io);
  io.log(USAGE);
  return 1;
}

export function parseMigrateArgs(args: string[], cwd: string): ParseResult<{ authFile: string; configFile?: string; dryRun: boolean }> {
  let authInput: string | undefined;
  let configInput: string | undefined;
  let positionalInput: string | undefined;
  let dryRun = false;
  let endOfOptions = false;

  for (let index = 0; index < args.length; index++) {
    const argument = args[index];
    if (!endOfOptions && argument === "--") {
      endOfOptions = true;
      continue;
    }
    if (!endOfOptions && argument === "--dry-run") {
      if (dryRun) return { ok: false, error: "--dry-run may only be specified once" };
      dryRun = true;
      continue;
    }
    if (!endOfOptions && (argument === "--auth-file" || argument === "--config")) {
      const option = argument;
      if (option === "--auth-file" && authInput !== undefined) {
        return { ok: false, error: "--auth-file may only be specified once" };
      }
      if (option === "--config" && configInput !== undefined) {
        return { ok: false, error: "--config may only be specified once" };
      }
      const value = args[++index];
      if (!value || value.startsWith("-")) {
        return { ok: false, error: `${option} requires a value` };
      }
      if (option === "--auth-file") authInput = value;
      else configInput = value;
      continue;
    }
    if (!endOfOptions && argument.startsWith("--auth-file=")) {
      if (authInput !== undefined) return { ok: false, error: "--auth-file may only be specified once" };
      authInput = argument.slice("--auth-file=".length);
      if (!authInput || authInput.startsWith("-")) return { ok: false, error: "--auth-file requires a value" };
      continue;
    }
    if (!endOfOptions && argument.startsWith("--config=")) {
      if (configInput !== undefined) return { ok: false, error: "--config may only be specified once" };
      configInput = argument.slice("--config=".length);
      if (!configInput || configInput.startsWith("-")) return { ok: false, error: "--config requires a value" };
      continue;
    }
    if (!endOfOptions && argument.startsWith("-")) {
      return { ok: false, error: "unknown argument" };
    }
    if (positionalInput !== undefined) {
      return { ok: false, error: "unexpected argument" };
    }
    positionalInput = argument;
  }

  if (authInput !== undefined && positionalInput !== undefined) {
    return { ok: false, error: "use either --auth-file or a positional auth file, not both" };
  }

  const authWasExplicit = authInput !== undefined || positionalInput !== undefined;
  const authPathInput = authInput ?? positionalInput ?? DEFAULT_AUTH_FILE;
  const configPathInput = configInput;

  let configPath: string | undefined;
  if (configPathInput !== undefined) {
    const normalized = normalizeProjectFile(cwd, configPathInput, "config file");
    if (!normalized.ok) return normalized;
    configPath = normalized.value;
  }

  let authPath: string;
  if (authWasExplicit || configPath === undefined) {
    const normalized = normalizeProjectFile(cwd, authPathInput, "auth file");
    if (!normalized.ok) return normalized;
    authPath = normalized.value;
  } else {
    const defaultAuth = normalizeProjectFile(cwd, DEFAULT_AUTH_FILE, "auth file");
    if (defaultAuth.ok) {
      authPath = defaultAuth.value;
    } else {
      const configAuth = normalizeProjectFile(cwd, configPath, "auth file");
      if (!configAuth.ok) return defaultAuth;
      authPath = configAuth.value;
    }
  }

  return { ok: true, value: { authFile: authPath, configFile: configPath, dryRun } };
}

export function parseBackupCreateArgs(args: string[]): ParseResult<BackupCreateRequest> {
  let output: string | undefined;
  for (let index = 0; index < args.length; index++) {
    const argument = args[index];
    if (argument === "--output") {
      if (output !== undefined) return { ok: false, error: "--output may only be specified once" };
      const value = args[++index];
      if (!value || value.startsWith("-")) return { ok: false, error: "--output requires a value" };
      output = value;
      continue;
    }
    if (argument.startsWith("--output=")) {
      if (output !== undefined) return { ok: false, error: "--output may only be specified once" };
      output = argument.slice("--output=".length);
      if (!output || output.startsWith("-")) return { ok: false, error: "--output requires a value" };
      continue;
    }
    return { ok: false, error: "unknown argument" };
  }
  if (output === undefined) return { ok: false, error: "--output <dir> is required" };
  return { ok: true, value: { output } };
}

export function parseBackupVerifyArgs(args: string[]): ParseResult<BackupVerifyRequest> {
  let input: string | undefined;
  let digest: string | undefined;
  let manifest: string | undefined;
  for (let index = 0; index < args.length; index++) {
    const argument = args[index];
    if (argument === "--input") {
      if (input !== undefined) return { ok: false, error: "--input may only be specified once" };
      const value = args[++index];
      if (!value || value.startsWith("-")) return { ok: false, error: "--input requires a value" };
      input = value;
      continue;
    }
    if (argument.startsWith("--input=")) {
      if (input !== undefined) return { ok: false, error: "--input may only be specified once" };
      input = argument.slice("--input=".length);
      if (!input || input.startsWith("-")) return { ok: false, error: "--input requires a value" };
      continue;
    }
    if (argument === "--digest") {
      if (digest !== undefined) return { ok: false, error: "--digest may only be specified once" };
      const value = args[++index];
      if (!value || value.startsWith("-")) return { ok: false, error: "--digest requires a value" };
      digest = value;
      continue;
    }
    if (argument.startsWith("--digest=")) {
      if (digest !== undefined) return { ok: false, error: "--digest may only be specified once" };
      digest = argument.slice("--digest=".length);
      if (!digest || digest.startsWith("-")) return { ok: false, error: "--digest requires a value" };
      continue;
    }
    if (argument === "--manifest") {
      if (manifest !== undefined) return { ok: false, error: "--manifest may only be specified once" };
      const value = args[++index];
      if (!value || value.startsWith("-")) return { ok: false, error: "--manifest requires a value" };
      manifest = value;
      continue;
    }
    if (argument.startsWith("--manifest=")) {
      if (manifest !== undefined) return { ok: false, error: "--manifest may only be specified once" };
      manifest = argument.slice("--manifest=".length);
      if (!manifest || manifest.startsWith("-")) return { ok: false, error: "--manifest requires a value" };
      continue;
    }
    return { ok: false, error: "unknown argument" };
  }
  if (input === undefined) return { ok: false, error: "--input <file> is required" };
  return { ok: true, value: { input, digest, manifest } };
}

export function parseRestoreArgs(args: string[], apply: boolean): ParseResult<RestoreRequest> {
  let input: string | undefined;
  let targetDb: string | undefined;
  let digest: string | undefined;
  let manifest: string | undefined;
  let confirm: string | undefined;
  let yes = false;

  for (let index = 0; index < args.length; index++) {
    const argument = args[index];
    if (argument === "--input") {
      if (input !== undefined) return { ok: false, error: "--input may only be specified once" };
      const value = args[++index];
      if (!value || value.startsWith("-")) return { ok: false, error: "--input requires a value" };
      input = value;
      continue;
    }
    if (argument.startsWith("--input=")) {
      if (input !== undefined) return { ok: false, error: "--input may only be specified once" };
      input = argument.slice("--input=".length);
      if (!input || input.startsWith("-")) return { ok: false, error: "--input requires a value" };
      continue;
    }
    if (argument === "--target-db" || argument === "--target-database" || argument === "--database" || argument === "--new-database") {
      if (targetDb !== undefined) return { ok: false, error: "--target-db may only be specified once" };
      const value = args[++index];
      if (!value || value.startsWith("-")) return { ok: false, error: "--target-db requires a value" };
      targetDb = value;
      continue;
    }
    if (
      argument.startsWith("--target-db=") ||
      argument.startsWith("--target-database=") ||
      argument.startsWith("--database=") ||
      argument.startsWith("--new-database=")
    ) {
      if (targetDb !== undefined) return { ok: false, error: "--target-db may only be specified once" };
      const separator = argument.indexOf("=");
      targetDb = argument.slice(separator + 1);
      if (!targetDb || targetDb.startsWith("-")) return { ok: false, error: "--target-db requires a value" };
      continue;
    }
    if (argument === "--digest") {
      if (digest !== undefined) return { ok: false, error: "--digest may only be specified once" };
      const value = args[++index];
      if (!value || value.startsWith("-")) return { ok: false, error: "--digest requires a value" };
      digest = value;
      continue;
    }
    if (argument.startsWith("--digest=")) {
      if (digest !== undefined) return { ok: false, error: "--digest may only be specified once" };
      digest = argument.slice("--digest=".length);
      if (!digest || digest.startsWith("-")) return { ok: false, error: "--digest requires a value" };
      continue;
    }
    if (argument === "--manifest") {
      if (manifest !== undefined) return { ok: false, error: "--manifest may only be specified once" };
      const value = args[++index];
      if (!value || value.startsWith("-")) return { ok: false, error: "--manifest requires a value" };
      manifest = value;
      continue;
    }
    if (argument.startsWith("--manifest=")) {
      if (manifest !== undefined) return { ok: false, error: "--manifest may only be specified once" };
      manifest = argument.slice("--manifest=".length);
      if (!manifest || manifest.startsWith("-")) return { ok: false, error: "--manifest requires a value" };
      continue;
    }
    if (argument === "--confirm" || argument === "--confirm-digest") {
      if (!apply) return { ok: false, error: "--confirm is only valid for restore:apply" };
      if (confirm !== undefined) return { ok: false, error: "--confirm may only be specified once" };
      const value = args[++index];
      if (!value || value.startsWith("-")) return { ok: false, error: "--confirm requires a value" };
      confirm = value;
      continue;
    }
    if (argument.startsWith("--confirm=") || argument.startsWith("--confirm-digest=")) {
      if (!apply) return { ok: false, error: "--confirm is only valid for restore:apply" };
      if (confirm !== undefined) return { ok: false, error: "--confirm may only be specified once" };
      const separator = argument.indexOf("=");
      confirm = argument.slice(separator + 1);
      if (!confirm || confirm.startsWith("-")) return { ok: false, error: "--confirm requires a value" };
      continue;
    }
    if (argument === "--yes") {
      if (!apply) return { ok: false, error: "--yes is only valid for restore:apply" };
      if (yes) return { ok: false, error: "--yes may only be specified once" };
      yes = true;
      continue;
    }
    return { ok: false, error: "unknown argument" };
  }

  if (input === undefined) return { ok: false, error: "--input <file> is required" };
  if (targetDb === undefined) return { ok: false, error: "--target-db <new-database> is required" };
  return { ok: true, value: { input, targetDb, digest, manifest, confirm, yes } };
}

async function cmdBackupCreate(args: string[], io: CliIO): Promise<number> {
  const parsed = parseBackupCreateArgs(args);
  if (!parsed.ok) {
    io.log(`✗ backup:create: ${parsed.error}`);
    io.log(BACKUP_CREATE_USAGE);
    return EXIT_USAGE;
  }
  return backupCreate(parsed.value, io);
}

async function cmdBackupVerify(args: string[], io: CliIO): Promise<number> {
  const parsed = parseBackupVerifyArgs(args);
  if (!parsed.ok) {
    io.log(`✗ backup:verify: ${parsed.error}`);
    io.log(BACKUP_VERIFY_USAGE);
    return EXIT_USAGE;
  }
  return backupVerify(parsed.value, io);
}

async function cmdRestorePlan(args: string[], io: CliIO): Promise<number> {
  const parsed = parseRestoreArgs(args, false);
  if (!parsed.ok) {
    io.log(`✗ restore:plan: ${parsed.error}`);
    io.log(RESTORE_PLAN_USAGE);
    return EXIT_USAGE;
  }
  return restorePlan(parsed.value, io);
}

async function cmdRestoreApply(args: string[], io: CliIO): Promise<number> {
  const parsed = parseRestoreArgs(args, true);
  if (!parsed.ok) {
    io.log(`✗ restore:apply: ${parsed.error}`);
    io.log(RESTORE_APPLY_USAGE);
    return EXIT_USAGE;
  }
  return restoreApply(parsed.value, io);
}

function configTemplate(): string {
  return `import { defineIdaasConfig } from '@getbrick/idaas-core'

export const idaas = defineIdaasConfig({
  appName: 'My App',
  session: { expiresInDays: 7 },
  password: { minLength: 8 },
  features: { twoFactor: true },
})
`;
}

function cmdInit(args: string[], io: CliIO): number {
  let force = false;
  for (const argument of args) {
    if (argument === "--force") {
      if (force) {
        io.log("✗ init: --force may only be specified once");
        return 1;
      }
      force = true;
      continue;
    }
    io.log("✗ init: unknown argument");
    return 1;
  }

  const path = join(io.cwd, CONFIG_FILE);
  if (existsSync(path) && !force) {
    io.log(`✗ ${CONFIG_FILE} already exists (use --force to overwrite)`);
    return 1;
  }
  writeFileSync(path, configTemplate());
  io.log(`✓ created ${CONFIG_FILE}`);
  io.log("");
  io.log("Next steps:");
  io.log("  1. pnpm add better-auth @getbrick/idaas-core");
  io.log("  2. create the auth instance:");
  io.log("     import { createIdaas } from '@getbrick/idaas-core'");
  io.log("     import { idaas } from './getbrick.config.js'");
  io.log("     export const auth = createIdaas({ config: idaas, database: yourDb })");
  io.log("  3. NestJS: GetbrickIdaasModule.forRoot({ auth })");
  io.log("  4. getbrick idaas migrate --auth-file src/auth.ts");
  return 0;
}

function cmdDoctor(args: string[], io: CliIO): number {
  const checks: Array<{ ok: boolean; msg: string; hint?: string }> = [];
  const configPath = join(io.cwd, CONFIG_FILE);
  const configExists = existsSync(configPath);
  checks.push({ ok: configExists, msg: `${CONFIG_FILE} exists` });

  if (configExists) {
    try {
      const content = readFileSync(configPath, "utf8");
      const code = stripCommentsAndStrings(content);
      checks.push({ ok: true, msg: `${CONFIG_FILE} is readable` });
      checks.push({
        ok: /\bexport\s+(?:const|let|var)\s+idaas\b/.test(code),
        msg: "config exports idaas",
        hint: "export const idaas = defineIdaasConfig(...)",
      });
      checks.push({
        ok: /\bdefineIdaasConfig\s*\(/.test(code),
        msg: "config calls defineIdaasConfig",
        hint: "import and call defineIdaasConfig from @getbrick/idaas-core",
      });
    } catch (error) {
      checks.push({ ok: false, msg: `${CONFIG_FILE} is readable`, hint: errorMessage(error) });
      checks.push({ ok: false, msg: "config exports idaas", hint: "config could not be read" });
      checks.push({ ok: false, msg: "config calls defineIdaasConfig", hint: "config could not be read" });
    }
  } else {
    checks.push({ ok: false, msg: `${CONFIG_FILE} is readable`, hint: "run: getbrick idaas init" });
    checks.push({ ok: false, msg: "config exports idaas", hint: "run: getbrick idaas init" });
    checks.push({ ok: false, msg: "config calls defineIdaasConfig", hint: "run: getbrick idaas init" });
  }

  let packageJson: Record<string, unknown> | undefined;
  try {
    const parsed: unknown = JSON.parse(readFileSync(join(io.cwd, "package.json"), "utf8"));
    if (!isRecord(parsed)) throw new Error("package.json must contain a JSON object");
    packageJson = parsed;
    checks.push({ ok: true, msg: "package.json is readable and valid JSON" });
  } catch (error) {
    checks.push({ ok: false, msg: "package.json is readable and valid JSON", hint: errorMessage(error) });
  }

  if (packageJson) {
    const dependencies = {
      ...asRecord(packageJson.dependencies),
      ...asRecord(packageJson.devDependencies),
    };
    checkDependency(checks, dependencies, "@getbrick/idaas-core", "pnpm add @getbrick/idaas-core");
    checkDependency(checks, dependencies, "better-auth", "pnpm add better-auth");
  }

  const migration = parseMigrateArgs(args, io.cwd);
  if (!migration.ok) {
    checks.push({ ok: false, msg: "migration parameters are valid", hint: migration.error });
  } else {
    checks.push({ ok: true, msg: "migration auth file exists" });
    if (migration.value.configFile && migration.value.configFile !== migration.value.authFile) {
      checks.push({ ok: true, msg: "migration config exists" });
    }
  }

  let failed = 0;
  for (const check of checks) {
    io.log(`${check.ok ? "✓" : "✗"} ${check.msg}${!check.ok && check.hint ? ` — ${check.hint}` : ""}`);
    if (!check.ok) failed++;
  }
  io.log(failed === 0 ? "All checks passed." : `${failed} check(s) failed.`);
  return failed === 0 ? 0 : 1;
}

async function cmdMigrate(args: string[], io: CliIO): Promise<number> {
  const parsed = parseMigrateArgs(args, io.cwd);
  if (!parsed.ok) {
    io.log(`✗ migrate: ${parsed.error}`);
    io.log(MIGRATE_USAGE);
    return 1;
  }
  const { authFile, configFile, dryRun } = parsed.value;
  io.log(`running better-auth migration${dryRun ? " (dry run)" : ""} ...`);
  try {
    return await io.runMigrate(io.cwd, authFile, { dryRun, config: configFile });
  } catch (error) {
    io.log(`✗ migration failed: ${errorMessage(error)}`);
    return 1;
  }
}

function checkDependency(
  checks: Array<{ ok: boolean; msg: string; hint?: string }>,
  dependencies: Record<string, unknown>,
  name: string,
  hint: string,
): void {
  const value = dependencies[name];
  checks.push({
    ok: typeof value === "string" && value.trim().length > 0,
    msg: `${name} is declared`,
    hint,
  });
}

function normalizeProjectFile(
  cwd: string,
  value: string,
  label: string,
): { ok: true; value: string } | { ok: false; error: string } {
  if (!value || /[\0\r\n]/.test(value)) return { ok: false, error: `${label} has an invalid path` };
  const root = resolve(cwd);
  const absolute = resolve(root, value);
  const projectRelative = relative(root, absolute);
  if (projectRelative === ".." || projectRelative.startsWith(`..${sep}`) || isAbsolute(projectRelative)) {
    return { ok: false, error: `${label} must stay within the project directory` };
  }

  let stats;
  try {
    stats = statSync(absolute);
  } catch {
    return { ok: false, error: `${label} does not exist` };
  }
  if (!stats.isFile()) return { ok: false, error: `${label} is not a file` };

  try {
    const realRoot = realpathSync(root);
    const realFile = realpathSync(absolute);
    const realRelative = relative(realRoot, realFile);
    if (realRelative === ".." || realRelative.startsWith(`..${sep}`) || isAbsolute(realRelative)) {
      return { ok: false, error: `${label} resolves outside the project directory` };
    }
  } catch {
    return { ok: false, error: `${label} cannot be resolved` };
  }

  return { ok: true, value: isAbsolute(value) ? absolute : projectRelative };
}

function stripCommentsAndStrings(source: string): string {
  let result = "";
  let quote: string | undefined;
  let lineComment = false;
  let blockComment = false;

  for (let index = 0; index < source.length; index++) {
    const character = source[index];
    const next = source[index + 1];
    if (lineComment) {
      if (character === "\n") {
        lineComment = false;
        result += "\n";
      }
      continue;
    }
    if (blockComment) {
      if (character === "*" && next === "/") {
        blockComment = false;
        result += " ";
        index++;
      }
      continue;
    }
    if (quote) {
      if (character === "\\") {
        index++;
      } else if (character === quote) {
        quote = undefined;
      }
      continue;
    }
    if (character === "/" && next === "/") {
      lineComment = true;
      index++;
      continue;
    }
    if (character === "/" && next === "*") {
      blockComment = true;
      index++;
      continue;
    }
    if (character === "\"" || character === "'" || character === "`") {
      quote = character;
      continue;
    }
    result += character;
  }
  return result;
}

function asRecord(value: unknown): Record<string, unknown> {
  return isRecord(value) ? value : {};
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function errorMessage(error: unknown): string {
  if (isRecord(error) && typeof error.code === "string") {
    const safeCodes = new Set(["EACCES", "EEXIST", "EINVAL", "EISDIR", "ENOENT", "ENOTDIR", "EPERM"]);
    if (safeCodes.has(error.code)) return error.code;
  }
  return "operation failed";
}
