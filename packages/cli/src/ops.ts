import { createHash } from "node:crypto";
import {
  accessSync,
  constants as fsConstants,
  createReadStream,
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  realpathSync,
  writeFileSync,
} from "node:fs";
import { basename, extname, isAbsolute, join, relative, resolve, sep } from "node:path";

export const EXIT_USAGE = 2;
export const EXIT_FAILURE = 1;
export const EXIT_ENVIRONMENT = 78;
export const EXIT_TOOL_NOT_FOUND = 127;

export interface CommandRunOptions {
  cwd: string;
  env: NodeJS.ProcessEnv;
  stdio: "inherit";
  shell: false;
}

export type RunCommand = (command: string, args: string[], options: CommandRunOptions) => number | Promise<number>;

export interface OperationIO {
  cwd: string;
  env?: NodeJS.ProcessEnv;
  log: (line: string) => void;
  runCommand?: RunCommand;
  now?: () => Date;
}

export interface BackupCreateRequest {
  output: string;
}

export interface BackupVerifyRequest {
  input: string;
  digest?: string;
  manifest?: string;
}

export interface RestoreRequest {
  input: string;
  targetDb: string;
  digest?: string;
  manifest?: string;
  confirm?: string;
  yes?: boolean;
}

export interface ResolvedFile {
  path: string;
  realPath: string;
  size: number;
}

type PathResult =
  | { ok: true; value: ResolvedFile }
  | { ok: false; error: string; code: number };

type DirectoryResult = { ok: true; value: string } | { ok: false; error: string; code: number };

type ManifestResult =
  | { ok: true; value?: string; present: boolean }
  | { ok: false; error: string; code: number };

type InspectionResult =
  | {
      ok: true;
      value: {
        digest: string;
        size: number;
        manifestPath?: string;
      };
    }
  | { ok: false; error: string; code: number };

interface HashResult {
  digest: string;
  size: number;
}

interface ManifestData {
  digest: string;
  file?: string;
  size?: number;
}

export async function backupCreate(request: BackupCreateRequest, io: OperationIO): Promise<number> {
  const env = runtimeEnv(io);
  if (!hasDatabaseEnvironment(env)) {
    io.log("✗ backup:create: DATABASE_URL or PG* must be provided by the runtime environment");
    return EXIT_ENVIRONMENT;
  }

  const directory = resolveOutputDirectory(io.cwd, request.output);
  if (!directory.ok) {
    io.log(`✗ backup:create: ${directory.error}`);
    return directory.code;
  }

  let date: string;
  try {
    date = (io.now?.() ?? new Date()).toISOString();
  } catch {
    io.log("✗ backup:create: could not determine backup timestamp");
    return EXIT_FAILURE;
  }
  if (Number.isNaN(Date.parse(date))) {
    io.log("✗ backup:create: could not determine backup timestamp");
    return EXIT_FAILURE;
  }
  const file = join(directory.value, `backup-${date.replace(/[:.]/g, "-")}.dump`);
  if (existsSync(file)) {
    io.log("✗ backup:create: backup file already exists");
    return EXIT_FAILURE;
  }

  io.log("running pg_dump");
  const commandResult = await runTool(
    io,
    "pg_dump",
    ["--format=custom", "--file", file],
    "backup:create",
  );
  if (commandResult !== 0) return commandResult;

  const resolved = resolveReadableFile(io.cwd, file);
  if (!resolved.ok) {
    io.log(`✗ backup:create: pg_dump completed without a readable backup file: ${resolved.error}`);
    return resolved.code;
  }

  let hash: HashResult;
  try {
    hash = await sha256File(resolved.value.path);
  } catch {
    io.log("✗ backup:create: could not hash backup");
    return EXIT_FAILURE;
  }

  const manifestPath = `${file}.manifest.json`;
  const manifest = `${JSON.stringify(
    {
      version: 1,
      file: basename(file),
      sha256: hash.digest,
      size: hash.size,
      createdAt: date,
    },
    null,
    2,
  )}\n`;
  try {
    writeFileSync(manifestPath, manifest, { flag: "wx" });
  } catch {
    io.log("✗ backup:create: could not write manifest");
    return EXIT_FAILURE;
  }

  io.log("✓ backup created");
  io.log("✓ manifest created");
  io.log(`sha256: ${hash.digest}`);
  io.log("the CLI does not encrypt backup output or manage file permissions");
  return 0;
}

export async function backupVerify(request: BackupVerifyRequest, io: OperationIO): Promise<number> {
  const file = resolveReadableFile(io.cwd, request.input);
  if (!file.ok) {
    io.log(`✗ backup:verify: ${file.error}`);
    return file.code;
  }

  const inspection = await inspectBackup(file.value, {
    cwd: io.cwd,
    digest: request.digest,
    manifest: request.manifest,
    requireManifest: true,
  });
  if (!inspection.ok) {
    io.log(`✗ backup:verify: ${inspection.error}`);
    return inspection.code;
  }

  io.log("✓ backup verified");
  io.log(`sha256: ${inspection.value.digest}`);
  if (inspection.value.manifestPath) io.log("manifest verified");
  else io.log("manifest: not present; supplied digest was used");
  return 0;
}

export async function restorePlan(request: RestoreRequest, io: OperationIO): Promise<number> {
  const target = validateTargetDatabase(request.targetDb);
  if (!target.ok) {
    io.log(`✗ restore:plan: ${target.error}`);
    return EXIT_USAGE;
  }
  const file = resolveReadableFile(io.cwd, request.input);
  if (!file.ok) {
    io.log(`✗ restore:plan: ${file.error}`);
    return file.code;
  }

  const env = runtimeEnv(io);
  if (isCurrentDatabase(env, target.value)) {
    io.log("✗ restore:plan: target database must be new, not the current database");
    return EXIT_USAGE;
  }

  const inspection = await inspectBackup(file.value, {
    cwd: io.cwd,
    digest: request.digest,
    manifest: request.manifest,
    requireManifest: false,
  });
  if (!inspection.ok) {
    io.log(`✗ restore:plan: ${inspection.error}`);
    return inspection.code;
  }

  io.log("restore plan for a new database");
  io.log(`sha256: ${inspection.value.digest}`);
  const commandResult = await runTool(io, "pg_restore", ["--list", file.value.path], "restore:plan");
  if (commandResult !== 0) return commandResult;
  io.log("✓ restore plan ready for a new database");
  return 0;
}

export async function restoreApply(request: RestoreRequest, io: OperationIO): Promise<number> {
  if (!request.confirm) {
    io.log("✗ restore:apply: --confirm <sha256> is required");
    return EXIT_USAGE;
  }
  const confirmation = normalizeDigest(request.confirm);
  if (!confirmation) {
    io.log("✗ restore:apply: --confirm must be exactly 64 hexadecimal characters");
    return EXIT_USAGE;
  }

  const env = runtimeEnv(io);
  if (!hasDatabaseEnvironment(env)) {
    io.log("✗ restore:apply: DATABASE_URL or PG* must be provided by the runtime environment");
    return EXIT_ENVIRONMENT;
  }

  const target = validateTargetDatabase(request.targetDb);
  if (!target.ok) {
    io.log(`✗ restore:apply: ${target.error}`);
    return EXIT_USAGE;
  }
  const file = resolveReadableFile(io.cwd, request.input);
  if (!file.ok) {
    io.log(`✗ restore:apply: ${file.error}`);
    return file.code;
  }

  if (isCurrentDatabase(env, target.value)) {
    io.log("✗ restore:apply: target database must be new, not the current database");
    return EXIT_USAGE;
  }

  const inspection = await inspectBackup(file.value, {
    cwd: io.cwd,
    digest: request.digest,
    manifest: request.manifest,
    requireManifest: false,
  });
  if (!inspection.ok) {
    io.log(`✗ restore:apply: ${inspection.error}`);
    return inspection.code;
  }
  if (inspection.value.digest !== confirmation) {
    io.log("✗ restore:apply: confirmation digest does not match the backup");
    return EXIT_FAILURE;
  }

  io.log("restoring backup into the requested new database");
  io.log(`confirmed sha256: ${inspection.value.digest}`);
  const createResult = await runTool(
    io,
    "createdb",
    ["--template=template0", target.value],
    "restore:apply",
  );
  if (createResult !== 0) return createResult;
  const commandResult = await runTool(
    io,
    "pg_restore",
    ["--exit-on-error", "--dbname", target.value, file.value.path],
    "restore:apply",
  );
  if (commandResult !== 0) return commandResult;
  io.log("✓ restore applied to a new database");
  return 0;
}

export function hasDatabaseEnvironment(env: NodeJS.ProcessEnv): boolean {
  if (typeof env.DATABASE_URL === "string" && env.DATABASE_URL.trim().length > 0) return true;
  return Object.entries(env).some(([name, value]) => /^PG[A-Z0-9_]+$/.test(name) && typeof value === "string" && value.trim().length > 0);
}

export function currentDatabase(env: NodeJS.ProcessEnv): string | undefined {
  const databaseUrl = typeof env.DATABASE_URL === "string" ? env.DATABASE_URL.trim() : "";
  if (databaseUrl) {
    const fromUrl = databaseNameFromUrl(databaseUrl);
    if (fromUrl) return fromUrl;
    const fromConnectionString = databaseNameFromConnectionString(databaseUrl);
    if (fromConnectionString) return fromConnectionString;
  }
  const database = typeof env.PGDATABASE === "string" ? env.PGDATABASE.trim() : "";
  return database || undefined;
}

function databaseNameFromUrl(value: string): string | undefined {
  try {
    const parsed = new URL(value);
    const queryName = parsed.searchParams.get("dbname")?.trim();
    if (queryName) return queryName;
    const pathname = parsed.pathname.replace(/^\/+/, "");
    if (!pathname) return undefined;
    return decodeURIComponent(pathname);
  } catch {
    return undefined;
  }
}

function databaseNameFromConnectionString(value: string): string | undefined {
  const match = /(?:^|\s)dbname=(?:"([^"]*)"|'([^']*)'|([^\s]+))/i.exec(value);
  const name = match?.[1] ?? match?.[2] ?? match?.[3];
  return name || undefined;
}

function databaseUserFromUrl(value: string): string | undefined {
  try {
    const parsed = new URL(value);
    return parsed.username ? decodeURIComponent(parsed.username) : undefined;
  } catch {
    return undefined;
  }
}

function databaseUserFromConnectionString(value: string): string | undefined {
  const match = /(?:^|\s)user=(?:"([^"]*)"|'([^']*)'|([^\s]+))/i.exec(value);
  const user = match?.[1] ?? match?.[2] ?? match?.[3];
  return user || undefined;
}

function isCurrentDatabase(env: NodeJS.ProcessEnv, target: string): boolean {
  const current = currentDatabase(env);
  if (current && sameDatabaseName(current, target)) return true;
  const pgDatabase = typeof env.PGDATABASE === "string" ? env.PGDATABASE.trim() : "";
  if (pgDatabase && sameDatabaseName(pgDatabase, target)) return true;

  const databaseUrl = typeof env.DATABASE_URL === "string" ? env.DATABASE_URL.trim() : "";
  const explicitDatabase = databaseUrl
    ? databaseNameFromUrl(databaseUrl) ?? databaseNameFromConnectionString(databaseUrl)
    : undefined;
  if (explicitDatabase || pgDatabase) return false;

  const urlUser = databaseUrl
    ? databaseUserFromUrl(databaseUrl) ?? databaseUserFromConnectionString(databaseUrl)
    : undefined;
  const configuredUser = typeof env.PGUSER === "string" ? env.PGUSER.trim() : "";
  const operatingSystemUser = typeof env.USER === "string" ? env.USER.trim() : "";
  const defaultUser = urlUser || configuredUser || operatingSystemUser;
  return Boolean(defaultUser && sameDatabaseName(defaultUser, target));
}

function sameDatabaseName(left: string, right: string): boolean {
  return left.toLowerCase() === right.toLowerCase();
}

export function resolveReadableFile(cwd: string, value: string): PathResult {
  const path = resolveSafePath(cwd, value);
  if (!path.ok) return path;

  let stats;
  try {
    stats = lstatSync(path.value);
  } catch (error) {
    const code = errorCode(error);
    if (code === "ENOENT") {
      return { ok: false, error: "input file does not exist", code: EXIT_FAILURE };
    }
    return { ok: false, error: "input file cannot be accessed", code: EXIT_FAILURE };
  }
  if (stats.isSymbolicLink()) {
    return { ok: false, error: "input file must not be a symbolic link", code: EXIT_USAGE };
  }
  if (!stats.isFile()) {
    return { ok: false, error: "input path is not a file", code: EXIT_USAGE };
  }

  try {
    accessSync(path.value, fsConstants.R_OK);
  } catch {
    return { ok: false, error: "input file is not readable", code: EXIT_FAILURE };
  }

  let realPath: string;
  try {
    realPath = realpathSync(path.value);
    if (!isAbsolute(value)) {
      const realRoot = realpathSync(cwd);
      const realRelative = relative(realRoot, realPath);
      if (escapesRoot(realRelative)) {
        return { ok: false, error: "input path resolves outside the project directory", code: EXIT_USAGE };
      }
    }
  } catch {
    return { ok: false, error: "input path cannot be resolved", code: EXIT_FAILURE };
  }

  return { ok: true, value: { path: path.value, realPath, size: stats.size } };
}

function resolveOutputDirectory(cwd: string, value: string): DirectoryResult {
  const path = resolveSafePath(cwd, value);
  if (!path.ok) return path;

  let stats;
  try {
    stats = lstatSync(path.value);
    if (stats.isSymbolicLink()) {
      return { ok: false, error: "output directory must not be a symbolic link", code: EXIT_USAGE };
    }
    if (!stats.isDirectory()) {
      return { ok: false, error: "output path is not a directory", code: EXIT_USAGE };
    }
  } catch (error) {
    if (errorCode(error) !== "ENOENT") {
      return { ok: false, error: "output directory cannot be accessed", code: EXIT_FAILURE };
    }
    try {
      mkdirSync(path.value, { recursive: true });
      stats = lstatSync(path.value);
    } catch {
      return { ok: false, error: "output directory cannot be created", code: EXIT_FAILURE };
    }
  }

  if (stats.isSymbolicLink() || !stats.isDirectory()) {
    return { ok: false, error: "output path is not a directory", code: EXIT_USAGE };
  }
  if (!isAbsolute(value)) {
    try {
      const realRoot = realpathSync(cwd);
      const realRelative = relative(realRoot, realpathSync(path.value));
      if (escapesRoot(realRelative)) {
        return { ok: false, error: "output directory resolves outside the project directory", code: EXIT_USAGE };
      }
    } catch {
      return { ok: false, error: "output directory cannot be resolved", code: EXIT_FAILURE };
    }
  }
  return { ok: true, value: path.value };
}

function resolveSafePath(cwd: string, value: string): { ok: true; value: string } | { ok: false; error: string; code: number } {
  if (typeof value !== "string" || !value || /[\0\r\n]/.test(value)) {
    return { ok: false, error: "path has an invalid value", code: EXIT_USAGE };
  }
  if (value.split(/[\\/]+/).some((segment) => segment === "..")) {
    return { ok: false, error: "path traversal is not allowed", code: EXIT_USAGE };
  }
  return { ok: true, value: resolve(cwd, value) };
}

function escapesRoot(value: string): boolean {
  return value === ".." || value.startsWith(`..${sep}`) || isAbsolute(value);
}

function validateTargetDatabase(value: string): { ok: true; value: string } | { ok: false; error: string } {
  if (typeof value !== "string" || !/^[A-Za-z_][A-Za-z0-9_-]{0,62}$/.test(value)) {
    return { ok: false, error: "target database must be a simple database name" };
  }
  return { ok: true, value };
}

async function inspectBackup(
  file: ResolvedFile,
  options: { cwd: string; digest?: string; manifest?: string; requireManifest: boolean },
): Promise<InspectionResult> {
  let manifest: ManifestResult;
  if (options.manifest !== undefined) {
    const manifestFile = resolveReadableFile(options.cwd, options.manifest);
    if (!manifestFile.ok) {
      return { ok: false, error: `manifest cannot be read: ${manifestFile.error}`, code: manifestFile.code };
    }
    manifest = { ok: true, value: manifestFile.value.path, present: true };
  } else {
    const extension = extname(file.path);
    const stem = extension ? file.path.slice(0, -extension.length) : file.path;
    const candidates = [`${file.path}.manifest.json`, `${file.path}.manifest`, `${stem}.manifest.json`];
    const candidate = candidates.find((value) => existsSync(value));
    if (candidate) {
      const manifestFile = resolveReadableFile(options.cwd, candidate);
      if (!manifestFile.ok) {
        return { ok: false, error: `manifest cannot be read: ${manifestFile.error}`, code: manifestFile.code };
      }
      manifest = { ok: true, value: manifestFile.value.path, present: true };
    } else {
      manifest = { ok: true, present: false };
    }
  }

  let manifestData: ManifestData | undefined;
  if (manifest.ok && manifest.present && manifest.value) {
    const parsed = readManifest(manifest.value);
    if (!parsed.ok) return parsed;
    manifestData = parsed.value;
  }

  let hash: HashResult;
  try {
    hash = await sha256File(file.path);
  } catch {
    return { ok: false, error: "input file is not readable", code: EXIT_FAILURE };
  }

  if (manifestData) {
    if (manifestData.digest !== hash.digest) {
      return { ok: false, error: "SHA-256 does not match the manifest", code: EXIT_FAILURE };
    }
    if (manifestData.size !== undefined && manifestData.size !== hash.size) {
      return { ok: false, error: "backup size does not match the manifest", code: EXIT_FAILURE };
    }
    if (
      manifestData.file !== undefined &&
      (!isManifestFileName(manifestData.file) || manifestData.file !== basename(file.path))
    ) {
      return { ok: false, error: "manifest file name does not match the backup", code: EXIT_FAILURE };
    }
  }

  if (options.digest !== undefined) {
    const supplied = normalizeManifestDigest(options.digest);
    if (!supplied) {
      return { ok: false, error: "digest must be a 64-character SHA-256 value", code: EXIT_USAGE };
    }
    if (supplied !== hash.digest) {
      return { ok: false, error: "SHA-256 does not match the supplied digest", code: EXIT_FAILURE };
    }
  }
  if (options.requireManifest && !manifestData && options.digest === undefined) {
    return { ok: false, error: "backup manifest is required; use --digest only for an explicit digest check", code: EXIT_FAILURE };
  }

  return {
    ok: true,
    value: {
      digest: hash.digest,
      size: hash.size,
      manifestPath: manifest.value,
    },
  };
}

function readManifest(path: string): { ok: true; value: ManifestData } | { ok: false; error: string; code: number } {
  let source: string;
  try {
    source = readFileSync(path, "utf8");
  } catch {
    return { ok: false, error: "manifest cannot be read", code: EXIT_FAILURE };
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(source);
  } catch {
    const textDigest = normalizeManifestDigest(source.trim().split(/\s+/, 1)[0] ?? "");
    if (!textDigest) return { ok: false, error: "manifest is not valid JSON or SHA-256 text", code: EXIT_FAILURE };
    return { ok: true, value: { digest: textDigest } };
  }

  if (!isRecord(parsed)) {
    return { ok: false, error: "manifest must contain a JSON object", code: EXIT_FAILURE };
  }
  const algorithm = parsed.algorithm;
  if (algorithm !== undefined && algorithm !== "sha256" && algorithm !== "SHA-256") {
    return { ok: false, error: "manifest algorithm must be SHA-256", code: EXIT_FAILURE };
  }

  const digestValue = parsed.sha256 ?? parsed.digest ?? parsed.checksum;
  if (typeof digestValue !== "string") {
    return { ok: false, error: "manifest does not contain a SHA-256 digest", code: EXIT_FAILURE };
  }
  const digest = normalizeManifestDigest(digestValue);
  if (!digest) {
    return { ok: false, error: "manifest contains an invalid SHA-256 digest", code: EXIT_FAILURE };
  }

  let size: number | undefined;
  if (parsed.size !== undefined || parsed.bytes !== undefined) {
    const sizeValue = parsed.size ?? parsed.bytes;
    if (
      (typeof sizeValue !== "number" && typeof sizeValue !== "string") ||
      (typeof sizeValue === "string" && !/^\d+$/.test(sizeValue))
    ) {
      return { ok: false, error: "manifest contains an invalid backup size", code: EXIT_FAILURE };
    }
    const numericSize = typeof sizeValue === "number" ? sizeValue : Number(sizeValue);
    if (!Number.isSafeInteger(numericSize) || numericSize < 0) {
      return { ok: false, error: "manifest contains an invalid backup size", code: EXIT_FAILURE };
    }
    size = numericSize;
  }

  let file: string | undefined;
  if (parsed.file !== undefined) {
    if (typeof parsed.file !== "string" || !parsed.file) {
      return { ok: false, error: "manifest contains an invalid file name", code: EXIT_FAILURE };
    }
    file = parsed.file;
  }

  return { ok: true, value: { digest, file, size } };
}

function normalizeDigest(value: string): string | undefined {
  return typeof value === "string" && /^[a-f0-9]{64}$/i.test(value) ? value.toLowerCase() : undefined;
}

function normalizeManifestDigest(value: string): string | undefined {
  const normalized = value.trim().replace(/^sha256:/i, "");
  return /^[a-f0-9]{64}$/i.test(normalized) ? normalized.toLowerCase() : undefined;
}

function isManifestFileName(value: string): boolean {
  return Boolean(value) && value !== "." && value !== ".." && !/[\\/\0\r\n]/.test(value);
}

async function sha256File(path: string): Promise<HashResult> {
  return new Promise((resolveHash, reject) => {
    const hash = createHash("sha256");
    let size = 0;
    const stream = createReadStream(path);
    stream.on("data", (chunk: string | Buffer) => {
      const bytes = typeof chunk === "string" ? Buffer.from(chunk) : chunk;
      size += bytes.length;
      hash.update(bytes);
    });
    stream.on("error", reject);
    stream.on("end", () => resolveHash({ digest: hash.digest("hex"), size }));
  });
}

async function runTool(io: OperationIO, command: string, args: string[], label: string): Promise<number> {
  if (!io.runCommand) {
    io.log(`✗ ${label}: ${command} is not available`);
    return EXIT_TOOL_NOT_FOUND;
  }
  try {
    const result = await io.runCommand(command, args, { cwd: io.cwd, env: runtimeEnv(io), stdio: "inherit", shell: false });
    if (result === 0) return 0;
    return result === EXIT_TOOL_NOT_FOUND ? EXIT_TOOL_NOT_FOUND : EXIT_FAILURE;
  } catch {
    io.log(`✗ ${label}: failed to run ${command}`);
    return EXIT_FAILURE;
  }
}

function runtimeEnv(io: OperationIO): NodeJS.ProcessEnv {
  return io.env ?? process.env;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function errorCode(error: unknown): string | undefined {
  if (!isRecord(error) || typeof error.code !== "string") return undefined;
  return /^[A-Z][A-Z0-9_]{0,31}$/.test(error.code) ? error.code : undefined;
}
