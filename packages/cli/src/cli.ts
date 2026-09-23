import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

export interface CliIO {
  cwd: string;
  log: (line: string) => void;
  runMigrate: (cwd: string, authFile: string) => number;
}

export const CONFIG_FILE = "getbrick.config.ts";

export async function run(argv: string[], io: CliIO): Promise<number> {
  const [product, command, ...rest] = argv;
  if (product !== "idaas") {
    io.log("Usage: getbrick idaas <init|doctor|migrate>");
    return product ? 1 : 0;
  }
  if (command === "init") return cmdInit(rest, io);
  if (command === "doctor") return cmdDoctor(io);
  if (command === "migrate") return cmdMigrate(rest, io);
  io.log("Usage: getbrick idaas <init|doctor|migrate>");
  return 1;
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
  const force = args.includes("--force");
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

function cmdDoctor(io: CliIO): number {
  const checks: Array<{ ok: boolean; msg: string; hint?: string }> = [];
  const configPath = join(io.cwd, CONFIG_FILE);
  const configExists = existsSync(configPath);
  checks.push({ ok: configExists, msg: `${CONFIG_FILE} exists` });
  if (configExists) {
    const content = readFileSync(configPath, "utf8");
    checks.push({ ok: content.includes("defineIdaasConfig"), msg: "config uses defineIdaasConfig" });
  } else {
    checks.push({ ok: false, msg: "config uses defineIdaasConfig", hint: "run: getbrick idaas init" });
  }
  try {
    const pkg = JSON.parse(readFileSync(join(io.cwd, "package.json"), "utf8"));
    const deps = { ...pkg.dependencies, ...pkg.devDependencies };
    const hasCore = Boolean(deps["@getbrick/idaas-core"]);
    checks.push({ ok: hasCore, msg: "@getbrick/idaas-core installed", hint: "pnpm add @getbrick/idaas-core" });
    const hasBetterAuth = Boolean(deps["better-auth"]);
    checks.push({ ok: hasBetterAuth, msg: "better-auth installed", hint: "pnpm add better-auth" });
  } catch {
    checks.push({ ok: false, msg: "package.json readable" });
  }
  let failed = 0;
  for (const c of checks) {
    io.log(`${c.ok ? "✓" : "✗"} ${c.msg}${!c.ok && c.hint ? ` — ${c.hint}` : ""}`);
    if (!c.ok) failed++;
  }
  io.log(failed === 0 ? "All checks passed." : `${failed} check(s) failed.`);
  return failed === 0 ? 0 : 1;
}

function cmdMigrate(args: string[], io: CliIO): number {
  const idx = args.indexOf("--auth-file");
  const authFile = idx >= 0 ? args[idx + 1] : args[0] ?? "src/auth.ts";
  io.log(`running better-auth migration for ${authFile} ...`);
  return io.runMigrate(io.cwd, authFile);
}
