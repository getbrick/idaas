import { spawnSync } from "node:child_process";
import { run, type CliIO } from "./cli.js";

export async function main(argv: string[]): Promise<number> {
  const io: CliIO = {
    cwd: process.cwd(),
    log: (line) => console.log(line),
    runMigrate: (cwd, authFile) => {
      const result = spawnSync(
        "npx",
        ["-y", "@better-auth/cli", "migrate", authFile],
        { stdio: "inherit", cwd, shell: process.platform === "win32" },
      );
      if (result.error) {
        console.log(`✗ failed to run npx: ${result.error.message}`);
        return 1;
      }
      return result.status ?? 1;
    },
  };
  return run(argv, io);
}
