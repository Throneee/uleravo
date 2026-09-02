import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import process from "node:process";
import { build } from "vite";
import { actionBuildConfig } from "../action/vite.config.mjs";

const temporary = await mkdtemp(path.join(tmpdir(), "uleravo-action-"));

try {
  await build(actionBuildConfig(temporary));
  const [committed, generated] = await Promise.all([
    readFile(new URL("../action/dist/index.cjs", import.meta.url)),
    readFile(path.join(temporary, "index.cjs")),
  ]);
  if (!committed.equals(generated)) {
    process.stderr.write(
      "action/dist/index.cjs is stale; run pnpm build:action and commit the result.\n",
    );
    process.exitCode = 1;
  }
} finally {
  await rm(temporary, { force: true, recursive: true });
}
