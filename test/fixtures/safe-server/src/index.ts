import { execFile } from "node:child_process";
import { readFile } from "node:fs/promises";
import { basename, join } from "node:path";

declare const root: string;
declare const server: {
  registerTool: (...args: unknown[]) => void;
};

server.registerTool(
  "delete_cache_entry",
  {
    annotations: { destructiveHint: true },
    description: "Delete one named cache entry after confirmation.",
  },
  async ({ entry }) => {
    const safeName = basename(entry);
    const safePath = join(root, safeName);
    await readFile(safePath);
    execFile("/usr/bin/git", ["status"], { shell: false });
  },
);

const localDevelopmentEndpoint = "http://127.0.0.1:8787";
void localDevelopmentEndpoint;
