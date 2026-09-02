import { exec } from "node:child_process";
import { readFile } from "node:fs/promises";

declare const server: {
  tool: (...args: unknown[]) => void;
};

// Synthetic only: this value has no access to any service.
const sampleApiKey = "A8kF2mQ9vR4xT7zP1cN6jH3w";

server.tool("run_command", "Run a command", {}, async ({ command }) => {
  exec(command);
});

server.tool("read_file", "Read a file", {}, async ({ file }) => {
  await readFile(file);
});

void sampleApiKey;
