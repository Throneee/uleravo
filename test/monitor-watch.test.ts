import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { runMonitor } from "../src/monitor/index.js";

let project: string;
let output: string[];
beforeEach(async () => {
  project = await mkdtemp(path.join(os.tmpdir(), "uleravo-monitor-watch-"));
  output = [];
  vi.spyOn(console, "log").mockImplementation((line: string) => {
    output.push(line);
  });
  vi.spyOn(console, "error").mockImplementation(() => {});
});
afterEach(async () => {
  vi.restoreAllMocks();
  vi.unstubAllEnvs();
  await rm(project, { recursive: true, force: true });
});

it("recaptures current declarations on each watch interval with fresh capture IDs and stable finding IDs", async () => {
  await mkdir(path.join(project, ".claude"));
  const file = path.join(project, ".claude/settings.json");
  await writeFile(file, '{"permissions":{"defaultMode":"bypassPermissions"}}');
  const stop = new AbortController();
  const sleeps: number[] = [];
  const before = process.listenerCount("SIGINT");
  expect(
    await runMonitor(["--project", project, "--watch", "--interval", "30"], {
      signal: stop.signal,
      sleep: async (ms: number) => {
        sleeps.push(ms);
        if (sleeps.length === 2) await writeFile(file, "{}");
        if (sleeps.length === 3) stop.abort();
      },
    }),
  ).toBe(0);
  const snapshots = output.map((line) => JSON.parse(line));
  expect(snapshots).toHaveLength(3);
  expect(new Set(snapshots.map((s) => s.captureId)).size).toBe(3);
  expect(snapshots[0].findings).toEqual(snapshots[1].findings);
  expect(snapshots[2].findings).toEqual([]);
  expect(sleeps).toEqual([30000, 30000, 30000]);
  expect(process.listenerCount("SIGINT")).toBe(before);
});
