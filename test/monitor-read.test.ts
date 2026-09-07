import * as fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { readConfig } from "../src/monitor/read.js";

// Intercept the open boundary only to make a filesystem race deterministic.
vi.mock("node:fs/promises", async (original) => ({ ...(await original<typeof fs>()) }));

let directory: string;
beforeEach(async () => {
  directory = await fs.mkdtemp(path.join(os.tmpdir(), "uleravo-monitor-race-"));
});
afterEach(async () => {
  vi.restoreAllMocks();
  await fs.rm(directory, { recursive: true, force: true });
});

it("rejects a file changed between lstat and open using real filesystem metadata", async () => {
  const file = path.join(directory, "config.json");
  await fs.writeFile(file, "{}");
  const original = fs.open;
  vi.spyOn(fs, "open").mockImplementation(async (...args) => {
    await fs.writeFile(file, '{"changed": true}');
    return original(...args);
  });
  await expect(readConfig(file)).rejects.toThrow();
});

it("rejects an ancestor replaced with a junction after the final metadata read", async () => {
  const parent = path.join(directory, "parent");
  const moved = path.join(directory, "moved");
  await fs.mkdir(parent);
  const file = path.join(parent, "config.json");
  await fs.writeFile(file, "{}");
  const original = fs.open;
  let swapped = false;
  vi.spyOn(fs, "open").mockImplementation(async (...args) => {
    const handle = await original(...args);
    let calls = 0;
    handle.stat = new Proxy(handle.stat, {
      apply: async (fn, receiver, statArgs) => {
        const metadata = await Reflect.apply(fn, receiver, statArgs);
        if (++calls === 2) {
          // Windows prevents renaming an open parent; close after final fstat.
          await handle.close();
          await fs.rename(parent, moved);
          await fs.symlink(moved, parent, process.platform === "win32" ? "junction" : "dir");
          swapped = true;
        }
        return metadata;
      },
    });
    return handle;
  });
  const result = readConfig(file);
  await expect(result).rejects.toThrow();
  expect(swapped).toBe(true);
});

it("rejects configuration changed during a bounded read", async () => {
  const file = path.join(directory, "config.json");
  await fs.writeFile(file, "{}");
  const original = fs.open;
  vi.spyOn(fs, "open").mockImplementation(async (...args) => {
    const handle = await original(...args);
    let changed = false;
    handle.read = new Proxy(handle.read, {
      apply: async (fn, receiver, readArgs) => {
        const result = await Reflect.apply(fn, receiver, readArgs);
        if (!changed) {
          changed = true;
          await fs.writeFile(file, '{"changed": true}');
        }
        return result;
      },
    });
    return handle;
  });
  await expect(readConfig(file)).rejects.toThrow();
});
