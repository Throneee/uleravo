import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { main } from "../src/cli.js";
import { formatCodexHarnessJson } from "../src/formatters/codex-harness.js";
import { snapshotCodexHarness } from "../src/harnesses/codex.js";

const temporaryDirectories: string[] = [];

beforeEach(() => {
  vi.spyOn(process.stdout, "write").mockImplementation(() => true);
  vi.spyOn(process.stderr, "write").mockImplementation(() => true);
});

afterEach(async () => {
  await Promise.all(
    temporaryDirectories
      .splice(0)
      .map((directory) => rm(directory, { force: true, recursive: true })),
  );
});

describe("Codex harness CLI", () => {
  it("captures a supplied config without ambient layers", async () => {
    const workspace = await makeTemporaryDirectory();
    const project = path.join(workspace, "project");
    const config = path.join(workspace, "config.toml");
    await mkdir(project);
    await writeFile(config, 'sandbox_mode = "read-only"\n[features]\nplugins = false\n');

    const exitCode = await main([
      "harness",
      project,
      "--user-config",
      config,
      "--skip-project-config",
      "--skip-requirements",
      "--codex-version",
      "0.138.0",
      "--format",
      "json",
    ]);
    const output = vi.mocked(process.stdout.write).mock.calls.join("");
    const report = JSON.parse(output) as {
      capture: { complete: boolean };
      documentType: string;
      semanticFacts: Array<{ key: string; value: unknown }>;
    };

    expect(exitCode).toBe(0);
    expect(report.capture.complete).toBe(true);
    expect(report.documentType).toBe("uleravo.harness-snapshot");
    expect(report.semanticFacts).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ key: "filesystem.sandbox-mode", value: "read-only" }),
        expect.objectContaining({ key: "feature.plugins", value: false }),
      ]),
    );
  });

  it("compares persisted harness snapshots through the semantic delta command", async () => {
    const workspace = await makeTemporaryDirectory();
    const project = path.join(workspace, "project");
    const baselineConfig = path.join(workspace, "baseline.toml");
    const currentConfig = path.join(workspace, "current.toml");
    const baselinePath = path.join(workspace, "baseline.json");
    const currentPath = path.join(workspace, "current.json");
    await mkdir(project);
    await writeFile(baselineConfig, 'sandbox_mode = "read-only"\n');
    await writeFile(currentConfig, 'sandbox_mode = "danger-full-access"\n');
    const baseline = await snapshotCodexHarness(project, {
      projectConfig: null,
      requirements: null,
      userConfig: baselineConfig,
    });
    const current = await snapshotCodexHarness(project, {
      projectConfig: null,
      requirements: null,
      userConfig: currentConfig,
    });
    await Promise.all([
      writeFile(baselinePath, formatCodexHarnessJson(baseline)),
      writeFile(currentPath, formatCodexHarnessJson(current)),
    ]);

    expect(await main(["harness-delta", baselinePath, currentPath, "--format", "json"])).toBe(0);
    const output = vi.mocked(process.stdout.write).mock.calls.join("");
    const delta = JSON.parse(output) as {
      changes: Array<{ direction: string; key: string }>;
      documentType: string;
    };
    expect(delta.documentType).toBe("uleravo.harness-delta");
    expect(delta.changes).toContainEqual(
      expect.objectContaining({ direction: "expanded", key: "filesystem.sandbox-mode" }),
    );
  });

  it("rejects contradictory layer options", async () => {
    expect(await main(["harness", ".", "--user-config", "config.toml", "--skip-user-config"])).toBe(
      2,
    );
    expect(vi.mocked(process.stderr.write).mock.calls.join("")).toContain(
      "Cannot supply and skip user config",
    );
  });
});

async function makeTemporaryDirectory(): Promise<string> {
  const directory = await mkdtemp(path.join(tmpdir(), "uleravo-harness-cli-"));
  temporaryDirectories.push(directory);
  return directory;
}
