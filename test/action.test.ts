import {
  cp,
  link,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import { runAction } from "../src/action.js";
import { readScanReport } from "../src/reports/read.js";

const fixtures = fileURLToPath(new URL("./fixtures", import.meta.url));
const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryDirectories
      .splice(0)
      .map((directory) => rm(directory, { force: true, recursive: true })),
  );
});

describe("GitHub Action adapter", () => {
  it("writes bounded evidence, provenance, outputs, and a numeric summary", async () => {
    const workspace = await workspaceWithFixture("safe-server");
    const environment = actionEnvironment(workspace);
    const stdout: string[] = [];
    const stderr: string[] = [];

    expect(
      await runAction({
        environment,
        stderr: (message) => stderr.push(message),
        stdout: (message) => stdout.push(message),
      }),
    ).toBe(0);

    const report = await readScanReport(path.join(workspace, "uleravo.json"));
    const sarif = JSON.parse(await readFile(path.join(workspace, "uleravo.sarif"), "utf8")) as {
      runs: Array<{ properties: { scanId: string } }>;
    };
    const outputs = parseCommandFile(await readFile(environment.GITHUB_OUTPUT ?? "", "utf8"));
    const summary = await readFile(environment.GITHUB_STEP_SUMMARY ?? "", "utf8");

    expect(report.scan.filesScanned).toBe(3);
    expect(report.provenance?.repository).toEqual({
      commit: "a".repeat(40),
      url: "https://github.com/Throneee/uleravo",
    });
    expect(sarif.runs[0]?.properties.scanId).toBe(report.scan.id);
    expect(outputs).toMatchObject({
      critical: "0",
      "error-diagnostics": "0",
      findings: "0",
      "has-findings": "false",
      outcome: "passed",
      report: "uleravo.json",
      sarif: "uleravo.sarif",
      "scan-complete": "true",
      "scan-id": report.scan.id,
      "threshold-exceeded": "false",
      "warning-diagnostics": "0",
    });
    expect(summary).toContain("| 0 | 0 | 0 | 0 | 0 | 0 |");
    expect(summary).toContain(
      "**Complete observation.** Findings are reported but do not fail this step.",
    );
    expect(stdout.join("")).toContain("0 findings");
    expect(stdout.join("")).toContain("complete observation");
    expect(stderr).toEqual([]);
  });

  it("preserves reports before returning the configured finding failure", async () => {
    const workspace = await workspaceWithFixture("vulnerable-server");
    const environment: Record<string, string> = {
      ...actionEnvironment(workspace),
      "INPUT_FAIL-ON": "high",
    };
    const stderr: string[] = [];
    const enforcedStdout: string[] = [];

    expect(
      await runAction({
        environment,
        stderr: (message) => stderr.push(message),
        stdout: (message) => enforcedStdout.push(message),
      }),
    ).toBe(1);
    const report = await readScanReport(path.join(workspace, "uleravo.json"));
    const outputs = parseCommandFile(await readFile(environment.GITHUB_OUTPUT ?? "", "utf8"));

    expect(report.summary.high + report.summary.critical).toBeGreaterThan(0);
    expect(outputs.outcome).toBe("findings");
    expect(outputs["has-findings"]).toBe("true");
    expect(outputs["scan-complete"]).toBe("true");
    expect(outputs["threshold-exceeded"]).toBe("true");
    expect(enforcedStdout.join("")).toContain("complete threshold exceeded");
    expect(stderr.join("")).toContain("high failure threshold");

    const observationStderr: string[] = [];
    const observationStdout: string[] = [];
    expect(
      await runAction({
        environment: {
          ...actionEnvironment(workspace),
          INPUT_OUTPUT: "accepted.json",
          "INPUT_SARIF-OUTPUT": "accepted.sarif",
        },
        stderr: (message) => observationStderr.push(message),
        stdout: (message) => observationStdout.push(message),
      }),
    ).toBe(0);
    const observationOutputs = parseCommandFile(
      await readFile(environment.GITHUB_OUTPUT ?? "", "utf8"),
    );
    expect(observationOutputs).toMatchObject({
      "has-findings": "true",
      outcome: "passed",
      "scan-complete": "true",
      "threshold-exceeded": "false",
    });
    expect(observationStdout.join("")).toContain("complete observation");
    const observationSummary = await readFile(environment.GITHUB_STEP_SUMMARY ?? "", "utf8");
    expect(observationSummary).toContain(
      "**Complete observation.** Findings are reported but do not fail this step.",
    );
    const observationSurface = [
      observationStdout.join(""),
      observationStderr.join(""),
      observationSummary,
      await readFile(environment.GITHUB_OUTPUT ?? "", "utf8"),
    ].join("\n");
    for (const finding of report.findings) {
      expect(observationSurface).not.toContain(finding.evidence);
    }
  });

  it("fails closed while preserving evidence when a scannable file exceeds its limit", async () => {
    const workspace = await workspaceWithFixture("vulnerable-server");
    const environment: Record<string, string> = {
      ...actionEnvironment(workspace),
      "INPUT_FAIL-ON": "none",
      "INPUT_MAX-FILE-BYTES": "100",
    };

    const stderr: string[] = [];
    const stdout: string[] = [];
    expect(
      await runAction({
        environment,
        stderr: (message) => stderr.push(message),
        stdout: (message) => stdout.push(message),
      }),
    ).toBe(2);
    const report = await readScanReport(path.join(workspace, "uleravo.json"));
    const sarif = JSON.parse(await readFile(path.join(workspace, "uleravo.sarif"), "utf8")) as {
      runs: Array<{
        invocations: Array<{
          executionSuccessful: boolean;
          toolExecutionNotifications: Array<{ locations?: unknown[] }>;
        }>;
      }>;
    };
    const outputs = parseCommandFile(await readFile(environment.GITHUB_OUTPUT ?? "", "utf8"));

    expect(report.diagnostics).toContainEqual(
      expect.objectContaining({ file: "src/index.ts", type: "error" }),
    );
    expect(sarif.runs[0]?.invocations[0]?.executionSuccessful).toBe(false);
    expect(sarif.runs[0]?.invocations[0]?.toolExecutionNotifications[0]?.locations).toHaveLength(1);
    expect(outputs.outcome).toBe("error");
    expect(outputs["scan-complete"]).toBe("false");
    expect(outputs["threshold-exceeded"]).toBe("false");
    expect(Number(outputs["error-diagnostics"])).toBeGreaterThan(0);
    expect(outputs["warning-diagnostics"]).toBe("0");
    expect(stdout.join("")).toContain("incomplete scan");
    expect(stderr.join("")).toContain("must not be treated as clean");
    expect(await readFile(environment.GITHUB_STEP_SUMMARY ?? "", "utf8")).toContain(
      "**Incomplete.** Do not interpret the finding count as a clean result.",
    );
  });

  it("fails closed when the target contains no scannable files", async () => {
    const workspace = await workspaceWithFixture("safe-server");
    const environment: Record<string, string> = {
      ...actionEnvironment(workspace),
      INPUT_TARGET: "server/README.md",
    };
    await writeFile(path.join(workspace, "server", "README.md"), "documentation only\n");

    expect(await quietRun(environment)).toBe(2);
    const report = await readScanReport(path.join(workspace, "uleravo.json"));
    const outputs = parseCommandFile(await readFile(environment.GITHUB_OUTPUT ?? "", "utf8"));

    expect(report.scan.filesScanned).toBe(0);
    expect(report.diagnostics).toContainEqual(
      expect.objectContaining({ message: expect.stringContaining("No scannable"), type: "error" }),
    );
    expect(outputs.outcome).toBe("error");
    expect(outputs["scan-complete"]).toBe("false");
  });

  it("reports warning diagnostics without making a complete observation fail", async () => {
    const workspace = await workspaceWithFixture("safe-server");
    await writeFile(path.join(workspace, "server", "invalid.json"), "{\n");
    const environment: Record<string, string> = {
      ...actionEnvironment(workspace),
      "INPUT_FAIL-ON": "none",
    };

    expect(await quietRun(environment)).toBe(0);
    const outputs = parseCommandFile(await readFile(environment.GITHUB_OUTPUT ?? "", "utf8"));

    expect(outputs).toMatchObject({
      "error-diagnostics": "0",
      outcome: "passed",
      "scan-complete": "true",
      "threshold-exceeded": "false",
      "warning-diagnostics": "1",
    });
  });

  it("rejects pre-existing evidence files inside the scan target", async () => {
    const workspace = await workspaceWithFixture("safe-server");
    const environment: Record<string, string> = {
      ...actionEnvironment(workspace),
      INPUT_OUTPUT: "server/uleravo.json",
      "INPUT_SARIF-OUTPUT": "server/uleravo.sarif",
    };

    expect(await quietRun(environment)).toBe(0);
    const firstReport = await readFile(path.join(workspace, "server/uleravo.json"), "utf8");
    expect(await quietRun(environment)).toBe(2);
    expect(await readFile(path.join(workspace, "server/uleravo.json"), "utf8")).toBe(firstReport);
  });

  it.skipIf(process.platform === "win32")(
    "keeps literal-backslash outputs distinct from nested source paths on POSIX",
    async () => {
      const workspace = await workspaceWithFixture("safe-server");
      await mkdir(path.join(workspace, "server", "reports"));
      await writeFile(
        path.join(workspace, "server", "reports", "uleravo.json"),
        JSON.stringify({ endpoint: "http://example.com" }),
      );
      const environment: Record<string, string> = {
        ...actionEnvironment(workspace),
        INPUT_OUTPUT: "server/reports\\uleravo.json",
      };

      expect(await quietRun(environment)).toBe(0);
      const report = await readScanReport(path.join(workspace, "server", "reports\\uleravo.json"));
      expect(report.findings.some((finding) => finding.file === "reports/uleravo.json")).toBe(true);
    },
  );

  it("does not exclude a committed default output before scanning", async () => {
    const workspace = await workspaceWithFixture("safe-server");
    const output = path.join(workspace, "server", "uleravo.json");
    const committed = JSON.stringify({ endpoint: "http://example.com" });
    await writeFile(output, committed);
    const environment: Record<string, string> = {
      ...actionEnvironment(workspace),
      INPUT_OUTPUT: "server/uleravo.json",
    };

    expect(await quietRun(environment)).toBe(2);
    expect(await readFile(output, "utf8")).toBe(committed);
  });

  it("rejects targets and outputs that escape the workspace", async () => {
    const workspace = await workspaceWithFixture("safe-server");
    const parent = path.dirname(workspace);
    const messages: string[] = [];

    expect(
      await runAction({
        environment: { ...actionEnvironment(workspace), INPUT_TARGET: parent },
        stderr: (message) => messages.push(message),
        stdout: () => undefined,
      }),
    ).toBe(2);
    expect(messages.join("")).toContain("inside GITHUB_WORKSPACE");

    expect(
      await quietRun({ ...actionEnvironment(workspace), INPUT_OUTPUT: "../report.json" }),
    ).toBe(2);
    expect(
      await quietRun({ ...actionEnvironment(workspace), INPUT_OUTPUT: path.join(workspace, "x") }),
    ).toBe(2);
    expect(
      await quietRun({
        ...actionEnvironment(workspace),
        INPUT_TARGET: path.join(workspace, "server"),
      }),
    ).toBe(2);
  });

  it("rejects an existing output alias of a scanned target file", async () => {
    const workspace = await workspaceWithFixture("safe-server");
    const target = path.join(workspace, "server", "package.json");
    const output = path.join(workspace, "target-alias.json");
    const original = await readFile(target, "utf8");
    await link(target, output);

    expect(
      await quietRun({
        ...actionEnvironment(workspace),
        INPUT_OUTPUT: "target-alias.json",
        INPUT_TARGET: "server/package.json",
      }),
    ).toBe(2);
    expect(await readFile(target, "utf8")).toBe(original);
  });

  it.each([
    ["artifacts", "artifacts/uleravo.sarif"],
    ["artifacts/uleravo.json", "artifacts"],
  ])("rejects overlapping output topology before creating %s", async (output, sarifOutput) => {
    const workspace = await workspaceWithFixture("safe-server");

    expect(
      await quietRun({
        ...actionEnvironment(workspace),
        INPUT_OUTPUT: output,
        "INPUT_SARIF-OUTPUT": sarifOutput,
      }),
    ).toBe(2);
    await expect(lstat(path.join(workspace, "artifacts"))).rejects.toMatchObject({
      code: "ENOENT",
    });
  });

  it("accepts harmless current-directory segments in output paths", async () => {
    const workspace = await workspaceWithFixture("safe-server");

    expect(
      await quietRun({
        ...actionEnvironment(workspace),
        INPUT_OUTPUT: "./uleravo.json",
        "INPUT_SARIF-OUTPUT": "reports/./uleravo.sarif",
      }),
    ).toBe(0);
  });

  it.runIf(process.platform !== "win32")(
    "rejects an output directory link that leaves the workspace",
    async () => {
      const workspace = await workspaceWithFixture("safe-server");
      const outside = await makeTemporaryDirectory();
      await symlink(outside, path.join(workspace, "escape"), "dir");
      const outsideParent = path.join(outside, "must-not-exist", "nested");

      expect(
        await quietRun({
          ...actionEnvironment(workspace),
          INPUT_OUTPUT: "escape/must-not-exist/nested/report.json",
        }),
      ).toBe(2);
      await expect(lstat(outsideParent)).rejects.toMatchObject({ code: "ENOENT" });
    },
  );

  it("rejects ambiguous or unsafe action inputs", async () => {
    const workspace = await workspaceWithFixture("safe-server");
    const base = actionEnvironment(workspace);
    const invalidEnvironments = [
      { ...base, "INPUT_FAIL-ON": "urgent" },
      { ...base, "INPUT_MAX-FILE-BYTES": "0" },
      { ...base, "INPUT_MAX-FILE-BYTES": "100000001" },
      { ...base, "INPUT_MAX-FILE-BYTES": `${Number.MAX_SAFE_INTEGER.toString()}0` },
      { ...base, INPUT_EXCLUDE: "../outside" },
      { ...base, INPUT_EXCLUDE: "src/\tindex.ts" },
      { ...base, INPUT_OUTPUT: "same.json", "INPUT_SARIF-OUTPUT": "same.json" },
      { ...base, INPUT_OUTPUT: "reports/../same.json" },
      { ...base, INPUT_OUTPUT: "server/package.json." },
      { ...base, INPUT_OUTPUT: "CON.json" },
      { ...base, INPUT_OUTPUT: "reports/data:stream" },
      { ...base, INPUT_OUTPUT: "reports/file?.json" },
      { ...base, INPUT_TARGET: "server/package.json", INPUT_OUTPUT: "server/package.json" },
      { ...base, INPUT_TARGET: "server\nother" },
      { ...base, INPUT_OUTPUT: "x".repeat(4097) },
      { ...base, GITHUB_REPOSITORY: "invalid" },
      { ...base, GITHUB_SHA: "short" },
    ];

    for (const environment of invalidEnvironments) {
      expect(await quietRun(environment)).toBe(2);
    }
  });

  it("works without optional GitHub output and summary files", async () => {
    const workspace = await workspaceWithFixture("safe-server");
    const environment: Record<string, string | undefined> = actionEnvironment(workspace);
    environment.GITHUB_OUTPUT = undefined;
    environment.GITHUB_STEP_SUMMARY = undefined;

    expect(await quietRun(environment)).toBe(0);
  });

  it("does not publish a successful outcome when summary publication fails", async () => {
    const workspace = await workspaceWithFixture("safe-server");
    const environment: Record<string, string> = {
      ...actionEnvironment(workspace),
      GITHUB_STEP_SUMMARY: workspace,
    };

    expect(await quietRun(environment)).toBe(2);
    await expect(readFile(environment.GITHUB_OUTPUT ?? "", "utf8")).rejects.toMatchObject({
      code: "ENOENT",
    });
  });
});

async function quietRun(
  environment: Readonly<Record<string, string | undefined>>,
): Promise<number> {
  return await runAction({
    environment,
    stderr: () => undefined,
    stdout: () => undefined,
  });
}

function actionEnvironment(workspace: string): Record<string, string> {
  return {
    GITHUB_OUTPUT: path.join(workspace, "github-output.txt"),
    GITHUB_REPOSITORY: "Throneee/uleravo",
    GITHUB_SERVER_URL: "https://github.com/",
    GITHUB_SHA: "a".repeat(40),
    GITHUB_STEP_SUMMARY: path.join(workspace, "github-summary.md"),
    GITHUB_WORKSPACE: workspace,
    "INPUT_MAX-FILE-BYTES": "1000000",
    INPUT_OUTPUT: "uleravo.json",
    "INPUT_SARIF-OUTPUT": "uleravo.sarif",
    INPUT_TARGET: "server",
  };
}

async function workspaceWithFixture(name: string): Promise<string> {
  const workspace = await makeTemporaryDirectory();
  await cp(path.join(fixtures, name), path.join(workspace, "server"), { recursive: true });
  return workspace;
}

async function makeTemporaryDirectory(): Promise<string> {
  const directory = await mkdtemp(path.join(tmpdir(), "uleravo-action-test-"));
  temporaryDirectories.push(directory);
  return directory;
}

function parseCommandFile(serialized: string): Record<string, string> {
  const result: Record<string, string> = {};
  const lines = serialized.split("\n");
  for (let index = 0; index < lines.length; index += 1) {
    const header = lines[index] ?? "";
    const separator = header.indexOf("<<");
    if (separator < 1) {
      continue;
    }
    const name = header.slice(0, separator);
    const delimiter = header.slice(separator + 2);
    const values: string[] = [];
    index += 1;
    while (index < lines.length && lines[index] !== delimiter) {
      values.push(lines[index] ?? "");
      index += 1;
    }
    result[name] = values.join("\n");
  }
  return result;
}
