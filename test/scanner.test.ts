import { mkdir, mkdtemp, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import { formatText } from "../src/formatters/text.js";
import {
  sameOpenedFileSnapshot,
  samePathAndOpenedFileSnapshot,
  targetDisplayName,
} from "../src/scanner/files.js";
import { scan } from "../src/scanner/scan.js";

const fixtureRoot = fileURLToPath(new URL("./fixtures", import.meta.url));
const temporaryDirectories: string[] = [];

const openedFileSnapshot = {
  ctimeMs: 300,
  dev: 9,
  ino: 42,
  mtimeMs: 200,
  size: 100,
};

afterEach(async () => {
  const { rm } = await import("node:fs/promises");
  await Promise.all(
    temporaryDirectories
      .splice(0)
      .map((directory) => rm(directory, { force: true, recursive: true })),
  );
});

describe("scan", () => {
  it("accepts only the observed Windows path-to-opened-file device mismatch", () => {
    const windowsPathSnapshot = { ...openedFileSnapshot, dev: 0 };

    expect(samePathAndOpenedFileSnapshot(windowsPathSnapshot, openedFileSnapshot, "win32")).toBe(
      true,
    );
    expect(samePathAndOpenedFileSnapshot(windowsPathSnapshot, openedFileSnapshot, "linux")).toBe(
      false,
    );
    expect(samePathAndOpenedFileSnapshot(openedFileSnapshot, windowsPathSnapshot, "win32")).toBe(
      false,
    );
    expect(
      samePathAndOpenedFileSnapshot(
        { ...windowsPathSnapshot, ino: 0 },
        { ...openedFileSnapshot, ino: 0 },
        "win32",
      ),
    ).toBe(false);
    expect(
      samePathAndOpenedFileSnapshot(
        { ...windowsPathSnapshot, dev: 8 },
        openedFileSnapshot,
        "win32",
      ),
    ).toBe(false);
  });

  it.each(["ino", "size", "mtimeMs", "ctimeMs"] as const)(
    "rejects a replaced or changed Windows path when %s differs",
    (field) => {
      const windowsPathSnapshot = {
        ...openedFileSnapshot,
        dev: 0,
        [field]: openedFileSnapshot[field] + 1,
      };

      expect(samePathAndOpenedFileSnapshot(windowsPathSnapshot, openedFileSnapshot, "win32")).toBe(
        false,
      );
    },
  );

  it.each(["dev", "ino", "size", "mtimeMs", "ctimeMs"] as const)(
    "keeps opened-handle snapshot comparisons strict when %s differs",
    (field) => {
      const changedSnapshot = {
        ...openedFileSnapshot,
        [field]: openedFileSnapshot[field] + 1,
      };

      expect(sameOpenedFileSnapshot(openedFileSnapshot, changedSnapshot)).toBe(false);
    },
  );

  it("uses a non-empty display name for filesystem roots", () => {
    expect(targetDisplayName(path.parse(path.resolve(".")).root)).toBe(
      path.parse(path.resolve(".")).root,
    );
  });

  it.each([
    ["maxFileBytes", { maxFileBytes: Number.NaN }],
    ["maxFiles", { maxFiles: Number.POSITIVE_INFINITY }],
    ["maxTotalBytes", { maxTotalBytes: 100_000_001 }],
  ] as const)("rejects an unsafe %s library limit", async (name, options) => {
    await expect(scan(path.join(fixtureRoot, "safe-server"), options)).rejects.toThrow(name);
  });

  it.each(["server.ts", "server.py"])(
    "fails closed when %s is an unresolved Git LFS pointer",
    async (fileName) => {
      const directory = await makeTemporaryDirectory();
      await writeFile(path.join(directory, "safe.ts"), "export const safe = true;\n");
      await writeFile(
        path.join(directory, fileName),
        [
          "version https://git-lfs.github.com/spec/v1",
          `oid sha256:${"a".repeat(64)}`,
          "size 12345",
          "",
        ].join("\n"),
      );

      const report = await scan(directory);

      expect(report.scan.filesScanned).toBe(1);
      expect(report.scan.filesSkipped).toBe(1);
      expect(report.diagnostics).toEqual([
        expect.objectContaining({
          file: fileName,
          message: expect.stringContaining("unresolved Git LFS pointer"),
          type: "error",
        }),
      ]);
    },
  );

  it("does not treat an unresolved LFS bun.lockb pointer as a hashed lockfile", async () => {
    const directory = await makeTemporaryDirectory();
    await writeFile(
      path.join(directory, "package.json"),
      JSON.stringify({ dependencies: { "example-mcp-server": "latest" } }),
    );
    await writeFile(
      path.join(directory, "bun.lockb"),
      [
        "version https://git-lfs.github.com/spec/v1",
        `oid sha256:${"b".repeat(64)}`,
        "size 12345",
        "",
      ].join("\n"),
    );

    const report = await scan(directory);

    expect(report.provenance?.lockfiles).toEqual([]);
    expect(report.diagnostics).toEqual([
      expect.objectContaining({
        file: "bun.lockb",
        message: expect.stringContaining("unresolved Git LFS pointer"),
        type: "error",
      }),
    ]);
    expect(report.findings).toContainEqual(
      expect.objectContaining({ file: "package.json", ruleId: "MCP010" }),
    );
  });

  it("does not mistake source containing the LFS version URL for a pointer", async () => {
    const directory = await makeTemporaryDirectory();
    await writeFile(
      path.join(directory, "server.ts"),
      [
        'const documentation = "version https://git-lfs.github.com/spec/v1";',
        "export { documentation };",
      ].join("\n"),
    );

    const report = await scan(directory);

    expect(report.scan.filesScanned).toBe(1);
    expect(report.diagnostics).toEqual([]);
  });

  it("fails closed only for declared submodules that are absent or unmaterialized", async () => {
    const directory = await makeTemporaryDirectory();
    await mkdir(path.join(directory, "empty-module"));
    await mkdir(path.join(directory, "materialized module"));
    await writeFile(
      path.join(directory, "materialized module", "server.ts"),
      "export const ready = true;\n",
    );
    await writeFile(
      path.join(directory, ".gitmodules"),
      [
        '[submodule "missing"]',
        "  path = missing-module",
        "  url = https://example.invalid/missing.git",
        '[submodule "empty"]',
        "  path = empty-module",
        "  url = https://example.invalid/empty.git",
        '[submodule "materialized"]',
        '  path = "materialized module"',
        "  url = https://example.invalid/materialized.git",
        "",
      ].join("\n"),
    );

    const report = await scan(directory);

    expect(report.diagnostics).toHaveLength(2);
    expect(new Set(report.diagnostics.map((diagnostic) => diagnostic.file))).toEqual(
      new Set(["empty-module", "missing-module"]),
    );
    expect(
      report.diagnostics.every(
        (diagnostic) =>
          diagnostic.type === "error" && diagnostic.message.includes("absent or unmaterialized"),
      ),
    ).toBe(true);
    expect(report.findings).toEqual([]);
  });

  it("validates declarations when the selected target is a .gitmodules file", async () => {
    const directory = await makeTemporaryDirectory();
    const manifest = path.join(directory, ".gitmodules");
    await writeFile(
      manifest,
      '[submodule "missing"]\n  path = missing-module\n  url = https://example.invalid/missing.git\n',
    );

    const report = await scan(manifest);

    expect(report.diagnostics).toEqual([
      expect.objectContaining({
        file: "missing-module",
        message: expect.stringContaining("absent or unmaterialized"),
        type: "error",
      }),
    ]);
  });

  it("bounds declared submodule validation by the configured file cap", async () => {
    const directory = await makeTemporaryDirectory();
    await writeFile(
      path.join(directory, ".gitmodules"),
      Array.from(
        { length: 3 },
        (_, index) =>
          `[submodule "module-${index.toString()}"]\n  path = module-${index.toString()}\n`,
      ).join(""),
    );

    const report = await scan(directory, { maxFiles: 2 });

    expect(report.diagnostics).toEqual([
      expect.objectContaining({
        file: ".gitmodules",
        message: expect.stringContaining("Declared submodule limit exceeded (2 paths)"),
        type: "error",
      }),
    ]);
  });

  it("fails closed without resolving an unsafe declared submodule path", async () => {
    const directory = await makeTemporaryDirectory();
    await writeFile(path.join(directory, "safe.ts"), "export const safe = true;\n");
    await writeFile(
      path.join(directory, ".gitmodules"),
      '[submodule "outside"]\n  path = ../outside\n  url = https://example.invalid/outside.git\n',
    );

    const report = await scan(directory);

    expect(report.diagnostics).toEqual([
      expect.objectContaining({
        file: ".gitmodules",
        message: expect.stringContaining("path is invalid or leaves the scan root"),
        type: "error",
      }),
    ]);
  });

  it("fails closed on unsupported continued submodule path syntax", async () => {
    const directory = await makeTemporaryDirectory();
    await writeFile(path.join(directory, "safe.ts"), "export const safe = true;\n");
    await writeFile(
      path.join(directory, ".gitmodules"),
      [
        '[submodule "continued"]',
        "  path = missing-\\",
        "module",
        "  url = https://example.invalid/missing.git",
        "",
      ].join("\n"),
    );

    const report = await scan(directory);

    expect(report.diagnostics).toEqual([
      expect.objectContaining({
        file: ".gitmodules",
        message: expect.stringContaining("unsupported or invalid syntax"),
        type: "error",
      }),
    ]);
  });

  it("fails closed on a bare submodule path key", async () => {
    const directory = await makeTemporaryDirectory();
    await writeFile(path.join(directory, "safe.ts"), "export const safe = true;\n");
    await writeFile(
      path.join(directory, ".gitmodules"),
      '[submodule "bare"]\n  path\n  url = https://example.invalid/missing.git\n',
    );

    const report = await scan(directory);

    expect(report.diagnostics).toEqual([
      expect.objectContaining({
        file: ".gitmodules",
        message: expect.stringContaining("unsupported or invalid syntax"),
        type: "error",
      }),
    ]);
  });

  it.each([
    ["at end of file", '[submodule "missing"]\n  url = https://example.invalid/missing.git\n'],
    [
      "before the next section",
      [
        '[submodule "missing"]',
        "  url = https://example.invalid/missing.git",
        '[submodule "materialized"]',
        "  path = materialized",
        "  url = https://example.invalid/materialized.git",
        "",
      ].join("\n"),
    ],
  ])("fails closed when a submodule path is missing %s", async (_case, manifest) => {
    const directory = await makeTemporaryDirectory();
    await mkdir(path.join(directory, "materialized"));
    await writeFile(path.join(directory, "materialized", "server.ts"), "export {};\n");
    await writeFile(path.join(directory, "safe.ts"), "export const safe = true;\n");
    await writeFile(path.join(directory, ".gitmodules"), manifest);

    const report = await scan(directory);

    expect(report.diagnostics).toEqual([
      expect.objectContaining({
        file: ".gitmodules",
        message: expect.stringContaining("unsupported or invalid syntax"),
        type: "error",
      }),
    ]);
  });

  it.each([
    [
      "within one section",
      ['[submodule "duplicate-key"]', "  path = first", "  path = second", ""].join("\n"),
    ],
    [
      "across two sections",
      [
        '[submodule "first"]',
        "  path = shared",
        '[submodule "second"]',
        "  path = shared",
        "",
      ].join("\n"),
    ],
  ])("fails closed for a duplicate submodule path %s", async (_case, manifest) => {
    const directory = await makeTemporaryDirectory();
    await mkdir(path.join(directory, "first"));
    await mkdir(path.join(directory, "second"));
    await mkdir(path.join(directory, "shared"));
    await writeFile(path.join(directory, "first", "server.ts"), "export {};\n");
    await writeFile(path.join(directory, "second", "server.ts"), "export {};\n");
    await writeFile(path.join(directory, "shared", "server.ts"), "export {};\n");
    await writeFile(path.join(directory, "safe.ts"), "export const safe = true;\n");
    await writeFile(path.join(directory, ".gitmodules"), manifest);

    const report = await scan(directory);

    expect(report.diagnostics).toEqual([
      expect.objectContaining({
        file: ".gitmodules",
        message: expect.stringContaining("unsupported or invalid syntax"),
        type: "error",
      }),
    ]);
  });

  it("rejects a Windows drive-relative declared submodule path on every platform", async () => {
    const directory = await makeTemporaryDirectory();
    await writeFile(path.join(directory, "safe.ts"), "export const safe = true;\n");
    await writeFile(
      path.join(directory, ".gitmodules"),
      '[submodule "drive-relative"]\n  path = D:module\n  url = https://example.invalid/module.git\n',
    );

    const report = await scan(directory);

    expect(report.diagnostics).toEqual([
      expect.objectContaining({
        file: ".gitmodules",
        message: expect.stringContaining("path is invalid or leaves the scan root"),
        type: "error",
      }),
    ]);
  });

  it("finds the high-signal vulnerability classes in an unsafe MCP server", async () => {
    const report = await scan(path.join(fixtureRoot, "vulnerable-server"));
    const ruleIds = new Set(report.findings.map((finding) => finding.ruleId));

    expect(ruleIds).toEqual(
      new Set([
        "MCP001",
        "MCP002",
        "MCP003",
        "MCP004",
        "MCP005",
        "MCP006",
        "MCP007",
        "MCP008",
        "MCP009",
        "MCP010",
        "MCP011",
        "MCP012",
      ]),
    );
    expect(report.summary.critical).toBeGreaterThanOrEqual(2);
    expect(report.summary.total).toBe(report.findings.length);
    expect(report.diagnostics).toEqual([]);
  });

  it("recognizes separated and camel-case destructive tool names", async () => {
    const directory = await makeTemporaryDirectory();
    await writeFile(
      path.join(directory, "metadata.ts"),
      [
        "declare const server: { tool: (...args: unknown[]) => void };",
        'server.tool("deleteFile", {}, async () => undefined);',
        'server.tool("RemoveUser", {}, async () => undefined);',
        'server.tool("remover", {}, async () => undefined);',
        'server.tool("wipe-cache", { annotations: { destructiveHint: true } }, async () => undefined);',
      ].join("\n"),
    );

    const report = await scan(directory);
    const destructiveFindings = report.findings.filter((finding) => finding.ruleId === "MCP012");

    expect(destructiveFindings).toHaveLength(2);
    expect(destructiveFindings.map((finding) => finding.message)).toEqual([
      expect.stringContaining("deleteFile"),
      expect.stringContaining("RemoveUser"),
    ]);
  });

  it("tracks handler input through aliased direct relative imports into exported command helpers", async () => {
    const report = await scan(path.join(fixtureRoot, "interfile-vulnerable-server"));

    expect(report.diagnostics).toEqual([]);
    expect(report.findings).toHaveLength(2);
    expect(new Set(report.findings.map((finding) => finding.ruleId))).toEqual(new Set(["MCP001"]));
    expect(new Set(report.findings.map((finding) => finding.file))).toEqual(new Set(["logic.ts"]));
    expect(report.findings.map((finding) => finding.evidence).join("\n")).toContain(
      "exec(command)",
    );
    expect(report.findings.map((finding) => finding.evidence).join("\n")).toContain("execSync(");
  });

  it("keeps fixed executable calls guarded across direct relative imports", async () => {
    const report = await scan(path.join(fixtureRoot, "interfile-safe-server"));

    expect(report.diagnostics).toEqual([]);
    expect(report.findings).toEqual([]);
  });

  it("does not cross package, ambiguous, or two-hop imported call boundaries", async () => {
    const directory = await makeTemporaryDirectory();
    await writeFile(
      path.join(directory, "registration.ts"),
      [
        'import { runCommand as importedRunCommand } from "./logic.js";',
        'import { packageCommand } from "example-package";',
        'import { delegate } from "./middle.js";',
        "",
        "declare const server: { tool: (...args: unknown[]) => void };",
        "",
        'server.tool("bounded", {}, async ({ command }) => {',
        "  importedRunCommand(command);",
        "  packageCommand(command);",
        "  delegate(command);",
        "});",
      ].join("\n"),
    );
    await writeFile(
      path.join(directory, "middle.ts"),
      [
        'import { runCommand } from "./logic.js";',
        "",
        "export function delegate(command: string): void {",
        "  runCommand(command);",
        "}",
      ].join("\n"),
    );
    for (const fileName of ["logic.js", "logic.ts"]) {
      await writeFile(
        path.join(directory, fileName),
        [
          'import { exec } from "node:child_process";',
          "",
          "export function runCommand(command: string): void {",
          "  exec(command);",
          "}",
        ].join("\n"),
      );
    }

    const report = await scan(directory);

    expect(report.diagnostics).toEqual([]);
    expect(report.findings).toEqual([]);
  });

  it("resolves import shadowing against each call's lexical scope", async () => {
    const directory = await makeTemporaryDirectory();
    await writeFile(
      path.join(directory, "registration.ts"),
      [
        'import { runCommand } from "./logic.js";',
        "",
        "declare const server: { tool: (...args: unknown[]) => void };",
        "declare const items: string[];",
        "",
        'server.tool("outer", {}, async ({ command }) => {',
        "  items.map((runCommand) => runCommand.toUpperCase());",
        "  runCommand(command);",
        "});",
        "",
        'server.tool("shadowed", {}, async ({ command }, runCommand) => {',
        "  runCommand(command);",
        "});",
      ].join("\n"),
    );
    await writeFile(
      path.join(directory, "logic.ts"),
      [
        'import { exec } from "node:child_process";',
        "",
        "export function runCommand(command: string): void {",
        "  exec(command);",
        "}",
      ].join("\n"),
    );

    const report = await scan(directory);

    expect(report.diagnostics).toEqual([]);
    expect(report.findings).toHaveLength(1);
    expect(report.findings[0]).toEqual(
      expect.objectContaining({
        file: "logic.ts",
        ruleId: "MCP001",
      }),
    );
  });

  it("fails the repository rule closed at 1,000 unique imported call states", async () => {
    const directory = await makeTemporaryDirectory();
    const helperNames = Array.from({ length: 1_001 }, (_, index) => `helper${index.toString()}`);
    await writeFile(
      path.join(directory, "registration.ts"),
      [
        `import { ${helperNames.join(", ")} } from "./logic.js";`,
        "",
        "declare const server: { tool: (...args: unknown[]) => void };",
        "",
        'server.tool("bounded", {}, async ({ command }) => {',
        ...helperNames.map((name) => `  ${name}(command);`),
        "});",
      ].join("\n"),
    );
    await writeFile(path.join(directory, "logic.ts"), "export {};\n");

    const report = await scan(directory);

    expect(report.findings).toEqual([]);
    expect(report.diagnostics).toHaveLength(1);
    expect(report.diagnostics[0]).toEqual(
      expect.objectContaining({
        message: expect.stringContaining(
          "Direct imported-call analysis exceeded 1000 unique call states.",
        ),
        type: "error",
      }),
    );
  });

  it("retains command taint after basename while treating the value as filesystem-safe", async () => {
    const directory = await makeTemporaryDirectory();
    await writeFile(
      path.join(directory, "server.ts"),
      [
        'import { exec } from "node:child_process";',
        'import { readFile } from "node:fs/promises";',
        'import { basename } from "node:path";',
        "",
        "declare const server: { tool: (...args: unknown[]) => void };",
        "",
        'server.tool("basename-command", {}, async ({ command }) => {',
        "  const safeName = basename(command);",
        "  exec(safeName);",
        "  await readFile(safeName);",
        "});",
      ].join("\n"),
    );

    const report = await scan(directory);

    expect(report.diagnostics).toEqual([]);
    expect(report.findings).toHaveLength(1);
    expect(report.findings[0]).toEqual(
      expect.objectContaining({
        file: "server.ts",
        ruleId: "MCP001",
      }),
    );
    expect(report.findings[0]?.evidence).toContain("exec(safeName)");
  });

  it("limits shell-mode taint to the command and argument vector", async () => {
    const directory = await makeTemporaryDirectory();
    await writeFile(
      path.join(directory, "server.ts"),
      [
        'import { spawn } from "node:child_process";',
        "declare const server: { tool: (...args: unknown[]) => void };",
        'server.tool("launch", {}, async ({ argument, directory }) => {',
        '  spawn("echo", [argument], { shell: true });',
        '  spawn("echo", ["fixed"], { cwd: directory, shell: true });',
        "});",
      ].join("\n"),
    );
    await writeFile(
      path.join(directory, "server.py"),
      [
        "from mcp.server.fastmcp import FastMCP",
        "import subprocess",
        "mcp = FastMCP('fixture')",
        "@mcp.tool()",
        "def launch(argument: str, directory: str):",
        "    subprocess.run(['echo', argument], shell=True)",
        "    subprocess.run(['echo', 'fixed'], cwd=directory, shell=True)",
      ].join("\n"),
    );

    const report = await scan(directory);
    const shellFindings = report.findings.filter((finding) => finding.ruleId === "MCP001");

    expect(shellFindings).toHaveLength(2);
    expect(new Set(shellFindings.map((finding) => finding.file))).toEqual(
      new Set(["server.py", "server.ts"]),
    );
  });

  it("invalidates a basename-safe path after unsafe mutation", async () => {
    const directory = await makeTemporaryDirectory();
    await writeFile(
      path.join(directory, "server.ts"),
      [
        'import { readFile } from "node:fs/promises";',
        'import { basename } from "node:path";',
        "",
        "declare const server: { tool: (...args: unknown[]) => void };",
        "",
        'server.tool("mutated-path", {}, async ({ requestedPath, suffix }) => {',
        "  let safeName = basename(requestedPath);",
        "  safeName += suffix;",
        "  await readFile(safeName);",
        "});",
      ].join("\n"),
    );

    const report = await scan(directory);

    expect(report.diagnostics).toEqual([]);
    expect(report.findings).toHaveLength(1);
    expect(report.findings[0]).toEqual(
      expect.objectContaining({
        file: "server.ts",
        ruleId: "MCP003",
      }),
    );
  });

  it("checks both source and destination path positions for rename", async () => {
    const directory = await makeTemporaryDirectory();
    await writeFile(
      path.join(directory, "server.ts"),
      [
        'import { rename } from "node:fs/promises";',
        "declare const server: { tool: (...args: unknown[]) => void };",
        'server.tool("rename", {}, async ({ destination }) => {',
        '  await rename("/srv/app/fixed.txt", destination);',
        "});",
      ].join("\n"),
    );

    const report = await scan(directory);

    expect(report.diagnostics).toEqual([]);
    expect(report.findings).toEqual([
      expect.objectContaining({ file: "server.ts", ruleId: "MCP003" }),
    ]);
  });

  it("preserves a basename guard across one direct relative import", async () => {
    const directory = await makeTemporaryDirectory();
    await writeFile(
      path.join(directory, "registration.ts"),
      [
        'import { basename } from "node:path";',
        'import { readRequestedFile } from "./logic.js";',
        "",
        "declare const server: { tool: (...args: unknown[]) => void };",
        "",
        'server.tool("read", {}, async ({ requestedPath }) => {',
        "  await readRequestedFile(basename(requestedPath));",
        "});",
      ].join("\n"),
    );
    await writeFile(
      path.join(directory, "logic.ts"),
      [
        'import { readFile } from "node:fs/promises";',
        "",
        "export async function readRequestedFile(requestedPath: string): Promise<void> {",
        "  await readFile(requestedPath);",
        "}",
      ].join("\n"),
    );

    const report = await scan(directory);

    expect(report.diagnostics).toEqual([]);
    expect(report.findings).toEqual([]);
  });

  it("invalidates an imported basename guard after unsafe mutation", async () => {
    const directory = await makeTemporaryDirectory();
    await writeFile(
      path.join(directory, "registration.ts"),
      [
        'import { basename } from "node:path";',
        'import { readRequestedFile } from "./logic.js";',
        "",
        "declare const server: { tool: (...args: unknown[]) => void };",
        "",
        'server.tool("read", {}, async ({ requestedPath, suffix }) => {',
        "  await readRequestedFile(basename(requestedPath), suffix);",
        "});",
      ].join("\n"),
    );
    await writeFile(
      path.join(directory, "logic.ts"),
      [
        'import { readFile } from "node:fs/promises";',
        "",
        "export async function readRequestedFile(",
        "  requestedPath: string,",
        "  suffix: string,",
        "): Promise<void> {",
        "  requestedPath += suffix;",
        "  await readFile(requestedPath);",
        "}",
      ].join("\n"),
    );

    const report = await scan(directory);

    expect(report.diagnostics).toEqual([]);
    expect(report.findings).toHaveLength(1);
    expect(report.findings[0]).toEqual(
      expect.objectContaining({
        file: "logic.ts",
        ruleId: "MCP003",
      }),
    );
  });

  it("keeps secrets out of evidence and serialized reports", async () => {
    const report = await scan(path.join(fixtureRoot, "vulnerable-server"));
    const serialized = JSON.stringify(report);

    expect(serialized).not.toContain("A8kF2mQ9vR4xT7zP1cN6jH3w");
    expect(serialized).not.toContain("super-secret-value");
    expect(serialized).toContain("<redacted>");
  });

  it("keeps credentials in mutable package references out of finding messages", async () => {
    const directory = await makeTemporaryDirectory();
    const password = "CredentialValue123";
    await writeFile(
      path.join(directory, "mcp.json"),
      JSON.stringify({
        mcpServers: {
          remote: {
            args: [`https://user:${password}@packages.example/server`],
            command: "npx",
          },
        },
      }),
    );

    const report = await scan(directory);
    const packageFinding = report.findings.find((finding) => finding.ruleId === "MCP010");
    const serialized = JSON.stringify(report);

    expect(packageFinding?.message).toContain("redacted");
    expect(serialized).not.toContain(password);
  });

  it.each(["tools/npx", "tools\\npx"])(
    "recognizes portable MCP package-runner path %s",
    async (command) => {
      const directory = await makeTemporaryDirectory();
      await writeFile(
        path.join(directory, "mcp.json"),
        JSON.stringify({
          mcpServers: { example: { args: ["example-mcp-server@latest"], command } },
        }),
      );

      const report = await scan(directory);

      expect(report.findings).toContainEqual(expect.objectContaining({ ruleId: "MCP010" }));
    },
  );

  it("recognizes an exact uvx requirement while retaining mutable-range detection", async () => {
    const directory = await makeTemporaryDirectory();
    await writeFile(
      path.join(directory, "mcp.json"),
      JSON.stringify({
        mcpServers: {
          exact: { args: ["example-mcp-server==1.2.3"], command: "uvx" },
          mutable: { args: ["example-mcp-server>=1.2"], command: "uvx" },
        },
      }),
    );

    const report = await scan(directory);
    const packageFindings = report.findings.filter((finding) => finding.ruleId === "MCP010");

    expect(packageFindings).toHaveLength(1);
    expect(packageFindings[0]?.message).toContain("mutable");
    expect(packageFindings[0]?.evidence).toContain("example-mcp-server>=1.2");
  });

  it("redacts long credential ranges before evidence truncation", async () => {
    const directory = await makeTemporaryDirectory();
    const longSecret = "Aa0!Bb1@Cc2#Dd3$Ee4%".repeat(16);
    const secretPrefix = longSecret.slice(0, 32);
    await writeFile(path.join(directory, "long-secret.ts"), `const apiKey = "${longSecret}";`);
    await writeFile(
      path.join(directory, "guarded-secret.ts"),
      "const apiKey = process.env.SERVICE_API_KEY;",
    );

    const report = await scan(directory);
    const secretFindings = report.findings.filter((finding) => finding.ruleId === "MCP007");
    const evidence = secretFindings[0]?.evidence ?? "";
    const serialized = JSON.stringify(report);

    expect(secretFindings.length === 1).toBe(true);
    expect(secretFindings.every((finding) => finding.file === "long-secret.ts")).toBe(true);
    expect(evidence.includes("<redacted>")).toBe(true);
    expect(evidence.includes(secretPrefix)).toBe(false);
    expect(serialized.includes(secretPrefix)).toBe(false);
  });

  it("redacts unquoted credentials from unrelated rule evidence", async () => {
    const directory = await makeTemporaryDirectory();
    const credential = ["Aa0!", "Bb1@", "Cc2;", "Dd3$", "Ee4%"].join("");
    const prefixMarker = credential.slice(0, 12);
    const suffixMarker = credential.slice(-8);
    await writeFile(
      path.join(directory, ".env.runtime"),
      `SERVICE_API_KEY=${credential} DUPLICATE=${credential} http://example.com`,
    );

    const report = await scan(directory);
    const transportFindings = report.findings.filter((finding) => finding.ruleId === "MCP008");
    const serialized = JSON.stringify(report);

    expect(transportFindings.length).toBe(1);
    expect(transportFindings[0]?.evidence.includes("<redacted>")).toBe(true);
    expect(transportFindings[0]?.evidence.includes(prefixMarker)).toBe(false);
    expect(transportFindings[0]?.evidence.includes(suffixMarker)).toBe(false);
    expect(serialized.includes(prefixMarker)).toBe(false);
    expect(serialized.includes(suffixMarker)).toBe(false);
  });

  it("redacts complete inline private keys from all finding evidence", async () => {
    const directory = await makeTemporaryDirectory();
    const keyBody = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcw";
    const privateKey = `-----BEGIN PRIVATE KEY-----\\n${keyBody}\\n-----END PRIVATE KEY-----`;
    await writeFile(
      path.join(directory, "credentials.ts"),
      `const key = "${privateKey}"; const endpoint = "http://example.com";`,
    );

    const report = await scan(directory);
    const serialized = JSON.stringify(report);
    const keyFinding = report.findings.find((finding) => finding.ruleId === "MCP007");

    expect(keyFinding?.evidence).toContain("<redacted>");
    expect(serialized).not.toContain(keyBody);
    expect(serialized).not.toContain("BEGIN PRIVATE KEY");
  });

  it("redacts every finding line inside a multiline private-key block", async () => {
    const directory = await makeTemporaryDirectory();
    const keyBody = "PrivateBodyMarkerThatMustNeverAppear";
    const embeddedToken = ["ghp_", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"].join("");
    await writeFile(
      path.join(directory, "credentials.yaml"),
      [
        "-----BEGIN PRIVATE KEY-----",
        keyBody,
        "Comment: http://inside-key.example/path",
        embeddedToken,
        "-----END PRIVATE KEY-----",
      ].join("\n"),
    );

    const report = await scan(directory);
    const serialized = JSON.stringify(report);

    expect(report.findings).toContainEqual(expect.objectContaining({ ruleId: "MCP008" }));
    expect(report.findings.filter((finding) => finding.ruleId === "MCP007")).toHaveLength(1);
    expect(serialized).not.toContain(keyBody);
    expect(serialized).not.toContain(embeddedToken);
    expect(serialized).not.toContain("inside-key.example");
  });

  it("centers bounded evidence on findings in long source lines", async () => {
    const directory = await makeTemporaryDirectory();
    const padding = "x".repeat(400);
    await writeFile(
      path.join(directory, "minified.ts"),
      `import { exec } from "node:child_process"; declare const server: { tool: (...args: unknown[]) => void }; server.tool("run", {}, async ({ command }) => { const padding = "${padding}"; exec(command); });`,
    );

    const report = await scan(directory);
    const commandFinding = report.findings.find((finding) => finding.ruleId === "MCP001");

    expect(commandFinding?.evidence).toContain("exec(command)");
    expect(commandFinding?.evidence.startsWith("…")).toBe(true);
    expect(commandFinding?.evidence.length).toBeLessThanOrEqual(240);
  });

  it("redacts a complete long line before centering unrelated finding evidence", async () => {
    const directory = await makeTemporaryDirectory();
    const secret = ["Q7vN", "4mZp", "8xLs", "2kRw"].join("").repeat(12);
    const secretTail = secret.slice(-32);
    await writeFile(
      path.join(directory, "minified-secret.ts"),
      `import { exec } from "node:child_process"; server.tool("run", {}, ({ command }) => { const apiKey = "${secret}"; exec(command); });`,
    );

    const report = await scan(directory);
    const commandFinding = report.findings.find((finding) => finding.ruleId === "MCP001");
    const serialized = JSON.stringify(report);

    expect(commandFinding?.evidence).toContain("exec(command)");
    expect(commandFinding?.evidence).toContain("<redacted>");
    expect(commandFinding?.evidence.includes(secretTail)).toBe(false);
    expect(serialized.includes(secretTail)).toBe(false);
  });

  it("fails closed when one file exhausts the evidence-work budget", async () => {
    const directory = await makeTemporaryDirectory();
    const minified = Array.from(
      { length: 200 },
      (_, index) => `const endpoint${index.toString()}="http://host${index.toString()}.example";`,
    ).join("");
    await writeFile(path.join(directory, "many-findings.ts"), minified);

    const report = await scan(directory);

    expect(report.diagnostics).toContainEqual(
      expect.objectContaining({
        file: "many-findings.ts",
        message: expect.stringContaining("Per-file evidence limit exceeded"),
        type: "error",
      }),
    );
  });

  it("redacts credential-shaped target and artifact metadata in live reports", async () => {
    const directory = await makeTemporaryDirectory();
    const credential = ["gh", "p_", "A".repeat(36)].join("");
    const target = path.join(directory, credential);
    await mkdir(target);
    await mkdir(path.join(target, credential));
    await writeFile(
      path.join(target, `${credential}.ts`),
      'const endpoint = "http://example.com";\n',
    );
    await writeFile(path.join(target, `${credential}.py`), new Uint8Array([0xff]));
    await writeFile(path.join(target, credential, "pnpm-lock.yaml"), "lockfileVersion: '9.0'\n");
    await writeFile(
      path.join(target, "package.json"),
      JSON.stringify({ name: credential, version: credential }),
    );

    const report = await scan(target);
    const serialized = JSON.stringify(report);

    expect(report.scan.target).toContain("<redacted>");
    expect(report.findings.some((finding) => finding.file.includes("<redacted>"))).toBe(true);
    expect(report.diagnostics.some((diagnostic) => diagnostic.file?.includes("<redacted>"))).toBe(
      true,
    );
    expect(report.provenance?.lockfiles[0]?.path).toContain("<redacted>");
    expect(report.provenance?.package).toEqual({ name: "<redacted>", version: "<redacted>" });
    expect(serialized.includes(credential)).toBe(false);
  });

  it.skipIf(process.platform === "win32")(
    "escapes terminal controls in outward artifact paths",
    async () => {
      const directory = await makeTemporaryDirectory();
      const controlledName = "unsafe\n::warning::spoof\u001b[31m.ts";
      const diagnosticName = "broken\u2028\u202e.py";
      await writeFile(
        path.join(directory, controlledName),
        'const endpoint = "http://example.com";',
      );
      await writeFile(path.join(directory, diagnosticName), new Uint8Array([0xff]));

      const report = await scan(directory);
      const rendered = formatText(report);
      const serialized = JSON.stringify(report);

      expect(report.findings[0]?.file).toContain("[U+000A]");
      expect(report.findings[0]?.file).toContain("[U+001B]");
      expect(report.diagnostics[0]?.file).toContain("[U+2028]");
      expect(report.diagnostics[0]?.file).toContain("[U+202E]");
      expect(rendered.includes("\n::warning::spoof")).toBe(false);
      expect(rendered.includes("\u001b")).toBe(false);
      expect(serialized.includes("\u202e")).toBe(false);
      expect(serialized.includes("\u2028")).toBe(false);
    },
  );

  it.skipIf(process.platform === "win32")(
    "does not reinterpret literal POSIX backslashes as test-directory separators",
    async () => {
      const directory = await makeTemporaryDirectory();
      await writeFile(
        path.join(directory, "test\\server.ts"),
        'const endpoint = "http://example.com";\n',
      );

      const report = await scan(directory);

      expect(report.findings).toContainEqual(
        expect.objectContaining({ file: "test\\server.ts", ruleId: "MCP008" }),
      );
    },
  );

  it("does not let a sibling lockfile suppress mutable package findings", async () => {
    const directory = await makeTemporaryDirectory();
    await mkdir(path.join(directory, "app"));
    await mkdir(path.join(directory, "other"));
    await writeFile(
      path.join(directory, "app", "package.json"),
      JSON.stringify({ dependencies: { "example-mcp-server": "latest" } }),
    );
    await writeFile(path.join(directory, "other", "pnpm-lock.yaml"), "lockfileVersion: '9.0'\n");

    const exposed = await scan(directory);
    expect(exposed.findings).toContainEqual(
      expect.objectContaining({ file: "app/package.json", ruleId: "MCP010" }),
    );

    await writeFile(path.join(directory, "pnpm-lock.yaml"), "lockfileVersion: '9.0'\n");
    const guarded = await scan(directory);
    expect(guarded.findings.map((finding) => finding.ruleId)).not.toContain("MCP010");
  });

  it("does not report the guarded equivalents", async () => {
    const report = await scan(path.join(fixtureRoot, "safe-server"));

    expect(report.findings).toEqual([]);
    expect(report.summary.total).toBe(0);
  });

  it("generates stable scan IDs and finding fingerprints", async () => {
    const target = path.join(fixtureRoot, "vulnerable-server");
    const first = await scan(target);
    const second = await scan(target);

    expect(first.scan.id).toBe(second.scan.id);
    expect(first.findings.map((finding) => finding.fingerprint)).toEqual(
      second.findings.map((finding) => finding.fingerprint),
    );
  });

  it("skips symlinks and explicit exclusions", async () => {
    const directory = await makeTemporaryDirectory();
    await mkdir(path.join(directory, "excluded"));
    await writeFile(
      path.join(directory, "excluded", "unsafe.ts"),
      'const key = "sk-proj-abcdefghijklmnopqrstuvwxyz";',
    );
    await symlink(
      path.join(fixtureRoot, "vulnerable-server"),
      path.join(directory, "linked-server"),
      process.platform === "win32" ? "junction" : "dir",
    );

    const report = await scan(directory, { excludePrefixes: ["excluded"] });

    expect(report.findings).toEqual([]);
    expect(report.scan.filesSkipped).toBeGreaterThanOrEqual(2);
    expect(
      report.diagnostics.some((diagnostic) => diagnostic.message.includes("symbolic link")),
    ).toBe(true);
  });

  it("warns on invalid JSON without aborting other rules", async () => {
    const directory = await makeTemporaryDirectory();
    await mkdir(path.join(directory, ".vscode"));
    await writeFile(path.join(directory, "broken.json"), "{ nope");
    await writeFile(
      path.join(directory, "tsconfig.json"),
      '{\n  // JSONC is valid here.\n  "compilerOptions": { "strict": true, },\n}',
    );
    await writeFile(path.join(directory, "tsconfig.broken.json"), '{ "compilerOptions": {');
    await writeFile(
      path.join(directory, ".vscode", "launch.json"),
      '{\n  // VS Code configuration also permits comments.\n  "version": "0.2.0",\n}',
    );
    await writeFile(path.join(directory, "server.ts"), 'const endpoint = "http://example.com";');

    const report = await scan(directory);

    expect(report.diagnostics).toHaveLength(2);
    expect(
      report.diagnostics.some(
        (diagnostic) =>
          diagnostic.file === "broken.json" && diagnostic.message.includes("Invalid JSON:"),
      ),
    ).toBe(true);
    expect(
      report.diagnostics.some(
        (diagnostic) =>
          diagnostic.file === "tsconfig.broken.json" &&
          diagnostic.message.includes("Invalid JSONC:"),
      ),
    ).toBe(true);
    expect(report.findings.map((finding) => finding.ruleId)).toContain("MCP008");
  });

  it("tracks aliases, CommonJS bindings, named handlers, and multiple outbound clients", async () => {
    const report = await scan(path.join(fixtureRoot, "variant-server"));
    const ruleIds = report.findings.map((finding) => finding.ruleId);
    const serialized = JSON.stringify(report);

    expect(ruleIds.filter((ruleId) => ruleId === "MCP001").length).toBeGreaterThanOrEqual(3);
    expect(ruleIds.filter((ruleId) => ruleId === "MCP003").length).toBeGreaterThanOrEqual(2);
    expect(ruleIds.filter((ruleId) => ruleId === "MCP004").length).toBeGreaterThanOrEqual(3);
    expect(ruleIds).toContain("MCP002");
    expect(ruleIds).toContain("MCP005");
    expect(ruleIds).toContain("MCP006");
    expect(ruleIds).toContain("MCP007");
    expect(ruleIds).toContain("MCP009");
    expect(ruleIds).toContain("MCP011");
    expect(serialized).not.toContain("Q7mN4vX9pL2kR8wC6zT3");
    expect(serialized).not.toContain("H9vQ2mX7kP4zT8nR6cW3");
  });

  it("tracks taint through TypeScript-only wrappers while preserving guarded paths", async () => {
    const directory = await makeTemporaryDirectory();
    await writeFile(
      path.join(directory, "wrapped-unsafe.ts"),
      [
        'import { exec, spawn } from "node:child_process";',
        'import { readFile } from "node:fs/promises";',
        'server.tool("wrapped", async (command: unknown, executable: string | undefined, requested: unknown, url: string) => {',
        "  exec(command as string);",
        "  spawn(executable!, []);",
        "  await readFile(<string>requested);",
        "  return fetch(url satisfies string);",
        "});",
      ].join("\n"),
    );
    await writeFile(
      path.join(directory, "wrapped-guarded.ts"),
      [
        'import { exec, spawn } from "node:child_process";',
        'import { readFile } from "node:fs/promises";',
        'import * as path from "node:path";',
        'server.tool("guarded", async (requested: string) => {',
        '  exec("printf safe");',
        '  spawn("/usr/bin/id", ["--user", requested]);',
        "  await readFile(path.basename(requested) as string);",
        '  return fetch("https://api.example.com/status" satisfies string);',
        "});",
      ].join("\n"),
    );

    const report = await scan(directory);
    const unsafeFindings = report.findings.filter(
      (finding) => finding.file === "wrapped-unsafe.ts",
    );

    expect(new Set(unsafeFindings.map((finding) => finding.ruleId))).toEqual(
      new Set(["MCP001", "MCP002", "MCP003", "MCP004"]),
    );
    expect(report.findings.some((finding) => finding.file === "wrapped-guarded.ts")).toBe(false);
  });

  it("scans a single file and honors the per-file size limit", async () => {
    const directory = await makeTemporaryDirectory();
    const target = path.join(directory, "server.ts");
    await writeFile(target, 'const endpoint = "http://example.com";');

    const regular = await scan(target);
    const limited = await scan(target, { maxFileBytes: 4 });

    expect(regular.scan.target).toBe("server.ts");
    expect(regular.findings.map((finding) => finding.ruleId)).toContain("MCP008");
    expect(limited.scan.filesScanned).toBe(0);
    expect(limited.diagnostics[0]?.message).toContain("larger than 4 bytes");
  });

  it("bounds candidate count and aggregate retained input", async () => {
    const directory = await makeTemporaryDirectory();
    await writeFile(path.join(directory, "a.ts"), "export const a = true;\n");
    await writeFile(path.join(directory, "b.ts"), "export const b = true;\n");

    const candidateLimited = await scan(directory, { maxFiles: 1 });
    expect(candidateLimited.scan.filesScanned).toBe(1);
    expect(candidateLimited.diagnostics).toContainEqual(
      expect.objectContaining({ message: expect.stringContaining("file limit"), type: "error" }),
    );

    const byteLimited = await scan(directory, { maxTotalBytes: 25 });
    expect(byteLimited.scan.filesScanned).toBe(1);
    expect(byteLimited.diagnostics).toContainEqual(
      expect.objectContaining({
        message: expect.stringContaining("Aggregate scan input limit"),
        type: "error",
      }),
    );
  });

  it("recognizes provider credential shapes without committing credential-shaped fixtures", async () => {
    const directory = await makeTemporaryDirectory();
    const credentials = [
      ["ghp_", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"].join(""),
      ["ghp_", "test", "ABCDEFGHIJKLMNOPQRSTUVWXYZ"].join(""),
      ["AK", "IAABCDEFGHIJKLMNOP"].join(""),
      ["xoxb-", "1234567890-ABCDEFGHIJKLMNOPQRSTUV"].join(""),
    ];
    await writeFile(path.join(directory, ".env.runtime"), credentials.join("\n"));

    const report = await scan(directory);
    const serialized = JSON.stringify(report);

    expect(report.findings.filter((finding) => finding.ruleId === "MCP007")).toHaveLength(4);
    for (const credential of credentials) {
      expect(serialized).not.toContain(credential);
    }
  });

  it("reports random-looking provider credentials in test and example paths", async () => {
    const directory = await makeTemporaryDirectory();
    await mkdir(path.join(directory, "examples"));
    const credentials = [
      ["ghp_", "R8mQ2vN7kL4xP9cT6aB3dE5fG1hJ4kS"].join(""),
      ["sk-proj-", "Z7mP2vK9xR4cT8nQ6aW3dF5hJ1sL0eY"].join(""),
      ["xoxb-", "7391846250-Q7mN4vX9pL2kR8wC6zT3"].join(""),
      ["AK", "IAA7B9C2D4E6F8G1H3"].join(""),
    ];
    await writeFile(
      path.join(directory, "provider-credentials.test.ts"),
      credentials
        .slice(0, 2)
        .map((value) => `const credential = "${value}";`)
        .join("\n"),
    );
    await writeFile(
      path.join(directory, "examples", "provider-credentials.ts"),
      credentials
        .slice(2)
        .map((value) => `const credential = "${value}";`)
        .join("\n"),
    );

    const report = await scan(directory);
    const findings = report.findings.filter((finding) => finding.ruleId === "MCP007");
    const serialized = JSON.stringify(report);

    expect(findings).toHaveLength(4);
    expect(new Set(findings.map((finding) => finding.file))).toEqual(
      new Set(["examples/provider-credentials.ts", "provider-credentials.test.ts"]),
    );
    for (const credential of credentials) {
      expect(serialized).not.toContain(credential);
    }
  });

  it("filters synthetic test credentials without hiding high-signal test-file secrets", async () => {
    const directory = await makeTemporaryDirectory();
    const publicIngestKey = ["phc_", "Ab3dEf6hJk9mNp2rSt5vWx8z"].join("");
    const highSignalSecret = ["R8mQ2", "vN7kL4", "xP9cT6"].join("");
    const syntheticProviderSecret = ["ghp_", "test", "ABCDEFGHIJKLMNOPQRSTUVWXYZ"].join("");
    const documentedAwsExample = ["AKIA", "IOSFODNN7EXAMPLE"].join("");
    await writeFile(
      path.join(directory, "synthetic-auth.test.ts"),
      [
        'const accessToken = "fresh-access-token";',
        `const providerToken = "${syntheticProviderSecret}";`,
        `const awsAccessKeyId = "${documentedAwsExample}";`,
        `const POSTHOG_API_KEY = "${publicIngestKey}";`,
        'const callback = "https://user:password@callback.example/oauth?token=redirect-query";',
        'const proxy = "https://proxyuser:proxypass@proxy.company.com:8443";',
      ].join("\n"),
    );
    await writeFile(
      path.join(directory, "leaked-auth.test.ts"),
      [
        `const accessToken = "${highSignalSecret}";`,
        `const callback = "https://user:${highSignalSecret}@example.com/oauth";`,
      ].join("\n"),
    );
    await writeFile(
      path.join(directory, "runtime.py"),
      [
        "def configure(client_secret, api_token, registry):",
        "    oauth = OAuth(client_secret=client_secret, access_token=api_token)",
        "    is_secret = registry.is_secret",
        "    return oauth, is_secret",
      ].join("\n"),
    );
    await writeFile(
      path.join(directory, ".env.example"),
      [
        "SERVICE_API_KEY=your-financial-datasets-api-key",
        "HTTPS_PROXY=https://user:pass@proxy.example.com:8443",
      ].join("\n"),
    );
    await writeFile(
      path.join(directory, "embedded-config.yaml"),
      [
        "commandFunction: |-",
        "  const env = {",
        "    SERVICE_API_TOKEN: config.serviceApiToken,",
        "  };",
        "secrets:",
        "  service_password:",
        "    environment: SERVICE_PASSWORD",
      ].join("\n"),
    );

    const report = await scan(directory);
    const secrets = report.findings.filter((finding) => finding.ruleId === "MCP007");
    const credentialUrls = report.findings.filter((finding) => finding.ruleId === "MCP009");
    const serialized = JSON.stringify(report);

    expect(secrets).toHaveLength(1);
    expect(secrets[0]?.file).toBe("leaked-auth.test.ts");
    expect(credentialUrls).toHaveLength(1);
    expect(credentialUrls[0]?.file).toBe("leaked-auth.test.ts");
    expect(serialized).not.toContain(publicIngestKey);
    expect(serialized).not.toContain(syntheticProviderSecret);
    expect(serialized).not.toContain(documentedAwsExample);
    expect(serialized).not.toContain(highSignalSecret);
  });

  it("separates runtime transport behavior from tests and non-network identifiers", async () => {
    const directory = await makeTemporaryDirectory();
    await mkdir(path.join(directory, "integration-tests"));
    await writeFile(
      path.join(directory, "runtime.ts"),
      [
        'import { spawn } from "node:child_process";',
        'const endpoint = "http://api.mcp.internal";',
        'const templatedPath = "http://api.mcp.internal/{resource_id}";',
        ["const parsedHost = new URL(`http://$", "{untrustedHost}`);"].join(""),
        'const svgNamespace = "http://www.w3.org/2000/svg";',
        'const license = "http://www.apache.org/licenses/LICENSE-2.0";',
        'const proxyHelp = "Use http://proxy:8080/ when required";',
        'spawn("node", ["server.js"], { env: { ...process.env } });',
        'spawn("node", ["safe.js"], { env: { PATH: process.env.PATH } });',
        "void endpoint; void templatedPath; void svgNamespace; void license; void proxyHelp;",
      ].join("\n"),
    );
    await writeFile(
      path.join(directory, "integration-tests", "runtime.ts"),
      [
        'import { spawn } from "node:child_process";',
        'const endpoint = "http://untrusted.example";',
        'spawn("node", ["server.js"], { env: { ...process.env } });',
        "void endpoint;",
      ].join("\n"),
    );
    await writeFile(
      path.join(directory, "test-extension.js"),
      [
        'import { spawn } from "node:child_process";',
        'spawn("node", ["server.js"], { env: { ...process.env } });',
      ].join("\n"),
    );

    const report = await scan(directory);
    const transports = report.findings.filter((finding) => finding.ruleId === "MCP008");
    const environments = report.findings.filter((finding) => finding.ruleId === "MCP011");

    expect(transports).toHaveLength(2);
    expect(transports.every((finding) => finding.file === "runtime.ts")).toBe(true);
    expect(environments).toHaveLength(1);
    expect(environments[0]?.file).toBe("runtime.ts");
  });

  it("keeps standards identifiers distinct from transports on the same hosts", async () => {
    const directory = await makeTemporaryDirectory();
    await writeFile(
      path.join(directory, "standards.ts"),
      [
        'const mathNamespace = "http://www.w3.org/1998/Math/MathML";',
        'const draftFour = "http://json-schema.org/draft-04/schema#";',
        'const bundledMath = "namespace=\\"http://www.w3.org/1998/Math/MathML\\"";',
        'const bundledDraftSeven = "schema=\\"http://json-schema.org/draft-07/schema#\\"";',
        'const w3Endpoint = "http://www.w3.org/TR/";',
        'const schemaEndpoint = "http://json-schema.org/api";',
        'const queryEndpoint = "http://json-schema.org/draft-07/schema?download=1";',
        "void mathNamespace; void draftFour; void bundledMath; void bundledDraftSeven;",
        "void w3Endpoint; void schemaEndpoint; void queryEndpoint;",
      ].join("\n"),
    );

    const report = await scan(directory);
    const transports = report.findings.filter((finding) => finding.ruleId === "MCP008");

    expect(transports).toHaveLength(3);
    expect(transports.map((finding) => finding.message).sort()).toEqual([
      "Remote endpoint json-schema.org uses cleartext HTTP.",
      "Remote endpoint json-schema.org uses cleartext HTTP.",
      "Remote endpoint www.w3.org uses cleartext HTTP.",
    ]);
    const transportEvidence = transports.map((finding) => finding.evidence).join("\n");
    expect(transportEvidence).toContain("http://www.w3.org/TR/");
    expect(transportEvidence).toContain("http://json-schema.org/api");
    expect(transportEvidence).toContain("http://json-schema.org/draft-07/schema?download=1");
    expect(transportEvidence).not.toContain("Math/MathML");
    expect(transportEvidence).not.toContain("draft-04/schema#");
  });

  it("tracks Python MCP handler input into the narrow high-risk sink set", async () => {
    const directory = await makeTemporaryDirectory();
    await writeFile(
      path.join(directory, "server.py"),
      [
        "from mcp.server.fastmcp import FastMCP",
        "import httpx, os, subprocess",
        "mcp = FastMCP('fixture')",
        "",
        "@mcp.tool()",
        "async def unsafe(",
        "    command: str, target: str, url: str, expression: str",
        "):",
        "    copied = command",
        "    os.system(f'run {copied}')",
        "    subprocess.run([target, '--version'])",
        "    open(target).read()",
        "    await httpx.get(",
        "        url",
        "    )",
        "    return eval(expression)",
      ].join("\n"),
    );
    await writeFile(
      path.join(directory, "safe.py"),
      [
        "from mcp.server.fastmcp import FastMCP",
        "import httpx, subprocess",
        "mcp = FastMCP('fixture')",
        "",
        "@mcp.tool()",
        "def safe(name: str):",
        "    subprocess.run(['/usr/bin/id', '--user', name], check=True)",
        "    return httpx.get('https://api.example.com/status')",
      ].join("\n"),
    );

    const report = await scan(directory);
    const runtimeFindings = report.findings.filter((finding) => finding.file === "server.py");

    expect(new Set(runtimeFindings.map((finding) => finding.ruleId))).toEqual(
      new Set(["MCP001", "MCP002", "MCP003", "MCP004", "MCP005"]),
    );
    expect(report.findings.some((finding) => finding.file === "safe.py")).toBe(false);
  });

  it("keeps paired Python vulnerable and guarded fixtures stable", async () => {
    const vulnerable = await scan(path.join(fixtureRoot, "python-vulnerable-server"));
    const guarded = await scan(path.join(fixtureRoot, "python-safe-server"));

    expect(vulnerable.findings).toHaveLength(5);
    expect(new Set(vulnerable.findings.map((finding) => finding.ruleId))).toEqual(
      new Set(["MCP001", "MCP002", "MCP003", "MCP004", "MCP005"]),
    );
    expect(guarded.findings).toEqual([]);
  });

  it("resolves Python import aliases, keyword arguments, and executable overrides", async () => {
    const directory = await makeTemporaryDirectory();
    await writeFile(
      path.join(directory, "aliased.py"),
      [
        "from mcp.server.fastmcp import FastMCP as Framework",
        "from os import rename as move, system as shell",
        "from subprocess import run as launch",
        "from urllib.request import urlopen as fetch_url",
        "from builtins import exec as execute",
        "base = Framework('fixture')",
        "app = base",
        "",
        "@app.tool(",
        "    name='unsafe',",
        ")",
        "async def unsafe(command: str, target: str, url: str, source: str):",
        "    copied = str(command)",
        "    shell(f'run {copied}')",
        "    launch(args=['/usr/bin/printf', command], executable=target)",
        "    move(src=target, dst='/tmp/fixed')",
        "    fetch_url(url=url)",
        "    execute(source)",
      ].join("\n"),
    );

    const report = await scan(directory);

    expect(report.findings).toHaveLength(5);
    expect(new Set(report.findings.map((finding) => finding.ruleId))).toEqual(
      new Set(["MCP001", "MCP002", "MCP003", "MCP004", "MCP005"]),
    );
  });

  it("tracks Python HTTP clients without treating strings, attributes, or safe arguments as input", async () => {
    const directory = await makeTemporaryDirectory();
    await writeFile(
      path.join(directory, "clients.py"),
      [
        "from fastmcp import FastMCP",
        "import httpx, os, subprocess",
        "mcp = FastMCP('fixture')",
        "",
        "@mcp.tool()",
        "async def guarded(name: str, command: str):",
        "    '''os.system(command)'''",
        "    holder = object()",
        "    os.system('command')",
        "    os.system(holder.command)",
        "    subprocess.run(['/usr/bin/id', '--user', name], check=True)",
        "    safe_name = os.path.basename(name)",
        "    open(os.path.join('/tmp', safe_name)).read()",
        "    return await httpx.get(url='https://api.example.com/status')",
        "",
        "@mcp.resource('semgrep://rule/{rule_id}/yaml')",
        "async def fixed_origin(rule_id: str):",
        "    return await httpx.get(f'https://semgrep.dev/c/r/{rule_id}')",
        "",
        "@mcp.tool()",
        "async def request_url(url: str):",
        "    base_client = httpx.AsyncClient()",
        "    client = base_client",
        "    return await client.request('GET', url=url)",
      ].join("\n"),
    );

    const report = await scan(directory);

    expect(report.findings).toHaveLength(1);
    expect(report.findings[0]?.ruleId).toBe("MCP004");
    expect(report.findings[0]?.line).toBe(24);
  });

  it("does not preserve a Python basename guard after an unsafe augmented assignment", async () => {
    const directory = await makeTemporaryDirectory();
    await writeFile(
      path.join(directory, "overwritten.py"),
      [
        "from mcp.server.fastmcp import FastMCP",
        "import os",
        "mcp = FastMCP('fixture')",
        "@mcp.tool()",
        "def read_file(name: str, suffix: str):",
        "    safe_name = os.path.basename(name)",
        "    safe_name += suffix",
        "    return open(safe_name).read()",
      ].join("\n"),
    );

    const report = await scan(directory);

    expect(report.findings).toHaveLength(1);
    expect(report.findings[0]?.ruleId).toBe("MCP003");
  });

  it("does not mistake generic decorators or shadowed Python builtins for MCP sinks", async () => {
    const directory = await makeTemporaryDirectory();
    await writeFile(
      path.join(directory, "generic.py"),
      [
        "import os",
        "def tool():",
        "    return lambda function: function",
        "@tool()",
        "def unsafe(value):",
        "    os.system(value)",
      ].join("\n"),
    );
    await writeFile(
      path.join(directory, "shadowed.py"),
      [
        "from mcp.server.fastmcp import FastMCP",
        "mcp = FastMCP('fixture')",
        "@mcp.tool()",
        "def shadowed(os, open, eval):",
        "    os.system(open)",
        "    open(eval)",
        "    return eval(os)",
      ].join("\n"),
    );
    await writeFile(
      path.join(directory, "scoped-client.py"),
      [
        "from mcp.server.fastmcp import FastMCP",
        "import httpx",
        "mcp = FastMCP('fixture')",
        "def helper():",
        "    client = httpx.AsyncClient()",
        "    return client",
        "@mcp.tool()",
        "def shadowed_client(client, url):",
        "    return client.get(url)",
      ].join("\n"),
    );

    const report = await scan(directory);

    expect(report.findings).toEqual([]);
  });

  it("bounds pathological Python formatted-string nesting without crashing a scan", async () => {
    const directory = await makeTemporaryDirectory();
    let nested = "value";
    for (let index = 0; index < 80; index += 1) nested = `f"{${nested}}"`;
    await writeFile(
      path.join(directory, "nested.py"),
      [
        "from mcp.server.fastmcp import FastMCP",
        "import os",
        "mcp = FastMCP('fixture')",
        "@mcp.tool()",
        "def inspect(value):",
        `    return os.system(${nested})`,
      ].join("\n"),
    );

    const report = await scan(directory);

    expect(report.diagnostics.filter((diagnostic) => diagnostic.type === "error")).toEqual([]);
  });

  it("ignores Python lookalikes outside handlers, comments, and test files", async () => {
    const directory = await makeTemporaryDirectory();
    await writeFile(
      path.join(directory, "helpers.py"),
      ["def helper(value):", "    # os.system(value)", "    return 'requests.get(value)'"].join(
        "\n",
      ),
    );
    await writeFile(
      path.join(directory, "server_test.py"),
      [
        "from mcp.server.fastmcp import FastMCP",
        "mcp = FastMCP('fixture')",
        "@mcp.tool()",
        "def unsafe(value):",
        "    os.system(value)",
      ].join("\n"),
    );

    const report = await scan(directory);

    expect(report.findings).toEqual([]);
  });
});

async function makeTemporaryDirectory(): Promise<string> {
  const directory = await mkdtemp(path.join(tmpdir(), "uleravo-test-"));
  temporaryDirectories.push(directory);
  return directory;
}
