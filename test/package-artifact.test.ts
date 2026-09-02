import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { access, mkdir, mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { describe, expect, it } from "vitest";

const execFileAsync = promisify(execFile);
const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const packageName = "uleravo";
const packageVersion = "0.6.3";
const archiveName = `${packageName}-${packageVersion}.tgz`;

describe("packed release", () => {
  it("is reproducible, self-contained, and exercises every advertised installed command", async () => {
    const temporaryRoot = await mkdtemp(path.join(os.tmpdir(), "uleravo-package-"));
    try {
      const firstPack = path.join(temporaryRoot, "pack-a");
      const secondPack = path.join(temporaryRoot, "pack-b");
      await Promise.all([mkdir(firstPack), mkdir(secondPack)]);
      const pnpmEntrypoint = await findPnpmEntrypoint();
      await run(
        process.execPath,
        [pnpmEntrypoint, "pack", "--pack-destination", firstPack],
        repositoryRoot,
      );
      await run(
        process.execPath,
        [pnpmEntrypoint, "pack", "--pack-destination", secondPack],
        repositoryRoot,
      );

      const firstArchive = path.join(firstPack, archiveName);
      const secondArchive = path.join(secondPack, archiveName);
      const [firstBytes, secondBytes] = await Promise.all([
        readFile(firstArchive),
        readFile(secondArchive),
      ]);
      expect(sha256(firstBytes)).toBe(sha256(secondBytes));
      expect(firstBytes).toEqual(secondBytes);

      const prefix = path.join(temporaryRoot, "prefix");
      const npmEntrypoint = await findNpmEntrypoint();
      await run(
        process.execPath,
        [
          npmEntrypoint,
          "install",
          "--global",
          "--prefix",
          prefix,
          "--ignore-scripts",
          "--no-audit",
          "--no-fund",
          firstArchive,
        ],
        temporaryRoot,
        { npm_config_cache: path.join(temporaryRoot, "npm-cache") },
      );

      const installedRoot =
        process.platform === "win32"
          ? path.join(prefix, "node_modules", packageName)
          : path.join(prefix, "lib", "node_modules", packageName);
      const installedShim =
        process.platform === "win32"
          ? path.join(prefix, `${packageName}.cmd`)
          : path.join(prefix, "bin", packageName);
      const installedCli = path.join(installedRoot, "dist", "cli.js");
      const installedReadme = await readFile(path.join(installedRoot, "README.md"), "utf8");
      await assertLocalReadmeLinks(installedReadme, installedRoot);

      await writeFile(
        path.join(temporaryRoot, "safe-target.ts"),
        "export const normalize = (value: string): string => value.trim();\n",
      );
      const skillRoot = path.join(temporaryRoot, "minimal-skill");
      await mkdir(skillRoot);
      await writeFile(
        path.join(skillRoot, "SKILL.md"),
        "---\nname: minimal-skill\ndescription: A packaged-command smoke fixture.\n---\n\nInspect the supplied local input.\n",
      );
      await Promise.all([access(installedShim), access(installedCli)]);
      await runInstalledCli(installedShim, installedCli, ["--version"], temporaryRoot);
      await runInstalledCli(
        installedShim,
        installedCli,
        ["scan", path.join(temporaryRoot, "safe-target.ts")],
        temporaryRoot,
      );
      await runInstalledCli(
        installedShim,
        installedCli,
        ["scan", path.join(temporaryRoot, "safe-target.ts"), "--fail-on", "high"],
        temporaryRoot,
      );

      const artifactSnapshot = path.join(temporaryRoot, "skill.snapshot.json");
      await runInstalledCli(
        installedShim,
        installedCli,
        [
          "snapshot",
          skillRoot,
          "--kind",
          "skill",
          "--format",
          "json",
          "--output",
          artifactSnapshot,
        ],
        temporaryRoot,
      );
      const installedSnapshot = JSON.parse(await readFile(artifactSnapshot, "utf8")) as {
        complete: boolean;
        documentType: string;
      };
      expect(installedSnapshot.documentType).toBe("uleravo.artifact-snapshot");
      expect(installedSnapshot.complete).toBe(true);

      const pluginRoot = path.join(temporaryRoot, "minimal-plugin");
      await mkdir(path.join(pluginRoot, ".codex-plugin"), { recursive: true });
      await writeFile(
        path.join(pluginRoot, ".codex-plugin", "plugin.json"),
        `${JSON.stringify({
          description: "A packaged Plugin smoke fixture.",
          name: "minimal-plugin",
          version: "1.0.0",
        })}\n`,
      );
      const pluginSnapshot = path.join(temporaryRoot, "plugin.snapshot.json");
      await runInstalledCli(
        installedShim,
        installedCli,
        [
          "snapshot",
          pluginRoot,
          "--kind",
          "plugin",
          "--format",
          "json",
          "--output",
          pluginSnapshot,
        ],
        temporaryRoot,
      );
      const installedPluginSnapshot = JSON.parse(await readFile(pluginSnapshot, "utf8")) as {
        artifact: { kind: string };
        complete: boolean;
      };
      expect(installedPluginSnapshot).toMatchObject({
        artifact: { kind: "plugin" },
        complete: true,
      });

      const sarif = path.join(temporaryRoot, "uleravo.sarif");
      const report = path.join(temporaryRoot, "uleravo.json");
      const provenanceReport = path.join(temporaryRoot, "uleravo-provenance.json");
      await runInstalledCli(
        installedShim,
        installedCli,
        [
          "scan",
          path.join(temporaryRoot, "safe-target.ts"),
          "--format",
          "sarif",
          "--output",
          sarif,
        ],
        temporaryRoot,
      );
      await runInstalledCli(
        installedShim,
        installedCli,
        [
          "scan",
          path.join(temporaryRoot, "safe-target.ts"),
          "--format",
          "json",
          "--output",
          report,
        ],
        temporaryRoot,
      );
      await runInstalledCli(
        installedShim,
        installedCli,
        [
          "scan",
          path.join(temporaryRoot, "safe-target.ts"),
          "--format",
          "json",
          "--output",
          provenanceReport,
          "--repository-url",
          "https://github.com/example/safe-target",
          "--commit-sha",
          "a".repeat(40),
        ],
        temporaryRoot,
      );

      const comparison = path.join(temporaryRoot, "comparison.json");
      await runInstalledCli(
        installedShim,
        installedCli,
        [
          "compare",
          report,
          report,
          "--format",
          "json",
          "--output",
          comparison,
          "--fail-on",
          "high",
        ],
        temporaryRoot,
      );

      const privateKey = path.join(temporaryRoot, "private.pem");
      const publicKey = path.join(temporaryRoot, "public.pem");
      const envelope = path.join(temporaryRoot, "uleravo.signed.json");
      const verified = path.join(temporaryRoot, "verified.json");
      await runInstalledCli(
        installedShim,
        installedCli,
        ["keygen", "--private-key", privateKey, "--public-key", publicKey],
        temporaryRoot,
      );
      await runInstalledCli(
        installedShim,
        installedCli,
        ["sign", report, "--private-key", privateKey, "--output", envelope],
        temporaryRoot,
      );
      await runInstalledCli(
        installedShim,
        installedCli,
        ["verify", envelope, "--public-key", publicKey, "--output", verified],
        temporaryRoot,
      );

      await Promise.all(
        [
          sarif,
          artifactSnapshot,
          report,
          provenanceReport,
          comparison,
          privateKey,
          publicKey,
          envelope,
          verified,
        ].map((file) => access(file)),
      );
      expect(await readFile(verified, "utf8")).toBe(await readFile(report, "utf8"));
    } finally {
      await rm(temporaryRoot, { force: true, recursive: true });
    }
  }, 120_000);
});

async function assertLocalReadmeLinks(readme: string, installedRoot: string): Promise<void> {
  for (const match of readme.matchAll(/\[[^\]]+\]\(([^)]+)\)/g)) {
    const rawTarget = match[1]?.trim();
    if (
      rawTarget === undefined ||
      rawTarget.startsWith("#") ||
      /^[a-z][a-z0-9+.-]*:/iu.test(rawTarget)
    ) {
      continue;
    }
    const relativeTarget = decodeURIComponent(rawTarget.split(/[?#]/u, 1)[0] ?? "");
    const target = path.resolve(installedRoot, relativeTarget);
    expect(target.startsWith(`${installedRoot}${path.sep}`)).toBe(true);
    expect((await stat(target)).isFile()).toBe(true);
  }
}

async function findPnpmEntrypoint(): Promise<string> {
  const entrypoint = process.env.npm_execpath;
  if (entrypoint === undefined || !/pnpm\.(?:cjs|mjs|js)$/iu.test(entrypoint)) {
    throw new Error("Run the packed-release test through the repository's pinned pnpm CLI.");
  }
  await access(entrypoint);
  return entrypoint;
}

async function findNpmEntrypoint(): Promise<string> {
  const executableDirectory = path.dirname(process.execPath);
  const candidates = [
    path.join(executableDirectory, "node_modules", "npm", "bin", "npm-cli.js"),
    path.resolve(executableDirectory, "..", "lib", "node_modules", "npm", "bin", "npm-cli.js"),
  ];
  for (const candidate of candidates) {
    try {
      if ((await stat(candidate)).isFile()) {
        return candidate;
      }
    } catch {
      // Continue to the other standard Node.js installation layout.
    }
  }
  throw new Error("Could not locate npm's JavaScript entrypoint beside the active Node.js binary.");
}

async function runInstalledCli(
  installedShim: string,
  installedCli: string,
  args: readonly string[],
  cwd: string,
): Promise<void> {
  if (process.platform === "win32") {
    await run(process.execPath, [installedCli, ...args], cwd);
    return;
  }
  await run(installedShim, args, cwd);
}

async function run(
  entrypoint: string,
  args: readonly string[],
  cwd: string,
  environment: NodeJS.ProcessEnv = {},
): Promise<void> {
  await execFileAsync(entrypoint, [...args], {
    cwd,
    env: { ...process.env, ...environment, NO_UPDATE_NOTIFIER: "1" },
    maxBuffer: 10 * 1024 * 1024,
  });
}

function sha256(content: Buffer): string {
  return createHash("sha256").update(content).digest("hex");
}
