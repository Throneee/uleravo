import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { access, cp, mkdir, mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { describe, expect, it } from "vitest";

const execFileAsync = promisify(execFile);
const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const packageName = "uleravo";
const packageVersion = "0.8.0-rc.1";
const artifactAnalyzerVersion = "0.7.0";
const harnessAnalyzerVersion = "0.7.0";
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

      const installedRoot = path.join(prefix, "node_modules", packageName);
      const installedShim = path.join(
        prefix,
        "node_modules",
        ".bin",
        process.platform === "win32" ? `${packageName}.cmd` : packageName,
      );
      const installedCli = path.join(installedRoot, "dist", "cli.js");
      const installedReadme = await readFile(path.join(installedRoot, "README.md"), "utf8");
      await assertLocalReadmeLinks(installedReadme, installedRoot);
      for (const reference of ["skill-review.md", "mcp-scanning.md"]) {
        const docs = path.join(installedRoot, "docs");
        await assertLocalReadmeLinks(
          await readFile(path.join(docs, reference), "utf8"),
          installedRoot,
          docs,
        );
      }

      await writeFile(
        path.join(temporaryRoot, "safe-target.ts"),
        "export const normalize = (value: string): string => value.trim();\n",
      );
      const workflow = path.join(temporaryRoot, "workflow");
      await cp(path.join(installedRoot, "examples", "skill-review"), workflow, { recursive: true });
      const skillRoot = path.join(workflow, "skill");
      const projectRoot = path.join(workflow, "project");
      await mkdir(projectRoot);
      await Promise.all([access(installedShim), access(installedCli)]);
      const versionResult = await runInstalledCli(
        installedShim,
        installedCli,
        ["--version"],
        temporaryRoot,
      );
      expect(String(versionResult.stdout).trim()).toBe(packageVersion);
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
        snapshot: { analyzer: { version: string } };
      };
      expect(installedSnapshot.documentType).toBe("uleravo.artifact-snapshot");
      expect(installedSnapshot.complete).toBe(true);
      expect(installedSnapshot.snapshot.analyzer.version).toBe(artifactAnalyzerVersion);

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
        snapshot: { analyzer: { version: string } };
      };
      expect(installedPluginSnapshot).toMatchObject({
        artifact: { kind: "plugin" },
        complete: true,
        snapshot: { analyzer: { version: artifactAnalyzerVersion } },
      });

      const baselineConfig = path.join(temporaryRoot, "baseline-codex.toml");
      const currentConfig = path.join(temporaryRoot, "current-codex.toml");
      const baselineHarness = path.join(temporaryRoot, "baseline.harness.json");
      const currentHarness = path.join(temporaryRoot, "current.harness.json");
      const harnessDelta = path.join(temporaryRoot, "harness.delta.json");
      await Promise.all([
        writeFile(baselineConfig, 'sandbox_mode = "read-only"\n'),
        writeFile(currentConfig, 'sandbox_mode = "danger-full-access"\n'),
      ]);
      for (const [config, output] of [
        [baselineConfig, baselineHarness],
        [currentConfig, currentHarness],
      ] as const) {
        await runInstalledCli(
          installedShim,
          installedCli,
          [
            "harness",
            temporaryRoot,
            "--user-config",
            config,
            "--skip-project-config",
            "--skip-requirements",
            "--codex-version",
            "0.138.0",
            "--format",
            "json",
            "--output",
            output,
          ],
          temporaryRoot,
        );
      }
      await runInstalledCli(
        installedShim,
        installedCli,
        [
          "harness-delta",
          baselineHarness,
          currentHarness,
          "--format",
          "json",
          "--output",
          harnessDelta,
        ],
        temporaryRoot,
      );
      const installedHarness = JSON.parse(await readFile(currentHarness, "utf8")) as {
        documentType: string;
        harness: { analyzer: { version: string } };
      };
      const installedHarnessDelta = JSON.parse(await readFile(harnessDelta, "utf8")) as {
        changes: Array<{ direction: string; key: string }>;
        documentType: string;
      };
      expect(installedHarness).toMatchObject({
        documentType: "uleravo.harness-snapshot",
        harness: { analyzer: { version: harnessAnalyzerVersion } },
      });
      expect(installedHarnessDelta.documentType).toBe("uleravo.harness-delta");
      expect(installedHarnessDelta.changes).toContainEqual(
        expect.objectContaining({
          direction: "expanded",
          key: "filesystem.sandbox-mode",
        }),
      );

      const graphConfig = path.join(workflow, "config.toml");
      const capabilityGraph = path.join(temporaryRoot, "skill.capability-graph.json");
      await runInstalledCli(
        installedShim,
        installedCli,
        [
          "capability-graph",
          skillRoot,
          projectRoot,
          "--user-config",
          graphConfig,
          "--skip-requirements",
          "--format",
          "json",
          "--output",
          capabilityGraph,
        ],
        temporaryRoot,
      );
      const installedCapabilityGraph = JSON.parse(await readFile(capabilityGraph, "utf8")) as {
        correlation: { state: string };
        documentType: string;
        scope: { assertion: string; effectAuthority: string; runtimeReachability: string };
      };
      expect(installedCapabilityGraph).toMatchObject({
        correlation: { state: "declared-disabled" },
        documentType: "uleravo.skill-capability-graph",
        scope: {
          assertion: "declared-exposure-only",
          effectAuthority: "not-established",
          runtimeReachability: "not-observed",
        },
      });
      await assertInstalledGraphComparison({
        baseline: capabilityGraph,
        config: graphConfig,
        installedCli,
        installedRoot,
        installedShim,
        project: projectRoot,
        skill: skillRoot,
        workspace: temporaryRoot,
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
          capabilityGraph,
          baselineHarness,
          currentHarness,
          harnessDelta,
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

async function assertInstalledGraphComparison(fixture: {
  baseline: string;
  config: string;
  installedCli: string;
  installedRoot: string;
  installedShim: string;
  project: string;
  skill: string;
  workspace: string;
}): Promise<void> {
  const invoke = (args: readonly string[]) =>
    runInstalledCli(fixture.installedShim, fixture.installedCli, args, fixture.workspace);
  const capture = (output: string) =>
    invoke([
      "capability-graph",
      fixture.skill,
      fixture.project,
      "--user-config",
      fixture.config,
      "--skip-requirements",
      "--format",
      "json",
      "--output",
      output,
    ]);
  const compare = (baseline: string, current: string, options: string[] = []) =>
    invoke(["capability-graph-compare", baseline, current, ...options]);
  await access(
    path.join(fixture.installedRoot, "schemas", "capability-graph-comparison.schema.json"),
  );
  const originalBaseline = await readFile(fixture.baseline, "utf8");
  await access(path.join(fixture.installedRoot, "schemas", "skill-review-receipt.schema.json"));
  const receipt = path.join(fixture.workspace, "baseline.review.json");
  const reviewText = await invoke(["review-record", fixture.baseline]);
  expect(String(reviewText.stdout)).toContain("reviewed-captured-evidence (caller-declared)");
  expect(String(reviewText.stdout)).toContain("unsigned-unauthenticated");
  await invoke(["review-record", fixture.baseline, "--format", "json", "--output", receipt]);
  const receiptBytes = await readFile(receipt, "utf8");
  const checkReview = (current: string, options: string[] = []) =>
    invoke(["review-check", receipt, current, ...options]);
  const matchText = await checkReview(fixture.baseline);
  expect(String(matchText.stdout)).toContain("Review result: matches-evidence");
  expect(String(matchText.stdout)).toContain("Recapture before checking");
  const matchJson = await checkReview(fixture.baseline, ["--format", "json"]);
  expect(JSON.parse(String(matchJson.stdout))).toMatchObject({
    status: "matches-evidence",
    comparison: { complete: true, status: "unchanged" },
  });
  const reordered = path.join(fixture.workspace, "reordered.graph.json");
  await writeFile(
    reordered,
    JSON.stringify(
      JSON.parse(originalBaseline, (_key, value: unknown) =>
        typeof value === "object" && value !== null && !Array.isArray(value)
          ? Object.fromEntries(Object.entries(value).reverse())
          : value,
      ),
    ),
  );
  const canonical = await invoke(["review-record", reordered, "--format", "json"]);
  expect(String(canonical.stdout)).toBe(receiptBytes);
  const unchangedText = await compare(fixture.baseline, fixture.baseline);
  expect(String(unchangedText.stdout)).toContain("Result: unchanged");
  expect(String(unchangedText.stdout)).toContain("installation continuity is not established");
  const unchanged = await compare(fixture.baseline, fixture.baseline, ["--format", "json"]);
  expect(JSON.parse(String(unchanged.stdout))).toMatchObject({
    complete: true,
    documentType: "uleravo.skill-capability-graph-comparison",
    status: "unchanged",
  });

  const manifest = path.join(fixture.skill, "SKILL.md");
  const originalSkill = await readFile(manifest, "utf8");
  const originalConfig = await readFile(fixture.config, "utf8");
  await writeFile(manifest, `${originalSkill}Explain the local evidence.\n`);
  const bytesChanged = path.join(fixture.workspace, "bytes-changed.graph.json");
  await capture(bytesChanged);
  const bytesResult = await compare(fixture.baseline, bytesChanged, ["--format", "json"]);
  expect(JSON.parse(String(bytesResult.stdout))).toMatchObject({
    status: "changed",
    observations: { skillBytes: "different", declarations: "same", harnessContext: "same" },
  });
  expect(String(bytesResult.stdout)).not.toContain(fixture.workspace);
  expect(String(bytesResult.stdout)).not.toContain("Explain the local evidence");
  expect(String((await compare(fixture.baseline, bytesChanged, ["--format", "json"])).stdout)).toBe(
    String(bytesResult.stdout),
  );
  const bytesText = await compare(fixture.baseline, bytesChanged);
  expect(String(bytesText.stdout)).toContain("Skill bytes: different");
  expect(String(bytesText.stdout)).toContain("Declaration groups: same");
  await expect(checkReview(bytesChanged, ["--format", "json"])).rejects.toMatchObject({
    code: 1,
    stdout: expect.stringContaining('"status": "changed-since-review"'),
  });
  await expect(checkReview(bytesChanged)).rejects.toMatchObject({
    code: 1,
    stdout: expect.stringContaining("Skill bytes: different"),
  });
  const bytesReceipt = path.join(fixture.workspace, "bytes.review.json");
  await invoke(["review-record", bytesChanged, "--format", "json", "--output", bytesReceipt]);

  await writeFile(fixture.config, originalConfig.replace("enabled = false", "enabled = true"));
  const enabled = path.join(fixture.workspace, "enabled.graph.json");
  await capture(enabled);
  const declarationResult = await compare(bytesChanged, enabled, ["--format", "json"]);
  expect(JSON.parse(String(declarationResult.stdout))).toMatchObject({
    status: "changed",
    baseline: { state: "declared-disabled" },
    current: { state: "declared-enabled" },
    observations: { skillBytes: "same", declarations: "different" },
  });
  const declarationText = await compare(bytesChanged, enabled);
  expect(String(declarationText.stdout)).toContain("declared-disabled");
  expect(String(declarationText.stdout)).toContain("declared-enabled");
  await expect(invoke(["review-check", bytesReceipt, enabled])).rejects.toMatchObject({
    code: 1,
    stdout: expect.stringContaining("declared-disabled -> declared-enabled"),
  });
  for (const output of [fixture.baseline, receipt, enabled]) {
    await expect(invoke(["review-record", enabled, "--output", output])).rejects.toMatchObject({
      code: 2,
    });
    await expect(checkReview(enabled, ["--output", output])).rejects.toMatchObject({ code: 2 });
  }
  expect(await readFile(receipt, "utf8")).toBe(receiptBytes);
  const invalidReceipt = path.join(fixture.workspace, "invalid.review.json");
  await writeFile(
    invalidReceipt,
    receiptBytes.replace('"scope": "advisory-only"', '"scope": "enforced"'),
  );
  await expect(invoke(["review-check", invalidReceipt, enabled])).rejects.toMatchObject({
    code: 2,
    stdout: "",
  });

  const comparisonPath = path.join(fixture.workspace, "graph-comparison.json");
  await compare(bytesChanged, enabled, ["--format", "json", "--output", comparisonPath]);
  expect(await readFile(comparisonPath, "utf8")).toBe(String(declarationResult.stdout));
  for (const output of [fixture.baseline, enabled, comparisonPath]) {
    await expect(compare(fixture.baseline, enabled, ["--output", output])).rejects.toMatchObject({
      code: 2,
    });
  }
  expect(await readFile(fixture.baseline, "utf8")).toBe(originalBaseline);
  expect(await readFile(comparisonPath, "utf8")).toBe(String(declarationResult.stdout));

  await writeFile(fixture.config, "[broken\n");
  const incomplete = path.join(fixture.workspace, "incomplete.graph.json");
  await expect(capture(incomplete)).rejects.toMatchObject({ code: 2 });
  await expect(compare(enabled, incomplete, ["--format", "json"])).rejects.toMatchObject({
    code: 2,
    stdout: expect.stringContaining('"status": "incomplete"'),
  });
  await expect(compare(incomplete, incomplete)).rejects.toMatchObject({
    code: 2,
    stdout: expect.stringContaining("Result: incomplete"),
  });
  await expect(checkReview(incomplete, ["--format", "json"])).rejects.toMatchObject({
    code: 2,
    stdout: expect.stringContaining('"status": "cannot-check"'),
  });
  await expect(invoke(["review-record", incomplete])).rejects.toMatchObject({
    code: 2,
    stdout: "",
  });

  await Promise.all([
    writeFile(manifest, originalSkill),
    writeFile(fixture.config, originalConfig),
  ]);
  const restored = path.join(fixture.workspace, "restored.graph.json");
  await capture(restored);
  const restoration = await compare(fixture.baseline, restored, ["--format", "json"]);
  expect(JSON.parse(String(restoration.stdout))).toMatchObject({
    complete: true,
    status: "unchanged",
  });
  const restoredReceipt = path.join(fixture.workspace, "restored.review.json");
  await invoke(["review-record", restored, "--format", "json", "--output", restoredReceipt]);
  const fresh = path.join(fixture.workspace, "current.graph.json");
  await capture(fresh);
  const retainedCheck = await invoke(["review-check", restoredReceipt, fresh]);
  expect(String(retainedCheck.stdout)).toContain("Review result: matches-evidence");
  expect(await readFile(receipt, "utf8")).toBe(receiptBytes);
  expect(await readFile(restoredReceipt, "utf8")).toBe(receiptBytes);
}

async function assertLocalReadmeLinks(
  readme: string,
  installedRoot: string,
  linkBase = installedRoot,
): Promise<void> {
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
    const target = path.resolve(linkBase, relativeTarget);
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
) {
  if (process.platform === "win32") {
    return run(process.execPath, [installedCli, ...args], cwd);
  }
  return run(installedShim, args, cwd);
}

async function run(
  entrypoint: string,
  args: readonly string[],
  cwd: string,
  environment: NodeJS.ProcessEnv = {},
) {
  return execFileAsync(entrypoint, [...args], {
    cwd,
    encoding: "utf8",
    env: { ...process.env, ...environment, NO_UPDATE_NOTIFIER: "1" },
    maxBuffer: 10 * 1024 * 1024,
  });
}

function sha256(content: Buffer): string {
  return createHash("sha256").update(content).digest("hex");
}
