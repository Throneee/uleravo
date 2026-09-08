import { spawnSync } from "node:child_process";
import { access, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { afterAll, beforeAll, expect, it } from "vitest";

const repository = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
let build: string;
let project: string;
let guard: string;
let marker: string;
const canary = "COMPILED_LOCAL_CANARY_NEVER_PRINT";
beforeAll(async () => {
  const cache = path.join(repository, "node_modules/.cache");
  await mkdir(cache, { recursive: true });
  build = await mkdtemp(path.join(cache, "uleravo-explain-cli-"));
  project = await mkdtemp(path.join(os.tmpdir(), "uleravo-explain-cli-"));
  const result = spawnSync(
    process.execPath,
    ["node_modules/typescript/bin/tsc", "-p", "tsconfig.build.json", "--outDir", build],
    { cwd: repository, encoding: "utf8", timeout: 30000 },
  );
  expect(result.status, result.stdout + result.stderr).toBe(0);
  guard = path.join(project, "guard.mjs");
  marker = path.join(project, "forbidden-effect");
  await writeFile(
    guard,
    `
import { writeFileSync } from "node:fs";
import os from "node:os";
import childProcess from "node:child_process";
import { syncBuiltinESMExports } from "node:module";
const forbidden = () => { writeFileSync(${JSON.stringify(marker)}, "attempted"); throw new Error("Forbidden side effect"); };
globalThis.fetch = forbidden;
for (const name of ["exec", "execFile", "spawn", "fork", "execSync", "execFileSync", "spawnSync"]) childProcess[name] = forbidden;
os.homedir = () => ${JSON.stringify(path.join(project, "synthetic-home"))};
syncBuiltinESMExports();
const env = process.env;
process.env = new Proxy(env, { get(target, key) { if (key === "EXPLAIN_TEST_TOKEN") return forbidden(); return Reflect.get(target, key); } });
`,
  );
}, 40000);
afterAll(async () => {
  if (build) await rm(build, { recursive: true, force: true });
  if (project) await rm(project, { recursive: true, force: true });
});
function cli(args: string[]) {
  return spawnSync(
    process.execPath,
    [
      "--import",
      pathToFileURL(guard).href,
      path.join(build, "cli.js"),
      "monitor",
      "--project",
      project,
      "--token-env",
      "EXPLAIN_TEST_TOKEN",
      ...args,
    ],
    { cwd: project, encoding: "utf8", timeout: 5000 },
  );
}

it("runs compiled local explanation with no credential, network, target execution or wire changes", async () => {
  const file = path.join(project, ".cursor/mcp.json");
  await mkdir(path.dirname(file), { recursive: true });
  const content = JSON.stringify({
    mcpServers: {
      disabled: { disabled: true, token: canary },
      [`${canary}\u001b[2J`]: {
        command: "npx",
        args: [canary],
        url: `http://fixture.invalid/${canary}`,
        token: canary,
      },
    },
  });
  await writeFile(file, content);
  const normal = cli([]);
  expect(normal.status, normal.stderr).toBe(0);
  const before = JSON.parse(normal.stdout);
  const subject = before.findings[0].subjectId;
  const explained = cli(["--explain", subject]);
  expect(explained.status, explained.stderr).toBe(0);
  expect(explained.stdout).toContain("LOCAL-ONLY explanation (not telemetry)");
  expect(explained.stdout).toContain("project .cursor/mcp.json :: mcpServers entry #2");
  expect(explained.stdout).toContain("CFG003:");
  expect(explained.stdout).toContain("CFG004:");
  expect(explained.stdout).toContain("CFG005:");
  expect(explained.stdout + explained.stderr).not.toContain(canary);
  expect(explained.stdout + explained.stderr).not.toContain(project);
  expect(explained.stdout).not.toContain("\u001b");
  for (const args of [
    ["--explain"],
    ["--explain", "A".repeat(64)],
    ["--explain", "a".repeat(63)],
    ["--explain", subject, "--upload", "--endpoint", "https://fixture.invalid/api/ingest"],
    ["--explain", subject, "--watch"],
  ]) {
    const invalid = cli(args);
    expect(invalid.status, invalid.stderr).toBe(2);
    expect(invalid.stdout).toBe("");
    expect(invalid.stderr).toContain("Invalid monitor arguments");
  }
  const after = JSON.parse(cli([]).stdout);
  expect(after.findings).toEqual(before.findings);
  expect(after.configurations).toEqual(before.configurations);
  expect(Object.keys(after)).toEqual(Object.keys(before));
  expect(JSON.stringify(after)).not.toMatch(/selector|mcp.json|LOCAL_CANARY/);
  expect(await readFile(file, "utf8")).toBe(content);
  await expect(access(marker)).rejects.toMatchObject({ code: "ENOENT" });
  await writeFile(file, '{"malformed":');
  const incomplete = cli(["--explain", subject]);
  expect(incomplete.status).toBe(2);
  expect(incomplete.stdout).toContain("Incomplete fresh capture; local locations withheld.");
  expect(incomplete.stdout).not.toContain("mcp.json");
  await writeFile(file, "{}");
  const stale = cli(["--explain", subject]);
  expect(stale.status).toBe(0);
  expect(stale.stdout).toContain("Subject not observed in this fresh capture.");
  expect(stale.stdout).toContain("not verification of security or resolution");
  await expect(access(marker)).rejects.toMatchObject({ code: "ENOENT" });
}, 30000);
