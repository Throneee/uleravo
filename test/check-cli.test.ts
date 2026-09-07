import { spawnSync } from "node:child_process";
import { access, lstat, mkdir, mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { afterAll, beforeAll, expect, it } from "vitest";

const repository = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
let build: string;
let root: string;
let project: string;
let guard: string;
let marker: string;
let env: NodeJS.ProcessEnv;
beforeAll(async () => {
  root = await mkdtemp(path.join(os.tmpdir(), "uleravo-check-cli-"));
  project = path.join(root, "project");
  const home = path.join(root, "synthetic-home");
  await mkdir(project);
  await mkdir(home);
  env = Object.fromEntries(
    Object.entries(process.env).filter(([key]) =>
      /^(PATH|SYSTEMROOT|WINDIR|COMSPEC|PATHEXT|SYSTEMDRIVE|NUMBER_OF_PROCESSORS|PROCESSOR_ARCHITECTURE)$/i.test(
        key,
      ),
    ),
  );
  Object.assign(env, {
    HOME: home,
    USERPROFILE: home,
    APPDATA: home,
    LOCALAPPDATA: home,
    TMP: root,
    TEMP: root,
    NO_COLOR: "1",
  });
  const cache = path.join(repository, "node_modules/.cache");
  await mkdir(cache, { recursive: true });
  build = await mkdtemp(path.join(cache, "uleravo-check-cli-"));
  const compiled = spawnSync(
    process.execPath,
    ["node_modules/typescript/bin/tsc", "-p", "tsconfig.build.json", "--outDir", build],
    {
      cwd: repository,
      env,
      encoding: "utf8",
      timeout: 30000,
    },
  );
  expect(compiled.status, compiled.stdout + compiled.stderr).toBe(0);
  guard = path.join(root, "guard.mjs");
  marker = path.join(root, "forbidden-effect");
  await writeFile(
    guard,
    `
import fs from "node:fs";
import fsp from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import child from "node:child_process";
import http from "node:http";
import https from "node:https";
import net from "node:net";
import { syncBuiltinESMExports } from "node:module";
const mark = fs.writeFileSync;
const forbidden = () => { mark(${JSON.stringify(marker)}, "attempted"); throw new Error("Forbidden side effect"); };
globalThis.fetch = forbidden;
os.homedir = forbidden;
for (const name of ["exec", "execFile", "spawn", "fork", "execSync", "execFileSync", "spawnSync"]) child[name] = forbidden;
for (const mod of [http, https]) for (const name of ["get", "request"]) mod[name] = forbidden;
net.connect = net.createConnection = net.Socket.prototype.connect = forbidden;
fs.watch = fsp.watch = forbidden;
const normalized = (value) => path.resolve(value instanceof URL ? fileURLToPath(value) : String(value)).toLowerCase();
const modules = normalized(${JSON.stringify(path.join(repository, "node_modules"))}) + path.sep;
const allowed = new Set(${JSON.stringify([".mcp.json", ".claude/settings.json", ".claude/settings.local.json", ".cursor/mcp.json", ".codex/config.toml"].map((file) => path.join(project, file)))}.map(normalized));
const metadata = new Set(allowed);
for (const file of allowed) {
  let current = path.dirname(file);
  for (;;) {
    metadata.add(current);
    const parent = path.dirname(current);
    if (parent === current) break;
    current = parent;
  }
}
// Selected-API regression guard, NOT an OS sandbox. Only the direct Node
// module-loader caller gets module-tree reads; application reads do not.
const moduleLoader = () => {
  const caller = new Error().stack?.split("\\n").slice(3).find((line) => !/\\(node:fs:|\\(node:internal\\/fs\\//.test(line));
  return /node:internal\\/modules\\//.test(caller ?? "");
};
const noTargetIO = process.env.CHECK_TEST_NO_TARGET_IO === "1";
const entrypoint = normalized(${JSON.stringify(path.join(build, "cli.js"))});
const metadataGuard = (original, name) => function(file, ...args) {
  const resolved = normalized(file);
  // CLI startup compares exactly its own entrypoint via realpath; not target I/O.
  if (name === "realpath" && resolved === entrypoint) return original.call(this, file, ...args);
  if (!(resolved.startsWith(modules) && moduleLoader()) && (noTargetIO || !metadata.has(resolved))) return forbidden();
  return original.call(this, file, ...args);
};
for (const name of ["lstat", "stat", "realpath", "access", "readlink", "readdir", "opendir"]) fsp[name] = metadataGuard(fsp[name], name);
for (const name of ["lstat", "stat", "realpath", "access", "readlink", "readdir", "opendir", "lstatSync", "statSync", "realpathSync", "accessSync", "readlinkSync", "readdirSync", "opendirSync"]) {
  const original = fs[name];
  fs[name] = metadataGuard(original, name);
  if (original.native) fs[name].native = metadataGuard(original.native, name);
}
const readOnly = (flag = "r") => typeof flag === "number"
  ? !(flag & (fs.constants.O_WRONLY | fs.constants.O_RDWR | fs.constants.O_APPEND | fs.constants.O_CREAT | fs.constants.O_TRUNC))
  : ["r", "rs", "sr"].includes(flag);
const readGuard = (original, name) => function(file, ...args) {
  const flag = name.startsWith("open") ? args[0] : args[0]?.flag ?? args[0]?.flags;
  if (!readOnly(flag)) return forbidden();
  const resolved = normalized(file);
  if (!(resolved.startsWith(modules) && moduleLoader()) && (noTargetIO || !allowed.has(resolved))) return forbidden();
  return original.call(this, file, ...args);
};
for (const name of ["open", "readFile"]) fsp[name] = readGuard(fsp[name], name);
for (const name of ["open", "readFile", "openSync", "readFileSync", "createReadStream"]) fs[name] = readGuard(fs[name], name);
for (const name of ["writeFile", "appendFile", "rename", "unlink", "rm", "rmdir", "mkdir", "mkdtemp", "copyFile", "cp", "truncate", "chmod", "chown", "lchown", "utimes", "lutimes", "link", "symlink"]) {
  fsp[name] = forbidden;
  fs[name] = fs[name + "Sync"] = forbidden;
}
for (const name of ["write", "writev", "ftruncate", "fchmod", "fchown", "futimes"]) fs[name] = fs[name + "Sync"] = forbidden;
fs.createWriteStream = forbidden;
syncBuiltinESMExports();
const syntheticCwd = process.env.CHECK_TEST_CWD;
// Contract double: only JS cwd changes. The OS child cwd stays the benign fixture.
if (syntheticCwd !== undefined) process.cwd = () => syntheticCwd;
const originalEnv = process.env;
process.env = new Proxy(originalEnv, { get(target, key) {
  if (typeof key === "string" && /TOKEN|SECRET|PASSWORD|API_KEY/.test(key)) return forbidden();
  return Reflect.get(target, key);
} });
`,
  );
}, 40000);
afterAll(async () => {
  if (build) await rm(build, { force: true, recursive: true });
  if (root) await rm(root, { force: true, recursive: true });
});
function cli(args: string[], overrides: NodeJS.ProcessEnv = {}) {
  return spawnSync(
    process.execPath,
    ["--import", pathToFileURL(guard).href, path.join(build, "cli.js"), ...args],
    {
      cwd: project,
      env: { ...env, ...overrides },
      encoding: "utf8",
      timeout: 5000,
    },
  );
}

// Post-fix compiled acceptance, separate from source RED/GREEN evidence.
it.each([
  String.raw`\\fixture.invalid\share\project`,
  "//fixture.invalid/share/project",
  String.raw`/\fixture.invalid\share\project`,
  String.raw`\/fixture.invalid/share/project`,
  String.raw`\\?\UNC\fixture.invalid\share\project`,
  String.raw`\\.\UNC\fixture.invalid\share\project`,
  String.raw`\\?\C:\project`,
  String.raw`\\.\C:\project`,
  String.raw`\??\UNC\fixture.invalid\share\project`,
  String.raw`\Device\Mup\fixture.invalid\share\project`,
  String.raw`\GLOBAL??\UNC\fixture.invalid\share\project`,
  "/??/UNC/fixture.invalid/share",
  "/Device/Mup/fixture.invalid/share",
  "/GLOBAL??/UNC/fixture.invalid/share",
  "/DosDevices/UNC/fixture.invalid/share",
  "Z:project",
  "Z:",
  "file://fixture.invalid/share/project",
  "smb://fixture.invalid/share",
])("compiled rejects unsupported target syntax with zero target I/O: %j", async (target) => {
  const result = cli(["check", target], { CHECK_TEST_NO_TARGET_IO: "1" });
  expect(result.status, result.stderr).toBe(2);
  expect(result.stdout).toContain("Unsupported local target syntax");
  expect(result.stdout + result.stderr).not.toContain("fixture.invalid");
  await expect(access(marker)).rejects.toMatchObject({ code: "ENOENT" });
});

it.each([
  String.raw`\\fixture.invalid\share\project`,
  "//fixture.invalid/share/project",
  String.raw`\\?\UNC\fixture.invalid\share\project`,
  String.raw`\Device\Mup\fixture.invalid\share\project`,
])("compiled rejects a controlled cwd-contract double with zero target I/O: %j", async (cwd) => {
  for (const args of [[], ["."], [project]]) {
    const result = cli(["check", ...args], { CHECK_TEST_NO_TARGET_IO: "1", CHECK_TEST_CWD: cwd });
    expect(result.status, result.stderr).toBe(2);
    expect(result.stdout).toContain("Unsupported local target syntax");
    await expect(access(marker)).rejects.toMatchObject({ code: "ENOENT" });
  }
});

it("exercises the compiled fresh check/edit/recheck and wire contract under selected API guards", async () => {
  const file = path.join(project, ".codex/config.toml");
  await mkdir(path.dirname(file));
  const beforeText = 'sandbox_mode = "danger-full-access"\n';
  await writeFile(file, beforeText);
  const beforeWire = cli(["monitor", "--project", project]);
  expect(beforeWire.status, beforeWire.stderr).toBe(0);
  const first = cli(["check"]);
  expect(first.status, JSON.stringify({ stdout: first.stdout, stderr: first.stderr })).toBe(1);
  expect(first.stdout).toContain("[HIGH] Unrestricted sandbox declared");
  expect(first.stdout).toContain("project .codex/config.toml :: sandbox_mode");
  expect(first.stdout).toContain("Manual next step: Restrict sandbox access");
  expect(first.stdout).not.toMatch(/[a-f0-9]{64}/);
  expect(await readFile(file, "utf8")).toBe(beforeText);
  const afterWire = cli(["monitor", "--project", project]);
  expect(afterWire.status, afterWire.stderr).toBe(0);
  const before = JSON.parse(beforeWire.stdout);
  const after = JSON.parse(afterWire.stdout);
  for (const field of ["schemaVersion", "complete", "projectId", "configurations", "findings"])
    expect(after[field]).toEqual(before[field]);
  expect(Object.keys(after)).toEqual(Object.keys(before));
  expect(afterWire.stdout).not.toMatch(
    /Location|selector|sandbox_mode|config.toml|Manual|severity|title/,
  );
  await writeFile(file, 'sandbox_mode = "read-only"\n');
  const recheck = cli(["check", project]);
  expect(recheck.status, recheck.stderr).toBe(0);
  expect(recheck.stdout).toContain("No supported declaration findings observed");
  expect(recheck.stdout).toContain("not verification of security or resolution");
  await writeFile(file, "sandbox_mode = [");
  expect(cli(["check"]).status).toBe(2);
  await rm(file);
  const empty = cli(["check"]);
  expect(empty.status).toBe(2);
  expect(empty.stdout).toContain("No coverage");
  for (const args of [
    ["--upload"],
    [project, "--watch"],
    ["--include-user"],
    ["--token-env", "CHECK_TOKEN"],
  ]) {
    const invalid = cli(["check", ...args]);
    expect(invalid.status).toBe(2);
    expect(invalid.stdout).toBe("");
    expect(invalid.stderr).toContain("Invalid check arguments");
  }
  await expect(access(marker)).rejects.toMatchObject({ code: "ENOENT" });
}, 30000);

it("compiled rejects an actual benign local junction or symlink target", async () => {
  const destination = path.join(root, "local-link-destination");
  const link = path.join(project, ".cursor");
  await mkdir(destination);
  await symlink(destination, link, process.platform === "win32" ? "junction" : "dir");
  expect((await lstat(link)).isSymbolicLink()).toBe(true);
  const result = cli(["check", link]);
  expect(result.status, result.stderr).toBe(2);
  expect(result.stdout).toContain("Target is a symbolic link or junction");
  await expect(access(marker)).rejects.toMatchObject({ code: "ENOENT" });
  await rm(link);
});

it("compiled renders the multi-harness canary then withholds all locations on incomplete capture", async () => {
  const canary = "CHECK_COMPILED_CANARY\u001b[2J\u202e";
  const fixtures: [string, string][] = [
    [
      ".claude/settings.json",
      JSON.stringify({ permissions: { defaultMode: "bypassPermissions", allow: ["Bash(*)"] } }),
    ],
    [
      ".cursor/mcp.json",
      JSON.stringify({
        mcpServers: {
          disabled: { disabled: true, token: canary },
          [canary]: {
            command: "npx",
            args: [canary],
            url: "http://fixture.invalid",
            token: canary,
          },
        },
      }),
    ],
    [".codex/config.toml", 'sandbox_mode = "danger-full-access"'],
  ];
  for (const [file, text] of fixtures) {
    await mkdir(path.dirname(path.join(project, file)), { recursive: true });
    await writeFile(path.join(project, file), text);
  }
  const result = cli(["check"]);
  expect(result.status, result.stderr).toBe(1);
  expect(result.stdout).toContain("6 declarations need review");
  expect(result.stdout).toContain("claude-code/project, cursor/project, codex/project");
  expect(result.stdout).toContain("mcpServers entry #2");
  expect(result.stdout.match(/Location:/g)).toHaveLength(6);
  expect(result.stdout + result.stderr).not.toMatch(
    /CHECK_COMPILED_CANARY|fixture\.invalid|\u202e|[a-f0-9]{64}/,
  );
  expect(result.stdout + result.stderr).not.toContain("\u001b");
  await writeFile(
    path.join(project, ".mcp.json"),
    JSON.stringify({ mcpServers: { inert: { command: [] } } }),
  );
  const incomplete = cli(["check"]);
  expect(incomplete.status, incomplete.stderr).toBe(2);
  expect(incomplete.stdout).toContain("Incomplete review");
  expect(incomplete.stdout).not.toMatch(/Location:|No supported declaration findings/);
  await expect(access(marker)).rejects.toMatchObject({ code: "ENOENT" });
  for (const file of [...fixtures.map(([file]) => file), ".mcp.json"])
    await rm(path.join(project, file));
}, 30000);

it("positive-controls compiled metadata tripwires on a benign synthetic-home directory", async () => {
  for (const module of ["node:fs/promises", "node:fs"]) {
    for (const method of module.endsWith("promises")
      ? ["lstat", "stat", "realpath"]
      : ["lstat", "stat", "realpath", "lstatSync", "statSync", "realpathSync"]) {
      const callback = module === "node:fs" && !method.endsWith("Sync") ? ", () => {}" : "";
      const script = `const fs = await import(${JSON.stringify(module)}); await fs[${JSON.stringify(method)}](${JSON.stringify(env.HOME)}${callback});`;
      const result = spawnSync(
        process.execPath,
        ["--import", pathToFileURL(guard).href, "--input-type=module", "-e", script],
        { cwd: project, env, encoding: "utf8", timeout: 5000 },
      );
      expect(result.status, `${module}.${method}: ${result.stderr}`).not.toBe(0);
      expect(await readFile(marker, "utf8")).toBe("attempted");
      await rm(marker);
    }
  }
}, 30000);

it("positive-controls compiled mutation tripwires using disposable project files", async () => {
  for (const module of ["node:fs/promises", "node:fs"]) {
    for (const [method, args] of [
      ["writeFile", "'.mcp.json', 'changed'"],
      ["appendFile", "'.mcp.json', 'changed'"],
      ["rename", "'.mcp.json', 'renamed'"],
      ["unlink", "'.mcp.json'"],
      ["rm", "'.mcp.json'"],
      ["open", "'.mcp.json', 'r+'"],
    ]) {
      for (const suffix of module === "node:fs" ? ["", "Sync"] : [""]) {
        await writeFile(path.join(project, ".mcp.json"), "inert");
        const callback = module === "node:fs" && !suffix ? ", () => {}" : "";
        const script = `const fs = await import(${JSON.stringify(module)}); await fs.${method}${suffix}(${args}${callback});`;
        const result = spawnSync(
          process.execPath,
          ["--import", pathToFileURL(guard).href, "--input-type=module", "-e", script],
          { cwd: project, env, encoding: "utf8", timeout: 5000 },
        );
        expect(result.status, `${module}.${method}${suffix}: ${result.stderr}`).not.toBe(0);
        expect(await readFile(marker, "utf8")).toBe("attempted");
        expect(await readFile(path.join(project, ".mcp.json"), "utf8")).toBe("inert");
        await rm(marker);
      }
    }
  }
  await rm(path.join(project, ".mcp.json"));
}, 30000);

it("does not grant arbitrary application reads just because a file is under node_modules", async () => {
  const moduleFile = path.join(repository, "node_modules/typescript/package.json");
  for (const method of ["readFile", "lstat", "stat", "realpath"]) {
    const script = `const fs = await import('node:fs/promises'); await fs.${method}(${JSON.stringify(moduleFile)});`;
    const result = spawnSync(
      process.execPath,
      ["--import", pathToFileURL(guard).href, "--input-type=module", "-e", script],
      { cwd: project, env, encoding: "utf8", timeout: 5000 },
    );
    expect(result.status, `${method}: ${result.stderr}`).not.toBe(0);
    expect(await readFile(marker, "utf8")).toBe("attempted");
    await rm(marker);
  }
});

it("positive-controls strict pre-target-I/O mode even for allowed local fixtures", async () => {
  await writeFile(path.join(project, ".mcp.json"), "{}");
  for (const [method, target] of [
    ["lstat", project],
    ["stat", project],
    ["realpath", project],
    ["readFile", path.join(project, ".mcp.json")],
  ]) {
    const script = `const fs = await import('node:fs/promises'); await fs.${method}(${JSON.stringify(target)});`;
    const result = spawnSync(
      process.execPath,
      ["--import", pathToFileURL(guard).href, "--input-type=module", "-e", script],
      {
        cwd: project,
        env: { ...env, CHECK_TEST_NO_TARGET_IO: "1" },
        encoding: "utf8",
        timeout: 5000,
      },
    );
    expect(result.status, `${method}: ${result.stderr}`).not.toBe(0);
    expect(await readFile(marker, "utf8")).toBe("attempted");
    await rm(marker);
  }
  await rm(path.join(project, ".mcp.json"));
});

it("positive-controls selected credential property, fetch, home discovery/content and spawn guards", async () => {
  const homeFixture = path.join(env.HOME ?? root, "home-fixture.txt");
  await writeFile(homeFixture, "inert synthetic home content");
  for (const script of [
    "process.env.CHECK_TOKEN",
    "fetch('https://fixture.invalid')",
    "(await import('node:os')).homedir()",
    "(await import('node:fs/promises')).readFile('SKILL.md')",
    `(await import('node:fs/promises')).readFile(${JSON.stringify(homeFixture)})`,
    "(await import('node:child_process')).spawn('inert-target')",
  ]) {
    const result = spawnSync(
      process.execPath,
      ["--import", pathToFileURL(guard).href, "--input-type=module", "-e", script],
      { cwd: project, env, encoding: "utf8", timeout: 5000 },
    );
    expect(result.status).not.toBe(0);
    expect(await readFile(marker, "utf8")).toBe("attempted");
    await rm(marker);
  }
});
