import * as fs from "node:fs/promises";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { main } from "../src/cli.js";
import * as captures from "../src/monitor/capture.js";
import * as reads from "../src/monitor/read.js";

// A configurable namespace lets tripwires stop metadata BEFORE native I/O.
vi.mock("node:fs/promises", async (original) => ({
  ...(await original<typeof import("node:fs/promises")>()),
}));

function targetIoTripwire() {
  const attempts: string[] = [];
  for (const name of [
    "lstat",
    "stat",
    "realpath",
    "open",
    "readFile",
    "readdir",
    "opendir",
    "access",
    "readlink",
  ] as const) {
    vi.spyOn(fs, name).mockImplementation(() => {
      attempts.push(name);
      throw new Error("Synthetic target I/O tripwire; never call through");
    });
  }
  return attempts;
}

it("rejects explicit UNC and device targets before any target filesystem attempt", async () => {
  const attempts = targetIoTripwire();
  const read = vi.spyOn(reads, "readConfig");
  const directory = vi.spyOn(reads, "checkDirectory");
  for (const target of [
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
  ]) {
    output = "";
    errors = "";
    expect(await main(["check", target])).toBe(2);
    expect(attempts, `target must be rejected lexically: ${target}`).toEqual([]);
    expect(output).toContain("Unsupported local target syntax");
    expect(output + errors).not.toMatch(/fixture\.invalid|share|C:\\project/);
  }
  expect(read).not.toHaveBeenCalled();
  expect(directory).not.toHaveBeenCalled();
  expect(os.homedir).not.toHaveBeenCalled();
});

it("rejects a remote default cwd before target metadata even for relative selection", async () => {
  const attempts = targetIoTripwire();
  for (const cwd of [
    String.raw`\\fixture.invalid\share\project`,
    "//fixture.invalid/share/project",
    String.raw`\\?\UNC\fixture.invalid\share\project`,
    String.raw`\Device\Mup\fixture.invalid\share\project`,
    "bad\npath",
  ]) {
    vi.mocked(process.cwd).mockReturnValue(cwd);
    for (const args of [[], ["."], ["child"], [project]]) {
      output = "";
      expect(await main(["check", ...args])).toBe(2);
      expect(attempts, `cwd must be rejected lexically: ${cwd}`).toEqual([]);
      expect(output).toContain("Unsupported local target syntax");
      expect(output).not.toContain("fixture.invalid");
    }
  }
});

it("rejects ambiguous drive-relative, URI and slash-device syntax before resolution I/O", async () => {
  const attempts = targetIoTripwire();
  for (const target of [
    "Z:project",
    "Z:",
    "file://fixture.invalid/share/project",
    "smb://fixture.invalid/share",
    "/??/UNC/fixture.invalid/share",
    "/Device/Mup/fixture.invalid/share",
    "/GLOBAL??/UNC/fixture.invalid/share",
    "/DosDevices/UNC/fixture.invalid/share",
  ]) {
    output = "";
    expect(await main(["check", target])).toBe(2);
    expect(attempts, `unsupported syntax: ${target}`).toEqual([]);
    expect(output).toContain("Unsupported local target syntax");
  }
});

it("positive-controls each source target metadata/content tripwire without calling through", () => {
  const attempts = targetIoTripwire();
  for (const name of [
    "lstat",
    "stat",
    "realpath",
    "open",
    "readFile",
    "readdir",
    "opendir",
    "access",
    "readlink",
  ] as const) {
    // biome-ignore lint/performance/noDynamicNamespaceImportAccess: Positive-control each mocked API.
    expect(() => Reflect.apply(fs[name], fs, [project])).toThrow("Synthetic target I/O tripwire");
    expect(attempts.pop()).toBe(name);
  }
  expect(attempts).toEqual([]);
});

it.each([".", "./", "child/.."])("accepts ordinary local relative syntax %s", async (target) => {
  await fixture(".codex/config.toml", 'sandbox_mode = "read-only"');
  await mkdir(path.join(project, "child"));
  expect(await main(["check", target])).toBe(0);
  expect(output).toContain("Covered configuration groups: codex/project");
});

it("explains the lexical local-storage limitation in check help", async () => {
  const attempts = targetIoTripwire();
  expect(await main(["check", "--help"])).toBe(0);
  expect(output).toContain("UNC/device and drive-relative paths are unsupported");
  expect(output).toContain(
    "Mapped drives, network mounts and ancestor redirects are not identified",
  );
  expect(output).toContain("Use stable local storage; this is not OS network isolation");
  expect(attempts).toEqual([]);
});

let project: string;
let output: string;
let errors: string;
beforeEach(async () => {
  project = await mkdtemp(path.join(os.tmpdir(), "uleravo-check-"));
  vi.spyOn(os, "homedir").mockReturnValue(path.join(project, "synthetic-home"));
  vi.spyOn(process, "cwd").mockReturnValue(project);
  output = "";
  errors = "";
  vi.spyOn(process.stdout, "write").mockImplementation((text) => {
    output += text;
    return true;
  });
  vi.spyOn(process.stderr, "write").mockImplementation((text) => {
    errors += text;
    return true;
  });
});
afterEach(async () => {
  vi.restoreAllMocks();
  await rm(project, { recursive: true, force: true });
});
async function fixture(file: string, value: unknown) {
  const dest = path.join(project, file);
  await mkdir(path.dirname(dest), { recursive: true });
  await writeFile(dest, typeof value === "string" ? value : JSON.stringify(value));
}

it.each([
  ["--include-user"],
  ["--upload"],
  ["--watch"],
  ["--endpoint", "https://fixture.invalid"],
  ["--token-env", "CHECK_TOKEN"],
  ["--format", "json"],
  ["one", "two"],
  [""],
  ["bad\npath"],
])(
  "rejects unsupported arguments before home, credential or configuration reads: %j",
  async (...args: string[]) => {
    const attempts = targetIoTripwire();
    const read = vi.spyOn(reads, "readConfig");
    const directory = vi.spyOn(reads, "checkDirectory");
    const network = vi.spyOn(globalThis, "fetch").mockRejectedValue(new Error("network forbidden"));
    const env = process.env;
    let credentials = 0;
    process.env = new Proxy(env, {
      get(target, key) {
        if (typeof key === "string" && /TOKEN|SECRET|PASSWORD|API_KEY/.test(key)) credentials++;
        return Reflect.get(target, key);
      },
    });
    try {
      expect(await main(["check", ...args])).toBe(2);
    } finally {
      process.env = env;
    }
    expect(attempts).toEqual([]);
    expect(output).toBe("");
    expect(errors).toContain("Invalid check arguments");
    expect(errors).not.toContain("fixture.invalid");
    expect(read).not.toHaveBeenCalled();
    expect(directory).not.toHaveBeenCalled();
    expect(os.homedir).not.toHaveBeenCalled();
    expect(network).not.toHaveBeenCalled();
    expect(credentials).toBe(0);
  },
);

it("keeps authoritative findings nonzero when a controlled capture-contract double withholds locators", async () => {
  await fixture(".claude/settings.json", {
    permissions: { defaultMode: "bypassPermissions", allow: ["Bash(*)"] },
  });
  const realCapture = captures.capture;
  const capture = vi.spyOn(captures, "capture");
  // Contract double only: the real parser/snapshot is unchanged; deliberately
  // suppress zero/all-but-one observations to model a future privacy filter.
  for (const keep of [0, 1]) {
    let observed = 0;
    capture.mockImplementation((options, observe) =>
      realCapture(options, (item) => {
        if (observed++ < keep) observe?.(item);
      }),
    );
    output = "";
    expect(await main(["check", project])).toBe(1);
    expect(output).toContain("2 declarations need review.");
    expect(output).toContain(
      `Incomplete local presentation: ${2 - keep} finding location(s) unavailable`,
    );
    expect(output.match(/Location:/g) ?? []).toHaveLength(keep);
    expect(output).not.toContain("No supported declaration findings");
    expect(observed).toBe(2);
  }
});

it("keeps fresh monitor identity and wire fields unchanged after local check", async () => {
  await fixture(".cursor/mcp.json", {
    mcpServers: {
      "CHECK_CANARY\u001b[2J\u202e": {
        token: "CHECK_CANARY",
        command: "npx",
        args: ["CHECK_CANARY"],
      },
    },
  });
  const normal = async () => {
    let wire = "";
    const log = vi.spyOn(console, "log").mockImplementation((line: string) => {
      wire = line;
    });
    const code = await main(["monitor", "--project", project]);
    log.mockRestore();
    expect(code).toBe(0);
    return JSON.parse(wire);
  };
  const before = await normal();
  output = "";
  errors = "";
  expect(await main(["check", project])).toBe(1);
  expect(output).toContain("mcpServers entry #1");
  expect(output + errors).not.toMatch(/CHECK_CANARY|\u202e/);
  expect(output + errors).not.toContain("\u001b");
  const after = await normal();
  expect(after.findings).toEqual(before.findings);
  expect(after.configurations).toEqual(before.configurations);
  expect(after.projectId).toBe(before.projectId);
  expect(Object.keys(after).sort()).toEqual([
    "captureId",
    "capturedAt",
    "complete",
    "configurations",
    "findings",
    "projectId",
    "schemaVersion",
  ]);
  for (const finding of after.findings)
    expect(Object.keys(finding).sort()).toEqual(["harness", "id", "ruleId", "scope", "subjectId"]);
  expect(JSON.stringify(after)).not.toMatch(
    /CHECK_CANARY|mcp.json|selector|Location|severity|title|Manual/,
  );
  expect(os.homedir).not.toHaveBeenCalled();
});

it("offers check in root help and documents its separate local exit contract", async () => {
  expect(await main(["--help"])).toBe(0);
  expect(output).toContain("uleravo check [project]");
  output = "";
  expect(await main(["check", "--help"])).toBe(0);
  expect(output).toContain("current directory");
  expect(output).toContain("Exit 0");
  expect(output).toContain("1 for findings");
  expect(output).toContain("2 for invalid target, no coverage or incomplete review");
  expect(os.homedir).not.toHaveBeenCalled();
});

it.each([
  ["malformed-json", '{"mcpServers":', ".mcp.json"],
  ["malformed-field", { mcpServers: { target: { command: [] } } }, ".mcp.json"],
  ["malformed-toml", "sandbox_mode = [", ".codex/config.toml"],
  ["oversized", " ".repeat(256 * 1024 + 1), ".mcp.json"],
])("withholds locations and calls out incomplete coverage for %s", async (_name, value, file) => {
  await fixture(String(file), value);
  await fixture(".cursor/mcp.json", { mcpServers: { target: { token: "CHECK_CANARY" } } });
  expect(await main(["check", project]), errors).toBe(2);
  expect(output).toContain("Incomplete review");
  expect(output).toContain("Malformed, unreadable, unsafe or over-limit configuration");
  expect(output).toContain("Manual next step:");
  expect(output).toContain("local finding locations withheld");
  expect(output).not.toMatch(/Location:|\[HIGH\]|0 declarations|No supported declaration findings/);
});

it.each([false, true])(
  "reports no coverage, including an unsupported Skill-only target (%s)",
  async (skillOnly) => {
    if (skillOnly) await fixture("SKILL.md", "# Inert Skill\nNothing is executed.");
    expect(await main(["check", project]), errors).toBe(2);
    expect(output).toContain("Covered configuration groups: none");
    expect(output).toContain("No coverage: no supported project configuration files were read");
    expect(output).toContain("Skill content is unsupported by check");
    expect(output).toContain(".codex/config.toml");
    expect(output).toContain("Manual next step:");
    expect(output).not.toMatch(/0 declarations|clean|safe project/i);
  },
);

it.each(["missing", "file"])("identifies a %s target without echoing its path", async (kind) => {
  const target = path.join(project, "PRIVATE_TARGET");
  if (kind === "file") await writeFile(target, "inert");
  expect(await main(["check", target]), errors).toBe(2);
  expect(output).toContain(
    kind === "missing" ? "Target does not exist" : "Target is not a directory",
  );
  expect(output).toContain("Covered configuration groups: none");
  expect(output).toContain("Manual next step:");
  expect(output + errors).not.toContain("PRIVATE_TARGET");
});

it("reports fresh non-observation after a manual edit without claiming resolution", async () => {
  await fixture(".codex/config.toml", 'sandbox_mode = "danger-full-access"');
  expect(await main(["check", project])).toBe(1);
  expect(output).toContain("1 declaration needs review.");
  output = "";
  await fixture(".codex/config.toml", 'sandbox_mode = "read-only"');
  expect(await main(["check", project])).toBe(0);
  expect(output).toContain("Covered configuration groups: codex/project");
  expect(output).toContain("Not covered (missing): claude-code/project, cursor/project");
  expect(output).toContain("No supported declaration findings observed in the covered groups");
  expect(output).toContain("not verification of security or resolution");
  expect(output).not.toContain("Unrestricted sandbox declared");
});

it("checks the current project with prioritized actionable declarations, without IDs", async () => {
  await fixture(".claude/settings.json", {
    permissions: { defaultMode: "bypassPermissions", allow: ["Bash(*)"] },
  });
  await fixture(".codex/config.toml", 'sandbox_mode = "danger-full-access"');
  await fixture(".cursor/mcp.json", {
    mcpServers: {
      disabled: { disabled: true, token: "CHECK_CANARY" },
      CHECK_CANARY: {
        command: "npx",
        args: ["inert-fixture"],
        url: "http://fixture.invalid",
        token: "CHECK_CANARY",
      },
    },
  });
  expect(await main(["check"]), errors).toBe(1);
  expect(output).toContain("Declaration review, not runtime protection");
  expect(output).toContain(
    "Covered configuration groups: claude-code/project, cursor/project, codex/project",
  );
  expect(output).toContain("6 declarations need review");
  expect(output).toContain("[HIGH] Permission prompts bypassed");
  expect(output).toContain("[HIGH] Unrestricted sandbox declared");
  expect(output).toContain("[HIGH] Literal credential in configuration");
  expect(output).toContain("[HIGH] Broad automatic shell approval");
  expect(output).toContain("[MEDIUM] Unpinned package launcher");
  expect(output).toContain("[MEDIUM] Unencrypted remote MCP connection");
  expect(output.indexOf("[HIGH] Literal credential")).toBeLessThan(output.indexOf("[MEDIUM]"));
  expect(output).toContain("project .claude/settings.json :: /permissions/defaultMode");
  expect(output).toContain("project .codex/config.toml :: sandbox_mode");
  expect(output).toContain("project .cursor/mcp.json :: mcpServers entry #2");
  expect(output.match(/Why:/g)).toHaveLength(6);
  expect(output.match(/Manual next step:/g)).toHaveLength(6);
  expect(output).toContain("Pin a reviewed exact package version");
  expect(output).toContain("uleravo check");
  expect(output + errors).not.toMatch(/CHECK_CANARY|fixture.invalid|[a-f0-9]{64}/);
  expect(output).not.toContain(project);
  expect(await readFile(path.join(project, ".codex/config.toml"), "utf8")).toBe(
    'sandbox_mode = "danger-full-access"',
  );
  expect(os.homedir).not.toHaveBeenCalled();
});
