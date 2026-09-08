import { mkdir, mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { stringify as toml } from "smol-toml";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { main } from "../src/cli.js";
import * as reads from "../src/monitor/read.js";
import type { Snapshot } from "../src/monitor/types.js";

let project: string;
let output: string[];
let errors: string[];
beforeEach(async () => {
  project = await mkdtemp(path.join(os.tmpdir(), "uleravo-explain-test-"));
  output = [];
  errors = [];
  vi.spyOn(console, "log").mockImplementation((line: string) => output.push(line));
  vi.spyOn(console, "error").mockImplementation((line: string) => errors.push(line));
});
afterEach(async () => {
  vi.unstubAllEnvs();
  vi.restoreAllMocks();
  await rm(project, { recursive: true, force: true });
});
async function fixture(file: string, value: unknown) {
  const destination = path.join(project, file);
  await mkdir(path.dirname(destination), { recursive: true });
  await writeFile(destination, typeof value === "string" ? value : JSON.stringify(value));
}
async function snapshot(extra: string[] = []): Promise<Snapshot> {
  expect(await main(["monitor", "--project", project, ...extra])).toBe(0);
  const result = JSON.parse(output.at(-1) ?? "null") as Snapshot;
  output.length = 0;
  errors.length = 0;
  return result;
}
async function explain(subject: string, extra: string[] = []) {
  return main(["monitor", "--project", project, "--explain", subject, ...extra]);
}

describe("opt-in local explanation through the CLI", () => {
  it("keeps later upload bytes identical to normal wire stdout after a local explanation", async () => {
    await fixture(".mcp.json", { mcpServers: { target: { token: "LOCAL_CANARY" } } });
    const subject = (await snapshot()).findings[0]?.subjectId ?? "";
    expect(await explain(subject)).toBe(0);
    output.length = 0;
    vi.stubEnv("ULERAVO_TOKEN", "synthetic-device-token");
    const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(
        JSON.stringify({
          accepted: true,
          duplicate: false,
          openFindings: 1,
        }),
      ),
    );
    expect(
      await main([
        "monitor",
        "--project",
        project,
        "--upload",
        "--endpoint",
        "http://127.0.0.1/api/ingest",
      ]),
    ).toBe(0);
    expect(fetchSpy).toHaveBeenCalledOnce();
    expect(fetchSpy.mock.calls[0]?.[1]?.body).toBe(output[0]);
    expect(output).toHaveLength(1);
    expect(output[0]).not.toMatch(/LOCAL_CANARY|mcp.json|selector|LOCAL-ONLY|entry #/);
  });

  it("documents the separate local-only mode in monitor help", async () => {
    expect(await main(["monitor", "--help"])).toBe(0);
    expect(output.join("\n")).toContain("--explain SUBJECT_ID");
    expect(output.join("\n")).toContain("64 lowercase hex");
    expect(output.join("\n")).toContain("not telemetry");
    expect(output.join("\n")).toContain("cannot combine with --upload or --watch");
  });

  it.each([".mcp.json", ".cursor/mcp.json", ".codex/config.toml"])(
    "uses fresh parsed ordinals including disabled entries without rendering hostile labels: %s",
    async (file) => {
      const label = 'LOCAL_CANARY\u001b[2J\r\nhttps://evil.invalid/"/~\u202e';
      const servers = {
        zDisabled: { disabled: true, token: "LOCAL_CANARY" },
        [label]: { token: "LOCAL_CANARY", command: "node" },
        aaa: { command: "node" },
      };
      await fixture(
        file,
        file.endsWith(".toml") ? toml({ mcp_servers: servers }) : { mcpServers: servers },
      );
      const before = await snapshot();
      const subject = before.findings[0]?.subjectId ?? "";
      expect(await explain(subject)).toBe(0);
      expect(output.join("\n")).toContain("entry #2 (parsed key order; label withheld)");
      expect(output.join("\n") + errors.join("\n")).not.toMatch(
        /LOCAL_CANARY|evil.invalid|\r|\u202e|zDisabled|aaa/,
      );
      expect(output.join("\n") + errors.join("\n")).not.toContain("\u001b");
      output.length = 0;
      const reordered = { aaa: servers.aaa, zDisabled: servers.zDisabled, [label]: servers[label] };
      await fixture(
        file,
        file.endsWith(".toml") ? toml({ mcp_servers: reordered }) : { mcpServers: reordered },
      );
      expect(await explain(subject)).toBe(0);
      expect(output.join("\n")).toContain("entry #3 (parsed key order; label withheld)");
      const after = await snapshot();
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
      expect(Object.keys(after.findings[0] ?? {}).sort()).toEqual([
        "harness",
        "id",
        "ruleId",
        "scope",
        "subjectId",
      ]);
      expect(JSON.stringify(after)).not.toMatch(
        /selector|entry #|LOCAL_CANARY|mcp_servers|mcpServers|config.toml|mcp.json/,
      );
    },
  );

  it.each([".claude.json", ".claude/settings.json", ".cursor/mcp.json", ".codex/config.toml"])(
    "requires user opt-in and reports only a home-relative filename for %s",
    async (file) => {
      const home = path.join(project, "synthetic-home");
      const homeSpy = vi.spyOn(os, "homedir").mockReturnValue(home);
      const servers = { target: { token: "LOCAL_CANARY" } };
      await fixture(
        `synthetic-home/${file}`,
        file.endsWith(".toml")
          ? toml({ mcp_servers: servers })
          : file.includes("settings")
            ? { permissions: { defaultMode: "bypassPermissions" } }
            : { mcpServers: servers },
      );
      const subject = (await snapshot(["--include-user"])).findings[0]?.subjectId ?? "";
      homeSpy.mockClear();
      expect(await explain(subject)).toBe(0);
      expect(output.join("\n")).toContain("Subject not observed");
      expect(homeSpy).not.toHaveBeenCalled();
      output.length = 0;
      expect(await explain(subject, ["--include-user"])).toBe(0);
      expect(output.join("\n")).toContain(`user ${file} ::`);
      expect(output.join("\n")).not.toMatch(/synthetic-home|LOCAL_CANARY|bypassPermissions/);
      expect(output.join("\n")).not.toContain(project);
      expect(homeSpy).toHaveBeenCalledOnce();
    },
  );

  it.each([
    {
      file: ".claude/settings.json",
      value: { permissions: { defaultMode: "bypassPermissions" } },
      rule: "CFG001",
      selector: "/permissions/defaultMode",
      advice: "Restore permission prompts",
    },
    {
      file: ".claude/settings.local.json",
      value: { permissions: { allow: ["Bash", "Bash(LOCAL_CANARY)"] } },
      rule: "CFG006",
      selector: "/permissions/allow",
      advice: "Narrow automatic shell approvals",
    },
    {
      file: ".codex/config.toml",
      value: 'sandbox_mode = "danger-full-access"',
      rule: "CFG002",
      selector: "sandbox_mode",
      advice: "Restrict sandbox access",
    },
    {
      file: ".claude/settings.json",
      value: { env: { API_KEY: "LOCAL_CANARY" } },
      rule: "CFG005",
      selector: 'JSON Pointer "" (settings root; inspected credential fields)',
      advice: "Replace literal credentials",
    },
  ])(
    "locates the fixed $rule subject in $file",
    async ({ file, value, rule, selector, advice }) => {
      await fixture(file, value);
      const subject = (await snapshot()).findings[0]?.subjectId ?? "";
      expect(await explain(subject)).toBe(0);
      expect(output.join("\n")).toContain(`project ${file} :: ${selector}`);
      expect(output.join("\n")).toContain(`${rule}: ${advice}`);
      expect(output.join("\n")).toContain(
        "No execution, edits, upload or verification of effective permissions.",
      );
      expect(output.join("\n")).not.toMatch(
        /LOCAL_CANARY|bypassPermissions|danger-full-access|API_KEY|Bash/,
      );
    },
  );

  it.each([
    "removed",
    "changed",
    "renamed",
    "disabled",
    "not-enabled",
    "settings-disabled",
    "unknown",
  ])(
    "reports a subject not observed, never verified secure or resolved, after %s",
    async (change) => {
      await fixture(".mcp.json", { mcpServers: { target: { url: "http://fixture.invalid" } } });
      let subject = (await snapshot()).findings[0]?.subjectId ?? "";
      if (change === "removed") await rm(path.join(project, ".mcp.json"));
      if (change === "changed")
        await fixture(".mcp.json", { mcpServers: { target: { command: "node" } } });
      if (change === "renamed")
        await fixture(".mcp.json", { mcpServers: { renamed: { url: "http://fixture.invalid" } } });
      if (change === "disabled" || change === "not-enabled") {
        await fixture(".mcp.json", {
          mcpServers: {
            target: {
              url: "http://fixture.invalid",
              ...(change === "disabled" ? { disabled: true } : { enabled: false }),
            },
          },
        });
      }
      if (change === "settings-disabled")
        await fixture(".claude/settings.local.json", { disabledMcpjsonServers: ["target"] });
      if (change === "unknown") subject = "0".repeat(64);
      expect(await explain(subject)).toBe(0);
      expect(output).toEqual([
        "LOCAL-ONLY explanation (not telemetry)",
        "Subject not observed in this fresh capture. This is not verification of security or resolution.",
      ]);
    },
  );

  it.each(["malformed", "oversized", "junction", "overflow", "missing-root"])(
    "withholds even matching local locations when the fresh capture is incomplete: %s",
    async (failure) => {
      await fixture(".cursor/mcp.json", { mcpServers: { target: { token: "LOCAL_CANARY" } } });
      const subject = (await snapshot()).findings[0]?.subjectId ?? "";
      if (failure === "malformed") await fixture(".mcp.json", '{"LOCAL_CANARY":');
      if (failure === "oversized") await fixture(".mcp.json", " ".repeat(256 * 1024 + 1));
      if (failure === "junction") {
        await fixture("linked/settings.json", {
          permissions: { defaultMode: "bypassPermissions" },
        });
        await symlink(
          path.join(project, "linked"),
          path.join(project, ".claude"),
          process.platform === "win32" ? "junction" : "dir",
        );
      }
      if (failure === "overflow") {
        await fixture(".mcp.json", {
          mcpServers: Object.fromEntries(
            Array.from({ length: 501 }, (_, index) => [String(index), { token: "LOCAL_CANARY" }]),
          ),
        });
      }
      if (failure === "missing-root") await rm(project, { recursive: true, force: true });
      expect(await explain(subject)).toBe(2);
      expect(output.join("\n")).toContain("Incomplete fresh capture; local locations withheld.");
      expect(output.join("\n")).not.toMatch(/\.cursor|mcpServers|CFG005|LOCAL_CANARY/);
      expect(output.join("\n") + errors.join("\n")).not.toContain(project);
    },
  );

  it.each([
    ["--explain"],
    ["--explain", ""],
    ["--explain", "a".repeat(63)],
    ["--explain", "a".repeat(65)],
    ["--explain", "A".repeat(64)],
    ["--explain", "g".repeat(64)],
    ["--explain", ` ${"a".repeat(64)}`],
    ["--explain", `${"a".repeat(64)}\n`],
    ["--explain", "canary-invalid-argument"],
    ["--explain", "a".repeat(64), "--explain", "b".repeat(64)],
    ["--explain", "a".repeat(64), "--upload", "--endpoint", "https://fixture.invalid/api/ingest"],
    ["--explain", "a".repeat(64), "--watch"],
  ])(
    "rejects invalid explanation arguments before reads, credentials or network: %j",
    async (...args: string[]) => {
      const checkSpy = vi.spyOn(reads, "checkDirectory");
      const homeSpy = vi.spyOn(os, "homedir").mockReturnValue(path.join(project, "synthetic-home"));
      const fetchSpy = vi.spyOn(globalThis, "fetch");
      const env = process.env;
      let credentialReads = 0;
      process.env = new Proxy(env, {
        get(target, key) {
          if (key === "EXPLAIN_TOKEN_CANARY") credentialReads++;
          return Reflect.get(target, key);
        },
      });
      try {
        expect(
          await main([
            "monitor",
            "--project",
            project,
            "--include-user",
            "--token-env",
            "EXPLAIN_TOKEN_CANARY",
            ...args,
          ]),
        ).toBe(2);
      } finally {
        process.env = env;
      }
      expect(output).toEqual([]);
      expect(errors.join("\n")).toContain("Invalid monitor arguments");
      expect(errors.join("\n")).not.toMatch(/canary|fixture.invalid/);
      expect(checkSpy).not.toHaveBeenCalled();
      expect(homeSpy).not.toHaveBeenCalled();
      expect(fetchSpy).not.toHaveBeenCalled();
      expect(credentialReads).toBe(0);
    },
  );

  it("locates the observed server without printing its label or any configuration value", async () => {
    const canary = "LOCAL_CANARY_SECRET_NEVER_PRINT";
    await fixture(".cursor/mcp.json", {
      mcpServers: {
        harmless: { command: "node" },
        [canary]: {
          command: "npx",
          args: [canary],
          url: `http://fixture.invalid/${canary}`,
          env: { API_KEY: canary },
        },
      },
    });
    const before = await readFile(path.join(project, ".cursor/mcp.json"), "utf8");
    const wire = await snapshot();
    const fetchSpy = vi.spyOn(globalThis, "fetch");
    const subject = wire.findings[0]?.subjectId ?? "";
    expect(await explain(subject)).toBe(0);
    expect(output.join("\n")).toContain("LOCAL-ONLY explanation (not telemetry)");
    expect(output.join("\n")).toContain(
      "project .cursor/mcp.json :: mcpServers entry #2 (parsed key order; label withheld)",
    );
    expect(output.join("\n")).toContain("CFG003: Pin a reviewed exact package version.");
    expect(output.join("\n")).toContain(
      "CFG004: Use encrypted transport for the remote MCP connection.",
    );
    expect(output.join("\n")).toContain(
      "CFG005: Replace literal credentials with harness-supported references",
    );
    expect(output.join("\n") + errors.join("\n")).not.toMatch(
      /LOCAL_CANARY|fixture.invalid|npx|API_KEY|harmless|http:/,
    );
    expect(output.join("\n")).not.toContain(project);
    expect(fetchSpy).not.toHaveBeenCalled();
    expect(await readFile(path.join(project, ".cursor/mcp.json"), "utf8")).toBe(before);
  });
});
