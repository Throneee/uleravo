import { mkdir, mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { stringify as toml } from "smol-toml";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { runMonitor } from "../src/monitor/index.js";

let project: string;
let output: string[];
beforeEach(async () => {
  project = await mkdtemp(path.join(os.tmpdir(), "uleravo-monitor-test-"));
  output = [];
  vi.spyOn(console, "log").mockImplementation((line: string) => {
    output.push(line);
  });
  vi.spyOn(console, "error").mockImplementation(() => {});
});
afterEach(async () => {
  vi.unstubAllEnvs();
  vi.restoreAllMocks();
  await rm(project, { recursive: true, force: true });
});
async function fixture(name: string, value: unknown) {
  const file = path.join(project, name);
  await mkdir(path.dirname(file), { recursive: true });
  await writeFile(file, typeof value === "string" ? value : JSON.stringify(value));
}
function report() {
  return JSON.parse(output.at(-1) ?? "null");
}
async function mcpFixture(file: string, servers: Record<string, unknown>) {
  await fixture(
    file,
    file.endsWith(".toml")
      ? toml({ mcp_servers: servers } as Parameters<typeof toml>[0])
      : { mcpServers: servers },
  );
}

describe("monitor local capture", () => {
  it("guides the first local capture without requiring a cloud account", async () => {
    const network = vi.spyOn(globalThis, "fetch").mockRejectedValue(new Error("forbidden"));
    const home = vi.spyOn(os, "homedir").mockReturnValue(path.join(project, "synthetic-home"));
    expect(await runMonitor(["--help"])).toBe(0);
    const help = output.join("\n");
    expect(help).toContain('uleravo monitor --project "PATH/TO/EXISTING/PROJECT" --once');
    expect(help).toContain("No account, endpoint or token is needed for local capture.");
    expect(help).toContain("local JSON findings[].subjectId or a cloud finding.subjectId");
    expect(help).toContain("Use the same project location and scope as the original capture.");
    expect(help).toContain("No coverage is not a secure project, even with exit 0.");
    expect(help).toContain("No commands or hooks are executed; no files are edited.");
    expect(network).not.toHaveBeenCalled();
    expect(home).not.toHaveBeenCalled();
  });
  it.each([
    [],
    ["."],
    ["--project"],
    ["--project", ""],
    ["--project", "x", "--token", "secret-fixture"],
    ["--project", "x", "--interval", "29"],
    ["--project", "x", "--interval", "30oops"],
    ["--project", "x", "--interval", "86401"],
    ["--project", "x", "--interval", "30.1"],
    ["--project", "x", "--upload"],
    ["--project", "x", "--endpoint", "http://remote.invalid/api/ingest"],
    ["--project", "x", "--endpoint", "https://user:secret-fixture@remote.invalid/api/ingest"],
    ["--project", "x", "--endpoint", "https://remote.invalid/api/ingest?token=secret-fixture"],
    ["--project", "x", "--endpoint", "https://remote.invalid/#secret-fixture"],
    ["--project", "x", "--token-env", "INVALID-NAME"],
    ["--project", "x", "--project", "y"],
    ["--project", "x", "--once", "--watch"],
  ])("rejects invalid CLI arguments without echoing values: %j", async (...argv: string[]) => {
    expect(await runMonitor(argv)).toBe(2);
    expect(output).toEqual([]);
    expect(JSON.stringify(vi.mocked(console.error).mock.calls)).not.toContain("secret-fixture");
  });

  it.each([".claude/settings.json", ".claude/settings.local.json"])(
    "captures declared bypass in %s as a nonblocking hashed finding",
    async (name) => {
      await fixture(name, {
        permissions: { defaultMode: "bypassPermissions" },
        hooks: { fixture: "do-not-execute-secret-fixture" },
      });
      expect(await runMonitor(["--project", project])).toBe(0);
      const first = report();
      expect(first.configurations[0]).toMatchObject({
        status: "read",
        digest: expect.stringMatching(/^[a-f0-9]{64}$/),
      });
      expect(first.findings).toEqual([
        {
          id: expect.stringMatching(/^[a-f0-9]{64}$/),
          ruleId: "CFG001",
          harness: "claude-code",
          scope: "project",
          subjectId: expect.stringMatching(/^[a-f0-9]{64}$/),
        },
      ]);
      expect(await runMonitor(["--project", project])).toBe(0);
      expect(report().findings).toEqual(first.findings);
      expect(report().captureId).not.toBe(first.captureId);
      expect(output.join("")).not.toMatch(/secret-fixture|bypassPermissions|hooks/);
    },
  );

  it.each(["Bash", "Bash(*)", "Bash(:*)"])(
    "classifies broad automatic shell approval %s without blocking",
    async (allow) => {
      await fixture(".claude/settings.json", { permissions: { allow: [allow, "Bash(npm test)"] } });
      expect(await runMonitor(["--project", project])).toBe(0);
      expect(report().findings.map((f: { ruleId: string }) => f.ruleId)).toEqual(["CFG006"]);
      await fixture(".claude/settings.json", {
        permissions: { allow: ["Bash(npm test)", "Read(*)"], deny: ["Bash"] },
      });
      expect(await runMonitor(["--project", project])).toBe(0);
      expect(report().findings).toEqual([]);
    },
  );

  it("parses Codex TOML full access without confusing quoted strings with declarations", async () => {
    await fixture(
      ".codex/config.toml",
      '# fixture\nsandbox_mode = "danger-full-access"\n[profiles.safe]\nsandbox_mode = "read-only"\n',
    );
    expect(await runMonitor(["--project", project])).toBe(0);
    expect(report().configurations[2]).toMatchObject({ status: "read" });
    expect(report().findings.map((f: { ruleId: string }) => f.ruleId)).toEqual(["CFG002"]);
    await fixture(
      ".codex/config.toml",
      'sandbox_mode = "read-only"\nnote = \'sandbox_mode = "danger-full-access"\'\n',
    );
    expect(await runMonitor(["--project", project])).toBe(0);
    expect(report().findings).toEqual([]);
  });

  it.each([".mcp.json", ".cursor/mcp.json", ".codex/config.toml"])(
    "classifies only non-loopback HTTP MCP declarations in %s",
    async (file) => {
      await mcpFixture(file, {
        privateServerName: { type: "http", url: "http://remote.invalid/secret-fixture" },
        local4: { type: "http", url: "http://127.0.0.1:3000/mcp" },
        local6: { type: "http", url: "http://[::1]:3000/mcp" },
        localName: { type: "http", url: "http://localhost:3000/mcp" },
        secure: { type: "http", url: "https://remote.invalid" },
        disabled: { type: "http", url: "http://remote.invalid", disabled: true },
        notEnabled: { type: "http", url: "http://remote.invalid", enabled: false },
      });
      expect(await runMonitor(["--project", project])).toBe(0);
      expect(report().findings.map((f: { ruleId: string }) => f.ruleId)).toEqual(["CFG004"]);
      expect(
        report().configurations.find((c: { status: string }) => c.status === "read").serverCount,
      ).toBe(5);
      expect(output.join("")).not.toMatch(/privateServerName|secret-fixture|remote.invalid|http:/);
    },
  );

  it.each([
    ["npx", ["-y", "@fixture/mcp@latest"], true],
    ["C:\\fixture\\npx.cmd", ["--yes", "@fixture/mcp@1.2.3"], false],
    ["npx", ["--package", "fixture@^1.2.3", "fixture"], true],
    ["npx", ["--package=fixture@1.2.3", "fixture"], false],
    ["npx", ["-p", "fixture@1.2.3", "-p", "second", "fixture"], true],
    ["npx", ["fixture@1.2.3-beta.1"], false],
    ["npx", ["fixture"], true],
    ["uvx", ["fixture"], true],
    ["uvx", ["ruff@0.3.0"], false],
    ["uvx", ["ruff@latest"], true],
    ["uvx", ["ruff@>=0.3.0"], true],
    ["uvx", ["--from", "ruff@0.3.0", "ruff"], true],
    ["uvx", ["fixture==1.2.3"], false],
    ["uvx", ["--from", "fixture>=1.2.3", "fixture"], true],
    ["uvx", ["--from=fixture==1.2.3", "fixture"], false],
    ["uvx", ["--python", "3.12", "fixture==1.2.3"], false],
    ["node", ["fixture.mjs"], false],
  ])("reviews direct package launcher %s %j", async (command, args, flagged) => {
    await mcpFixture(".cursor/mcp.json", { launcher: { command, args } });
    expect(await runMonitor(["--project", project])).toBe(0);
    expect(report().findings.map((f: { ruleId: string }) => f.ruleId)).toEqual(
      flagged ? ["CFG003"] : [],
    );
  });

  it.each([".mcp.json", ".cursor/mcp.json", ".codex/config.toml"])(
    "detects literal credentials without hashing their values or field names in %s",
    async (file) => {
      const reference = file === ".mcp.json" ? "${FIXTURE_TOKEN}" : "${env:FIXTURE_TOKEN}";
      const referenceFields = file.endsWith(".toml")
        ? {
            bearer_token_env_var: "FIXTURE_TOKEN",
            env_http_headers: { Authorization: "FIXTURE_TOKEN" },
            env_vars: ["FIXTURE_TOKEN"],
          }
        : { env: { API_KEY: reference }, headers: { Authorization: `Bearer ${reference}` } };
      await mcpFixture(file, {
        literal: {
          command: "node",
          env: { PRIVATE_API_KEY: "secret-fixture-a", NODE_ENV: "production" },
          headers: { Authorization: "Bearer secret-fixture-b" },
        },
        references: { command: "node", ...referenceFields },
        plain: {
          command: "node",
          env: { NODE_ENV: "production" },
          headers: { "Content-Type": "application/json" },
        },
      });
      expect(await runMonitor(["--project", project])).toBe(0);
      const first = report();
      expect(first.findings.map((f: { ruleId: string }) => f.ruleId)).toEqual(["CFG005"]);
      await mcpFixture(file, {
        literal: { command: "node", env: { OTHER_PASSWORD: "secret-fixture-rotated" } },
        references: { command: "node", ...referenceFields },
        plain: {
          command: "node",
          env: { NODE_ENV: "production" },
          headers: { "Content-Type": "application/json" },
        },
      });
      expect(await runMonitor(["--project", project])).toBe(0);
      expect(report().findings).toEqual(first.findings);
      expect(report().configurations).toEqual(first.configurations);
      expect(output.join("")).not.toMatch(
        /secret-fixture|PRIVATE_API_KEY|OTHER_PASSWORD|FIXTURE_TOKEN|Authorization/,
      );
    },
  );

  it("includes token fields, static OAuth secrets and settings env while rejecting literal fallbacks as references", async () => {
    await mcpFixture(".mcp.json", {
      fallback: { command: "node", env: { API_KEY: "${TOKEN:-secret-fixture}" } },
      mixed: { command: "node", headers: { Authorization: "Bearer ${TOKEN} secret-fixture" } },
      token: { command: "node", token: "secret-fixture" },
    });
    await mcpFixture(".cursor/mcp.json", {
      oauth: {
        url: "https://fixture.invalid",
        auth: { CLIENT_SECRET: "secret-fixture", CLIENT_ID: "public" },
      },
    });
    await fixture(".claude/settings.json", { env: { API_KEY: "secret-fixture" } });
    expect(await runMonitor(["--project", project])).toBe(0);
    expect(report().findings).toHaveLength(5);
    expect(report().findings.every((f: { ruleId: string }) => f.ruleId === "CFG005")).toBe(true);
    expect(output.join("")).not.toContain("secret-fixture");
  });

  it("detects Codex oauth.client_secret without treating client IDs or secret references as literals", async () => {
    await mcpFixture(".codex/config.toml", {
      literal: { url: "https://fixture.invalid", oauth: { client_secret: "secret-fixture" } },
      reference: {
        url: "https://fixture.invalid",
        oauth: { client_secret_env_var: "FIXTURE_SECRET", client_id: "public" },
      },
      empty: { url: "https://fixture.invalid", oauth: { client_secret: "" } },
    });
    expect(await runMonitor(["--project", project])).toBe(0);
    expect(report().findings.map((f: { ruleId: string }) => f.ruleId)).toEqual(["CFG005"]);
    expect(output.join("")).not.toMatch(/secret-fixture|FIXTURE_SECRET|client_secret/);
    const first = report();
    await mcpFixture(".codex/config.toml", {
      literal: { url: "https://fixture.invalid", oauth: { client_secret: "rotated-fixture" } },
      reference: {
        url: "https://fixture.invalid",
        oauth: { client_secret_env_var: "FIXTURE_SECRET", client_id: "public" },
      },
      empty: { url: "https://fixture.invalid", oauth: { client_secret: "" } },
    });
    expect(await runMonitor(["--project", project])).toBe(0);
    expect(report().findings).toEqual(first.findings);
  });

  it("refuses a junction/symlink ancestor before reading configuration content", async () => {
    await fixture("target/settings.json", { permissions: { defaultMode: "bypassPermissions" } });
    await symlink(
      path.join(project, "target"),
      path.join(project, ".claude"),
      process.platform === "win32" ? "junction" : "dir",
    );
    expect(await runMonitor(["--project", project])).toBe(2);
    expect(report()).toMatchObject({ complete: false, findings: [] });
    expect(report().configurations[0]).toMatchObject({ status: "error" });
    expect(report().configurations[0]).not.toHaveProperty("digest");
  });

  it("caps each configuration read at 256 KiB instead of accepting oversized valid JSON", async () => {
    await fixture(".mcp.json", { padding: "x".repeat(256 * 1024), mcpServers: {} });
    expect(await runMonitor(["--project", project])).toBe(2);
    expect(report()).toMatchObject({ complete: false });
    expect(report().configurations[0]).toMatchObject({ status: "error", serverCount: 0 });
    expect(console.error).toHaveBeenCalledWith(expect.stringContaining("Incomplete"));
  });

  it.each([
    [".mcp.json", '{"private":"secret-fixture",'],
    [".mcp.json", { mcpServers: [] }],
    [".mcp.json", { mcpServers: { broken: null } }],
    [".mcp.json", { mcpServers: { broken: { command: "node", args: "secret-fixture" } } }],
    [".claude/settings.json", { permissions: { allow: "Bash" } }],
    [".claude/settings.json", []],
    [".codex/config.toml", 'sandbox_mode = "read-only"\nsandbox_mode = "danger-full-access"'],
  ])("makes malformed configuration visible and incomplete: %s", async (file, value) => {
    await fixture(file as string, value);
    expect(await runMonitor(["--project", project])).toBe(2);
    expect(report().complete).toBe(false);
    expect(report().configurations.some((c: { status: string }) => c.status === "error")).toBe(
      true,
    );
    expect(output.join("") + JSON.stringify(vi.mocked(console.error).mock.calls)).not.toContain(
      "secret-fixture",
    );
  });

  it("treats a missing explicitly requested project as incomplete rather than optional missing files", async () => {
    expect(await runMonitor(["--project", path.join(project, "nonexistent")])).toBe(2);
    expect(report().complete).toBe(false);
    expect(report().configurations.every((c: { status: string }) => c.status === "error")).toBe(
      true,
    );
  });

  it("reads user configuration equivalents only after explicit include-user opt-in", async () => {
    const home = path.join(project, "fixture-home");
    const homeSpy = vi.spyOn(os, "homedir").mockReturnValue(home);
    await fixture("fixture-home/.claude.json", {
      mcpServers: { global: { command: "npx", args: ["fixture"] } },
      projects: { hidden: { secret: "secret-fixture" } },
    });
    await fixture("fixture-home/.claude/settings.json", {
      permissions: { defaultMode: "bypassPermissions" },
    });
    await fixture("fixture-home/.cursor/mcp.json", {
      mcpServers: { global: { url: "http://fixture.invalid" } },
    });
    await fixture("fixture-home/.codex/config.toml", 'sandbox_mode = "danger-full-access"');
    expect(await runMonitor(["--project", project])).toBe(0);
    expect(report().configurations).toHaveLength(3);
    expect(report().findings).toEqual([]);
    expect(homeSpy).not.toHaveBeenCalled();
    expect(await runMonitor(["--project", project, "--include-user"])).toBe(0);
    expect(report().configurations).toHaveLength(6);
    expect(
      report()
        .findings.map((f: { ruleId: string }) => f.ruleId)
        .sort(),
    ).toEqual(["CFG001", "CFG002", "CFG003", "CFG004"]);
    expect(report().findings.every((f: { scope: string }) => f.scope === "user")).toBe(true);
    const userFindings = report().findings;
    await mkdir(path.join(project, "second-project"));
    expect(
      await runMonitor(["--project", path.join(project, "second-project"), "--include-user"]),
    ).toBe(0);
    expect(report().findings).toEqual(userFindings);
    expect(output.join("")).not.toMatch(/secret-fixture|fixture-home/);
  });

  it("does not count Claude MCP entries explicitly disabled by observed project settings", async () => {
    await mcpFixture(".mcp.json", {
      off: { type: "http", url: "http://fixture.invalid" },
      on: { command: "npx", args: ["fixture"] },
    });
    await fixture(".claude/settings.local.json", { disabledMcpjsonServers: ["off"] });
    expect(await runMonitor(["--project", project])).toBe(0);
    expect(report().findings.map((f: { ruleId: string }) => f.ruleId)).toEqual(["CFG003"]);
    expect(report().configurations[0].serverCount).toBe(1);
  });

  it.each([501, 500])(
    "bounds server/finding counts and encoded wire size for %i declarations",
    async (count) => {
      await mcpFixture(
        ".cursor/mcp.json",
        Object.fromEntries(
          Array.from({ length: count }, (_, i) => [
            String(i),
            {
              command: "npx",
              args: ["fixture"],
              url: "http://fixture.invalid",
              env: { API_KEY: "secret-fixture" },
            },
          ]),
        ),
      );
      expect(await runMonitor(["--project", project])).toBe(2);
      expect(report().complete).toBe(false);
      expect(report().findings.length).toBeLessThanOrEqual(500);
      expect(
        report().configurations.every((c: { serverCount: number }) => c.serverCount <= 500),
      ).toBe(true);
      expect(Buffer.byteLength(output.at(-1) ?? "")).toBeLessThanOrEqual(128 * 1024);
    },
  );

  it("does not reinterpret unsupported fields as another harness's permissions or MCP source", async () => {
    await fixture(".claude/settings.json", {
      mcpServers: { notASupportedSource: { command: "npx", args: ["fixture"] } },
    });
    await fixture(".cursor/mcp.json", {
      permissions: { defaultMode: "bypassPermissions", allow: ["Bash"] },
      sandbox_mode: "danger-full-access",
    });
    await fixture(
      ".codex/config.toml",
      '[permissions]\ndefaultMode = "bypassPermissions"\nallow = ["Bash"]',
    );
    expect(await runMonitor(["--project", project])).toBe(0);
    expect(report().findings).toEqual([]);
    expect(report().configurations.every((c: { serverCount: number }) => c.serverCount === 0)).toBe(
      true,
    );
  });

  it.each([
    { command: 42 },
    { command: "node", url: null },
    { command: "node", enabled: "false" },
    { command: "node", env: { API_KEY: 42 } },
    { command: "node", headers: [] },
  ])("marks malformed inspected MCP fields incomplete", async (server) => {
    await mcpFixture(".cursor/mcp.json", { broken: server });
    expect(await runMonitor(["--project", project])).toBe(2);
    expect(report().configurations[1].status).toBe("error");
  });

  it("shows monitor help without a project, filesystem capture, or upload", async () => {
    expect(await runMonitor(["--help"])).toBe(0);
    expect(output.join("\n")).toMatch(/--project[\s\S]*--watch[\s\S]*--upload/);
    expect(output.join("\n")).toContain("/api/ingest");
    expect(output.join("\n")).toContain("ULERAVO_TOKEN");
  });

  it("reports missing optional configurations as complete but no coverage without uploading", async () => {
    const fetchSpy = vi.spyOn(globalThis, "fetch");
    await fixture("unobserved.txt", "fixture only");
    expect(await runMonitor(["--project", project])).toBe(0);
    expect(report()).toMatchObject({
      schemaVersion: 1,
      complete: true,
      findings: [],
      configurations: [
        { harness: "claude-code", scope: "project", status: "missing", serverCount: 0 },
        { harness: "cursor", scope: "project", status: "missing", serverCount: 0 },
        { harness: "codex", scope: "project", status: "missing", serverCount: 0 },
      ],
    });
    expect(report().captureId).toMatch(/^[0-9a-f-]{36}$/);
    expect(report().capturedAt).toMatch(/Z$/);
    expect(fetchSpy).not.toHaveBeenCalled();
    expect(output.join("")).not.toContain(project);
    expect(console.error).toHaveBeenCalledWith(expect.stringContaining("No coverage"));
  });
});
