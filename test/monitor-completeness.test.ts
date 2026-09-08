import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { stringify as toml } from "smol-toml";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { capture, type LocalObservation } from "../src/monitor/capture.js";
import { runMonitor } from "../src/monitor/index.js";
import { parseOptions } from "../src/monitor/options.js";
import type { Harness, Scope } from "../src/monitor/types.js";

let project: string;
let home: string;
let output: string[];
let errors: string[];
beforeEach(async () => {
  project = await mkdtemp(path.join(os.tmpdir(), "uleravo-completeness-"));
  home = path.join(project, "synthetic-home");
  await mkdir(home);
  // Never call through, including RED runs before validation exists.
  vi.spyOn(os, "homedir").mockReturnValue(home);
  vi.spyOn(globalThis, "fetch").mockRejectedValue(new Error("Unexpected request"));
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
async function fixture(file: string, value: Record<string, unknown>, scope: Scope = "project") {
  const destination = path.join(scope === "user" ? home : project, file);
  await mkdir(path.dirname(destination), { recursive: true });
  await writeFile(
    destination,
    file.endsWith(".toml") ? toml(value as Parameters<typeof toml>[0]) : JSON.stringify(value),
  );
  return destination;
}
function args(scope: Scope) {
  return ["--project", project, ...(scope === "user" ? ["--include-user"] : [])];
}
const withheld = [
  "LOCAL-ONLY explanation (not telemetry)",
  "Incomplete fresh capture; local locations withheld.",
];
async function assertMalformed(
  file: string,
  value: Record<string, unknown>,
  harness: Harness,
  scope: Scope,
) {
  // A separate, still-readable group must not make explanation disclose locators.
  const other = harness === "cursor" ? ".mcp.json" : ".cursor/mcp.json";
  await fixture(other, { mcpServers: { target: { token: "SYNTHETIC_SECRET" } } });
  const before = await capture(parseOptions(args(scope)));
  const subject = before.findings[0]?.subjectId ?? "";
  expect(subject).toMatch(/^[a-f0-9]{64}$/);
  const filePath = await fixture(file, value, scope);
  const original = await readFile(filePath, "utf8");
  const observations: LocalObservation[] = [];
  const after = await capture(parseOptions(args(scope)), (item) => observations.push(item));
  expect(after.complete).toBe(false);
  const group = after.configurations.find(
    (config) => config.harness === harness && config.scope === scope,
  );
  expect(group?.status).toBe("error");
  expect(group).not.toHaveProperty("digest");
  expect(
    after.findings.filter((finding) => finding.harness === harness && finding.scope === scope),
  ).toEqual([]);
  expect(
    observations.filter((item) => item.finding.harness === harness && item.finding.scope === scope),
  ).toEqual([]);
  expect(after.findings.some((finding) => finding.subjectId === subject)).toBe(true);
  expect(await runMonitor([...args(scope), "--explain", subject])).toBe(2);
  expect(output).toEqual(withheld);
  expect(JSON.stringify(after) + errors.join("\n")).not.toMatch(
    /SYNTHETIC_SECRET|selector|entry #|mcp.json|settings.json|config.toml/,
  );
  expect(await readFile(filePath, "utf8")).toBe(original);
  expect(globalThis.fetch).not.toHaveBeenCalled();
}

it.each(["project", "user"] as const)(
  "withholds unrelated locators for malformed sandbox in %s TOML",
  async (scope) => {
    await assertMalformed(
      ".codex/config.toml",
      {
        sandbox_mode: ["danger-full-access"],
        mcp_servers: { target: { token: "SYNTHETIC_SECRET" } },
      },
      "codex",
      scope,
    );
  },
);

const settings = [
  { file: ".claude/settings.json", scope: "project" },
  { file: ".claude/settings.local.json", scope: "project" },
  { file: ".claude/settings.json", scope: "user" },
] as const;

const servers = [
  { file: ".mcp.json", harness: "claude-code", scope: "project" },
  { file: ".claude.json", harness: "claude-code", scope: "user" },
  { file: ".cursor/mcp.json", harness: "cursor", scope: "project" },
  { file: ".cursor/mcp.json", harness: "cursor", scope: "user" },
  { file: ".codex/config.toml", harness: "codex", scope: "project" },
  { file: ".codex/config.toml", harness: "codex", scope: "user" },
] as const;
const credentialSources = [
  ...settings.map((source) => ({ ...source, harness: "claude-code" as const })),
  ...servers,
];
function credentialConfig(file: string, fields: Record<string, unknown>) {
  return file.includes("settings")
    ? { ...fields, permissions: { defaultMode: "bypassPermissions" } }
    : {
        [file.endsWith(".toml") ? "mcp_servers" : "mcpServers"]: {
          firstValid: { token: "SYNTHETIC_SECRET" },
          target: { command: "npx", args: ["fixture"], ...fields },
        },
      };
}
it.each(
  credentialSources.flatMap((source) =>
    ["token", "bearer_token", "api_key", "apiKey", "password", "client_secret"].map((field) => ({
      ...source,
      field,
    })),
  ),
)(
  "rejects non-string inspected credential before any source findings: $scope $file $field",
  async ({ file, harness, scope, field }) => {
    await assertMalformed(
      file,
      credentialConfig(file, {
        token: "SYNTHETIC_SECRET",
        [field]: ["SYNTHETIC_SECRET"],
      }),
      harness,
      scope,
    );
  },
);

it.each(
  credentialSources.flatMap((source) => [
    { ...source, auth: ["SYNTHETIC_SECRET"] },
    { ...source, auth: { CLIENT_SECRET: { value: "SYNTHETIC_SECRET" } } },
  ]),
)(
  "rejects malformed inspected auth credentials: $scope $file $auth",
  async ({ file, harness, scope, auth }) => {
    await assertMalformed(file, credentialConfig(file, { auth }), harness, scope);
  },
);

it.each(
  (["project", "user"] as const).flatMap((scope) => [
    { scope, oauth: ["SYNTHETIC_SECRET"] },
    { scope, oauth: { client_secret: ["SYNTHETIC_SECRET"] } },
  ]),
)(
  "rejects malformed inspected Codex OAuth before any findings: $scope $oauth",
  async ({ scope, oauth }) => {
    await assertMalformed(
      ".codex/config.toml",
      credentialConfig(".codex/config.toml", { oauth }),
      "codex",
      scope,
    );
  },
);

it.each(
  settings.flatMap((source) => [
    { ...source, disabled: "target" },
    { ...source, disabled: ["target", 42] },
  ]),
)(
  "rejects malformed inspected disabled-server lists: $scope $file $disabled",
  async ({ file, scope, disabled }) => {
    await assertMalformed(file, { disabledMcpjsonServers: disabled }, "claude-code", scope);
  },
);

it.each(
  settings.flatMap((source) =>
    ["env", "headers", "http_headers"].flatMap((field) => [
      { ...source, field, value: { API_KEY: { value: "SYNTHETIC_SECRET" } } },
      { ...source, field, value: ["SYNTHETIC_SECRET"] },
    ]),
  ),
)(
  "rejects malformed inspected credential maps before settings observations: $scope $file $field $value",
  async ({ file, scope, field, value }) => {
    await assertMalformed(
      file,
      {
        [field]: value,
        permissions: { defaultMode: "bypassPermissions" },
      },
      "claude-code",
      scope,
    );
  },
);

it.each(credentialSources)(
  "preserves supported values, references and unused extensions: $scope $file",
  async ({ file, harness, scope }) => {
    const reference = harness === "claude-code" ? "${FIXTURE_TOKEN}" : "${env:FIXTURE_TOKEN}";
    const fields = {
      token: "",
      bearer_token: "",
      api_key: "",
      apiKey: "",
      password: "",
      client_secret: "",
      ...(harness === "codex"
        ? {
            env: { NODE_ENV: "production" },
            http_headers: { Accept: "application/json" },
            bearer_token_env_var: "FIXTURE_TOKEN",
            env_http_headers: { Authorization: "FIXTURE_TOKEN" },
            env_vars: ["FIXTURE_TOKEN"],
            oauth: {
              client_secret: "",
              client_secret_env_var: "FIXTURE_TOKEN",
              client_id: "public",
              scopes: ["read"],
              extension: { value: 42 },
            },
          }
        : {
            env: { API_KEY: reference },
            headers: { Authorization: `Bearer ${reference}` },
            // OAuth is not an inspected container for these harnesses.
            oauth: ["unobserved"],
          }),
      auth: {
        CLIENT_ID: "public",
        CLIENT_SECRET: harness === "codex" ? "" : reference,
        scopes: ["read"],
        extension: { API_KEY: ["unobserved"] },
        token_options: { source: "unused" },
        oauth: { scopes: ["unused"] },
      },
      extension: { token: ["unobserved"], nested: { sandbox_mode: false } },
    };
    const value = file.includes("settings")
      ? {
          ...fields,
          permissions: { defaultMode: "future-string-mode", allow: [], extension: ["unused"] },
          disabledMcpjsonServers: [],
          mcpServers: ["not-a-settings-source"],
          sandbox_mode: ["not-a-claude-setting"],
        }
      : {
          [harness === "codex" ? "mcp_servers" : "mcpServers"]: {
            target: { command: "node", args: [], enabled: true, disabled: false, ...fields },
          },
          permissions: ["not-inspected-here"],
          ...(harness === "codex"
            ? {
                sandbox_mode: "future-string-mode",
                profiles: { other: { sandbox_mode: ["unused"] } },
              }
            : { sandbox_mode: ["unused"] }),
          env: ["not-a-settings-root"],
          extension: ["unused"],
        };
    await fixture(file, value, scope);
    const snap = await capture(parseOptions(args(scope)));
    expect(snap.complete).toBe(true);
    expect(snap.findings).toEqual([]);
    expect(
      snap.configurations.find((config) => config.harness === harness && config.scope === scope),
    ).toHaveProperty("digest");
    expect(globalThis.fetch).not.toHaveBeenCalled();
  },
);

it.each(servers)(
  "retains validation of inspected MCP containers and launcher types: $scope $file",
  async ({ file, harness, scope }) => {
    for (const fields of [
      { args: [42] },
      { command: 42 },
      { url: false },
      { enabled: "false" },
      { disabled: "true" },
      { env: { API_KEY: false } },
      { headers: ["bad"] },
      { http_headers: { Authorization: ["bad"] } },
    ]) {
      await fixture(file, credentialConfig(file, fields), scope);
      const snap = await capture(parseOptions(args(scope)));
      expect(snap.complete).toBe(false);
      const group = snap.configurations.find(
        (config) => config.harness === harness && config.scope === scope,
      );
      expect(group?.status).toBe("error");
      expect(group).not.toHaveProperty("digest");
      expect(snap.findings).toEqual([]);
    }
  },
);

it("withholds all locators and omits the entire partly malformed multi-file group", async () => {
  await fixture(".claude/settings.json", { permissions: { defaultMode: "bypassPermissions" } });
  await fixture(".mcp.json", { mcpServers: { target: { token: "SYNTHETIC_SECRET" } } });
  const before = await capture(parseOptions(args("project")));
  const subject = before.findings[0]?.subjectId ?? "";
  await fixture(".claude/settings.local.json", { env: { API_KEY: { value: "SYNTHETIC_SECRET" } } });
  const after = await capture(parseOptions(args("project")));
  expect(after.complete).toBe(false);
  expect(after.configurations[0]?.status).toBe("error");
  expect(after.configurations[0]).not.toHaveProperty("digest");
  expect(after.findings).toEqual([]);
  expect(await runMonitor([...args("project"), "--explain", subject])).toBe(2);
  expect(output).toEqual(withheld);
});

it("keeps malformed user coverage opt-in and default/upload bytes free of local observations", async () => {
  await fixture(".cursor/mcp.json", { mcpServers: { target: { token: "SYNTHETIC_SECRET" } } });
  await fixture(
    ".claude/settings.json",
    { env: { API_KEY: { value: "SYNTHETIC_SECRET" } } },
    "user",
  );
  const homeSpy = vi.mocked(os.homedir);
  homeSpy.mockClear();
  const env = process.env;
  let credentialReads = 0;
  process.env = new Proxy(env, {
    get(target, key) {
      if (key === "COMPLETENESS_TOKEN") {
        credentialReads++;
        throw new Error("Unexpected credential read");
      }
      return Reflect.get(target, key);
    },
  });
  try {
    expect(await runMonitor([...args("project"), "--token-env", "COMPLETENESS_TOKEN"])).toBe(0);
    const normal = JSON.parse(output[0] ?? "null");
    expect(normal.complete).toBe(true);
    expect(homeSpy).not.toHaveBeenCalled();
    output.length = 0;
    expect(
      await runMonitor([
        ...args("user"),
        "--explain",
        normal.findings[0].subjectId,
        "--token-env",
        "COMPLETENESS_TOKEN",
      ]),
    ).toBe(2);
    expect(output).toEqual(withheld);
    expect(homeSpy).toHaveBeenCalledOnce();
    expect(credentialReads).toBe(0);
    expect(globalThis.fetch).not.toHaveBeenCalled();
  } finally {
    process.env = env;
  }
  output.length = 0;
  vi.stubEnv("COMPLETENESS_TOKEN", "synthetic-device-token");
  vi.mocked(globalThis.fetch).mockResolvedValue(
    new Response(JSON.stringify({ accepted: true, duplicate: false, openFindings: 1 })),
  );
  expect(
    await runMonitor([
      ...args("user"),
      "--upload",
      "--token-env",
      "COMPLETENESS_TOKEN",
      "--endpoint",
      "http://127.0.0.1/api/ingest",
    ]),
  ).toBe(2);
  expect(globalThis.fetch).toHaveBeenCalledOnce();
  expect(vi.mocked(globalThis.fetch).mock.calls[0]?.[1]?.body).toBe(output[0]);
  expect(output).toHaveLength(1);
  const wire = JSON.parse(output[0] ?? "null");
  expect(wire.complete).toBe(false);
  expect(
    wire.configurations.find(
      (config: { harness: string; scope: string }) =>
        config.harness === "claude-code" && config.scope === "user",
    ),
  ).toEqual({ harness: "claude-code", scope: "user", status: "error", serverCount: 0 });
  expect(wire.findings).toHaveLength(1);
  expect(Object.keys(wire).sort()).toEqual([
    "captureId",
    "capturedAt",
    "complete",
    "configurations",
    "findings",
    "projectId",
    "schemaVersion",
  ]);
  expect(output[0] + errors.join("\n")).not.toMatch(
    /SYNTHETIC_SECRET|synthetic-home|synthetic-device-token|mcp.json|settings.json|selector|entry #|LOCAL-ONLY|API_KEY/,
  );
});

it.each(settings)(
  "does not turn prior permissions into complete absence: $scope $file",
  async ({ file, scope }) => {
    await fixture(file, { permissions: { defaultMode: "bypassPermissions" } }, scope);
    const before = await capture(parseOptions(args(scope)));
    expect(before.complete).toBe(true);
    const subject = before.findings.find((finding) => finding.ruleId === "CFG001")?.subjectId;
    expect(subject).toMatch(/^[a-f0-9]{64}$/);
    await fixture(file, { permissions: { defaultMode: ["bypassPermissions"] } }, scope);
    const observations: LocalObservation[] = [];
    const after = await capture(parseOptions(args(scope)), (observation) =>
      observations.push(observation),
    );
    expect(after.complete).toBe(false);
    expect(
      after.configurations.find(
        (config) => config.harness === "claude-code" && config.scope === scope,
      ),
    ).toEqual({
      harness: "claude-code",
      scope,
      status: "error",
      serverCount: 0,
    });
    expect(after.findings).toEqual([]);
    expect(observations).toEqual([]);
    expect(await runMonitor([...args(scope), "--explain", subject ?? ""])).toBe(2);
    expect(output).toEqual(withheld);
    expect(globalThis.fetch).not.toHaveBeenCalled();
  },
);
