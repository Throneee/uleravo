import { createHash } from "node:crypto";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { createServer, type Server } from "node:http";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import { formatCodexHarnessJson } from "../src/formatters/codex-harness.js";
import {
  freezeCodexHarnessResolution,
  snapshotCodexHarness,
  snapshotCodexHarnessWithResolution,
} from "../src/harnesses/codex.js";
import { compareCodexHarnessSnapshots } from "../src/harnesses/comparison.js";
import { MAX_HARNESS_REPORT_BYTES } from "../src/harnesses/domain.js";
import { parseCodexHarnessSnapshot } from "../src/harnesses/read.js";

const fixtureRoot = fileURLToPath(new URL("./fixtures/codex-harness", import.meta.url));
const temporaryDirectories: string[] = [];
const servers: Server[] = [];

afterEach(async () => {
  await Promise.all(
    servers.splice(0).map(
      (server) =>
        new Promise<void>((resolve, reject) => {
          server.close((error) => (error === undefined ? resolve() : reject(error)));
        }),
    ),
  );
  await Promise.all(
    temporaryDirectories.splice(0).map((directory) => rm(directory, { recursive: true })),
  );
});

describe("Codex local harness snapshot", () => {
  it("normalizes high-value permissions and inventories without execution, network, or secrets", async () => {
    let requests = 0;
    const server = createServer((_request, response) => {
      requests += 1;
      response.end("unexpected");
    });
    servers.push(server);
    const port = await listen(server);
    const fixture = await materializeFixture(port);

    const first = await snapshotCodexHarness(fixture.project, {
      codexVersion: "codex-cli 0.138.0",
      projectConfig: fixture.projectConfig,
      requirements: fixture.requirements,
      userConfig: fixture.userConfig,
    });
    const second = await snapshotCodexHarness(fixture.project, {
      codexVersion: "codex-cli 0.138.0",
      projectConfig: fixture.projectConfig,
      requirements: fixture.requirements,
      userConfig: fixture.userConfig,
    });

    expect(first).toEqual(second);
    expect(first.capture.complete).toBe(true);
    expect(first.project).toMatchObject({
      configApplicability: "applied",
      trust: { state: "declared", value: "trusted" },
    });
    expect(first.codexVersion).toMatchObject({ state: "declared", value: "codex-cli 0.138.0" });
    expect(first.semanticFacts.find((fact) => fact.key === "approval.policy")).toMatchObject({
      rank: 2,
      value: "never",
    });
    expect(
      first.semanticFacts.find((fact) => fact.key === "network.workspace-command-access"),
    ).toMatchObject({ rank: 1, value: true });
    expect(first.coverage.find((entry) => entry.area === "effective-runtime-state")).toMatchObject({
      state: "unavailable",
    });

    const local = first.inventory.mcpServers.find(
      (entry) => entry.id === "local" && entry.source.layer === "user-config",
    );
    expect(local).toMatchObject({
      environmentNames: ["API_KEY", "SAFE_MODE"],
      identity: { argumentCount: 2, executable: "node", kind: "stdio" },
    });
    const remote = first.inventory.mcpServers.find(
      (entry) => entry.id === "remote" && entry.source.layer === "user-config",
    );
    expect(remote).toMatchObject({
      environmentNames: ["MCP_BEARER_TOKEN"],
      headerNames: ["Authorization", "X-Key", "X-Tenant"],
      identity: {
        credentialsPresent: false,
        kind: "http",
        queryParameterNames: ["tenant", "token"],
        url: `http://127.0.0.1:${port.toString()}/mcp/<redacted>`,
      },
      oauthScopes: ["documents.read", "documents.write"],
    });
    expect(first.inventory.skills).toMatchObject([
      { enabled: { value: true }, path: "./skills/reviewer" },
    ]);
    expect(
      first.inventory.plugins.find(
        (entry) => entry.id === "audit" && entry.source.layer === "user-config",
      ),
    ).toMatchObject({ id: "audit", mcpServerIds: ["embedded"] });
    expect(
      first.inventory.apps.find(
        (entry) => entry.id === "github" && entry.source.layer === "requirements",
      ),
    ).toMatchObject({ applicability: "constraints", enabled: { value: false } });
    expect(
      first.inventory.plugins.find(
        (entry) => entry.id === "audit" && entry.source.layer === "requirements",
      ),
    ).toMatchObject({ applicability: "constraints", mcpServerIds: ["managed", "remote"] });
    expect(
      first.semanticFacts.some(
        (fact) =>
          fact.key.startsWith("requirement.permission-profile.locked.filesystem.") &&
          fact.value === "deny",
      ),
    ).toBe(true);
    expect(
      first.semanticFacts.find((fact) => fact.value === "allow:packages.example.com"),
    ).toMatchObject({ effect: "exposure", value: "allow:packages.example.com" });
    expect(first.inventory.hooks.some((hook) => hook.handler === "node")).toBe(true);

    const serialized = JSON.stringify(first);
    for (const secret of [
      "super-user-secret-value",
      "super-project-secret-value",
      "super-argument-secret-value",
      "super-query-secret-value",
      "hidden-tenant",
      "super-header-secret-value",
      "sk-proj-abcdefghijklmnopqrstuvwxyz",
      "hidden-header-value",
      "super-hook-secret-value",
      "managed-hook-secret",
      "managed-secret",
      "managed-inline-secret",
      "managed-plugin-secret",
      "managed-password",
      "managed-plugin-token",
      "fragment-secret",
      "proxy-secret",
      "hidden",
    ]) {
      expect(serialized).not.toContain(secret);
    }
    expect(requests).toBe(0);
    await expect(readFile(path.join(fixture.project, "executed.txt"), "utf8")).rejects.toThrow();
    expect(parseCodexHarnessSnapshot(`${JSON.stringify(first)}\n`)).toEqual(first);

    const malformedNestedValue = structuredClone(first) as unknown as {
      inventory: { apps: Array<{ enabled: { value: unknown } }> };
    };
    const declaredApp = malformedNestedValue.inventory.apps.find(
      (app) => app.enabled.value !== undefined,
    );
    expect(declaredApp).toBeDefined();
    if (declaredApp !== undefined) declaredApp.enabled.value = "not-a-boolean";
    expect(() => parseCodexHarnessSnapshot(JSON.stringify(malformedNestedValue))).toThrow(
      /inventory\.apps/u,
    );

    const validButTampered = structuredClone(first) as unknown as {
      project: { configApplicability: string };
    };
    validButTampered.project.configApplicability = "ignored";
    expect(() => parseCodexHarnessSnapshot(JSON.stringify(validButTampered))).toThrow(
      /harness\.id/u,
    );
  });

  it("keeps an untrusted project layer visible but excludes it from the local composite", async () => {
    const fixture = await materializeFixture(9);
    const user = (await readFile(fixture.userConfig, "utf8")).replace(
      'trust_level = "trusted"',
      'trust_level = "untrusted"',
    );
    await writeFile(fixture.userConfig, user);

    const snapshot = await snapshotCodexHarness(fixture.project, {
      projectConfig: fixture.projectConfig,
      requirements: null,
      userConfig: fixture.userConfig,
    });

    expect(snapshot.project.configApplicability).toBe("ignored");
    expect(snapshot.semanticFacts.find((fact) => fact.key === "approval.policy")?.value).toBe(
      "on-request",
    );
    expect(
      snapshot.inventory.mcpServers.find((entry) => entry.source.layer === "project-config"),
    ).toMatchObject({ applicability: "ignored" });
    expect(snapshot.coverage.find((entry) => entry.area === "project-config")).toMatchObject({
      state: "ignored",
    });
  });

  it("does not guess project applicability or omitted runtime defaults", async () => {
    const fixture = await materializeFixture(9);
    const snapshot = await snapshotCodexHarness(fixture.project, {
      projectConfig: fixture.projectConfig,
      requirements: null,
      userConfig: null,
    });

    expect(snapshot.project).toMatchObject({
      configApplicability: "unknown",
      trust: { state: "unavailable" },
    });
    expect(snapshot.semanticFacts.find((fact) => fact.key === "approval.policy")).toBeUndefined();
    expect(snapshot.coverage.find((entry) => entry.area === "runtime-defaults")).toMatchObject({
      state: "unavailable",
    });
  });

  it("binds caller-observed Codex versions without invoking a binary", async () => {
    const fixture = await materializeFixture(9);
    const baseline = await snapshotCodexHarness(fixture.project, {
      codexVersion: "0.138.0",
      projectConfig: null,
      requirements: null,
      userConfig: fixture.userConfig,
    });
    const current = await snapshotCodexHarness(fixture.project, {
      codexVersion: "0.139.0",
      projectConfig: null,
      requirements: null,
      userConfig: fixture.userConfig,
    });

    expect(current.capture.inputSha256).not.toBe(baseline.capture.inputSha256);
    expect(current.harness.id).not.toBe(baseline.harness.id);
  });

  it("produces a directional semantic permission delta", async () => {
    const workspace = await makeTemporaryDirectory();
    const project = path.join(workspace, "project");
    const baselineConfig = path.join(workspace, "baseline.toml");
    const currentConfig = path.join(workspace, "current.toml");
    await mkdir(project);
    await writeFile(
      baselineConfig,
      'approval_policy = "on-request"\nsandbox_mode = "read-only"\nweb_search = "disabled"\n[features]\ncomputer_use = false\n',
    );
    await writeFile(
      currentConfig,
      'approval_policy = "never"\nsandbox_mode = "danger-full-access"\nweb_search = "live"\n[features]\ncomputer_use = true\n[mcp_servers.remote]\nurl = "https://example.com/mcp"\nenabled = true\n',
    );
    const baseline = await snapshotCodexHarness(project, {
      projectConfig: null,
      requirements: null,
      userConfig: baselineConfig,
    });
    const current = await snapshotCodexHarness(project, {
      projectConfig: null,
      requirements: null,
      userConfig: currentConfig,
    });

    const delta = compareCodexHarnessSnapshots(baseline, current);

    expect(delta.summary.expanded).toBeGreaterThanOrEqual(5);
    expect(delta.changes).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ direction: "expanded", key: "approval.policy" }),
        expect.objectContaining({ direction: "expanded", key: "filesystem.sandbox-mode" }),
        expect.objectContaining({ direction: "expanded", key: "network.web-search" }),
        expect.objectContaining({ direction: "expanded", key: "feature.computer-use" }),
        expect.objectContaining({ direction: "expanded", key: "mcp.remote.enabled" }),
      ]),
    );
  });

  it("classifies explicit denials and guard transitions directionally", async () => {
    const workspace = await makeTemporaryDirectory();
    const project = path.join(workspace, "project");
    const baselineConfig = path.join(workspace, "baseline.toml");
    const currentConfig = path.join(workspace, "current.toml");
    await mkdir(project);
    await writeFile(
      baselineConfig,
      '[features]\ncomputer_use = true\n[features.network_proxy.domains]\n"api.example.com" = "allow"\n[mcp_servers.local]\ncommand = "node"\n',
    );
    await writeFile(
      currentConfig,
      '[features]\ncomputer_use = false\n[features.network_proxy.domains]\n"api.example.com" = "deny"\n[mcp_servers.local]\ncommand = "node"\nenabled_tools = []\n',
    );
    const baseline = await snapshotCodexHarness(project, {
      projectConfig: null,
      requirements: null,
      userConfig: baselineConfig,
    });
    const current = await snapshotCodexHarness(project, {
      projectConfig: null,
      requirements: null,
      userConfig: currentConfig,
    });

    const delta = compareCodexHarnessSnapshots(baseline, current);
    expect(delta.changes).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ direction: "reduced", key: "feature.computer-use" }),
        expect.objectContaining({
          direction: "reduced",
          key: "mcp.local.tool-allowlist-present",
        }),
      ]),
    );
    expect(
      delta.changes.find((change) => change.after?.value === "deny:api.example.com"),
    ).toMatchObject({ direction: "reduced" });
  });

  it("detects redacted URL and hook identity changes and preserves case-distinct ids", async () => {
    const workspace = await makeTemporaryDirectory();
    const project = path.join(workspace, "project");
    const baselineConfig = path.join(workspace, "baseline.toml");
    const currentConfig = path.join(workspace, "current.toml");
    await mkdir(project);
    await writeFile(
      baselineConfig,
      '[mcp_servers.Foo]\nurl = "https://example.com/mcp?token=baseline-url-secret"\n[mcp_servers.foo]\nurl = "https://example.net/mcp"\n[hooks]\n[[hooks.PreToolUse]]\nmatcher = "shell"\n[[hooks.PreToolUse.hooks]]\ntype = "command"\ncommand = "node safe.js --token baseline-hook-secret"\n',
    );
    await writeFile(
      currentConfig,
      '[mcp_servers.Foo]\nurl = "https://example.com/mcp?token=current-url-secret"\n[mcp_servers.foo]\nurl = "https://example.net/mcp"\n[hooks]\n[[hooks.PreToolUse]]\nmatcher = "shell"\n[[hooks.PreToolUse.hooks]]\ntype = "command"\ncommand = "node changed.js --token current-hook-secret"\n',
    );
    const baseline = await snapshotCodexHarness(project, {
      projectConfig: null,
      requirements: null,
      userConfig: baselineConfig,
    });
    const current = await snapshotCodexHarness(project, {
      projectConfig: null,
      requirements: null,
      userConfig: currentConfig,
    });

    expect(parseCodexHarnessSnapshot(JSON.stringify(current))).toEqual(current);
    expect(current.semanticFacts.some((fact) => fact.key === "mcp.Foo.identity")).toBe(true);
    expect(current.semanticFacts.some((fact) => fact.key === "mcp.foo.identity")).toBe(true);
    const delta = compareCodexHarnessSnapshots(baseline, current);
    expect(delta.changes).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ direction: "changed", key: "hook.PreToolUse.0.0" }),
        expect.objectContaining({ direction: "changed", key: "mcp.Foo.identity" }),
      ]),
    );
    const serialized = JSON.stringify({ baseline, current, delta });
    for (const secret of [
      "baseline-url-secret",
      "current-url-secret",
      "baseline-hook-secret",
      "current-hook-secret",
    ]) {
      expect(serialized).not.toContain(secret);
    }
  });

  it("refuses to compare an incomplete local capture", async () => {
    const workspace = await makeTemporaryDirectory();
    const project = path.join(workspace, "project");
    const malformed = path.join(workspace, "malformed.toml");
    await mkdir(project);
    await writeFile(malformed, "[broken\n");
    const incomplete = await snapshotCodexHarness(project, {
      projectConfig: null,
      requirements: null,
      userConfig: malformed,
    });

    expect(() => compareCodexHarnessSnapshots(incomplete, incomplete)).toThrow(/incomplete/u);
  });

  it("withholds empty executable identities while preserving its own JSON roundtrip", async () => {
    const workspace = await makeTemporaryDirectory();
    const project = path.join(workspace, "project");
    const userConfig = path.join(workspace, "config.toml");
    const requirements = path.join(workspace, "requirements.toml");
    await mkdir(project);
    await writeFile(
      userConfig,
      [
        "[mcp_servers.empty]",
        'command = ""',
        'http_headers_helper = ""',
        "[mcp_servers.quoted]",
        `command = "''"`,
        `http_headers_helper = "''"`,
        "[mcp_servers.object]",
        'command = { executable = "", args = ["--must-not-run"] }',
        "[hooks]",
        "[[hooks.PreToolUse]]",
        "[[hooks.PreToolUse.hooks]]",
        'type = "command"',
        'command = ""',
        "[[hooks.PreToolUse.hooks]]",
        'type = "command"',
        `command = "''"`,
        "",
      ].join("\n"),
    );
    await writeFile(
      requirements,
      ["[mcp_servers.managed.identity]", `command = "''"`, ""].join("\n"),
    );

    const snapshot = await snapshotCodexHarness(project, {
      projectConfig: null,
      requirements,
      userConfig,
    });

    for (const id of ["empty", "managed", "object", "quoted"]) {
      expect(snapshot.inventory.mcpServers.find((server) => server.id === id)?.identity).toEqual({
        kind: "unavailable",
        reason: "No non-empty stdio executable was declared.",
      });
    }
    for (const id of ["empty", "quoted"]) {
      expect(
        snapshot.inventory.mcpServers.find((server) => server.id === id)?.httpHeadersHelper,
      ).toMatchObject({ state: "unavailable" });
    }
    expect(snapshot.inventory.hooks.map((hook) => hook.handler)).toEqual([
      "unavailable",
      "unavailable",
    ]);
    expect(parseCodexHarnessSnapshot(formatCodexHarnessJson(snapshot))).toEqual(snapshot);
  });

  it("rejects generated and formatted snapshots above the report byte ceiling", async () => {
    const workspace = await makeTemporaryDirectory();
    const project = path.join(workspace, "project");
    const userConfig = path.join(workspace, "config.toml");
    await mkdir(project);
    const appSections = Array.from(
      { length: 10_000 },
      (_value, index) => `[apps.app${index.toString().padStart(5, "0")}]\nenabled = true\n`,
    ).join("");
    await writeFile(userConfig, appSections);

    await expect(
      snapshotCodexHarness(project, {
        projectConfig: null,
        requirements: null,
        userConfig,
      }),
    ).rejects.toThrow(/report limit/u);

    const small = await snapshotCodexHarness(project, {
      projectConfig: null,
      requirements: null,
      userConfig: null,
    });
    const oversized = structuredClone(small);
    const writableOversized = oversized as unknown as {
      coverage: Array<{ reason: string }>;
    };
    const firstCoverage = writableOversized.coverage[0];
    expect(firstCoverage).toBeDefined();
    if (firstCoverage !== undefined) {
      firstCoverage.reason = "x".repeat(MAX_HARNESS_REPORT_BYTES);
    }
    expect(() => formatCodexHarnessJson(oversized)).toThrow(/report limit/u);
  }, 20_000);

  it("fails closed for malformed and linked configuration inputs", async () => {
    const workspace = await makeTemporaryDirectory();
    const project = path.join(workspace, "project");
    const malformed = path.join(workspace, "malformed.toml");
    await mkdir(project);
    await writeFile(malformed, "[broken\nsecret = 'must-not-leak'\n");
    const malformedSnapshot = await snapshotCodexHarness(project, {
      projectConfig: null,
      requirements: null,
      userConfig: malformed,
    });
    expect(malformedSnapshot.capture.complete).toBe(false);
    expect(JSON.stringify(malformedSnapshot)).not.toContain("must-not-leak");
    expect(malformedSnapshot.diagnostics).toMatchObject([
      { code: "HARNESS_CONFIG_INVALID", layer: "user-config" },
    ]);

    const linked = path.join(workspace, "linked.toml");
    try {
      await import("node:fs/promises").then(({ symlink }) => symlink(malformed, linked, "file"));
    } catch (error) {
      if (process.platform === "win32") return;
      throw error;
    }
    const linkedSnapshot = await snapshotCodexHarness(project, {
      projectConfig: null,
      requirements: null,
      userConfig: linked,
    });
    expect(linkedSnapshot.capture.complete).toBe(false);
    expect(linkedSnapshot.diagnostics).toMatchObject([
      { code: "HARNESS_CONFIG_UNSAFE", layer: "user-config" },
    ]);
  });

  it.runIf(process.platform === "win32")(
    "freezes the detected ProgramData requirements path before asynchronous capture",
    async () => {
      const workspace = await makeTemporaryDirectory();
      const project = path.join(workspace, "project");
      const firstProgramData = path.join(workspace, "program-data-a");
      const secondProgramData = path.join(workspace, "program-data-b");
      const firstRequirements = path.join(firstProgramData, "OpenAI", "Codex", "requirements.toml");
      const secondRequirements = path.join(
        secondProgramData,
        "OpenAI",
        "Codex",
        "requirements.toml",
      );
      const firstContents = "# frozen ProgramData evidence\n";
      await Promise.all([
        mkdir(project),
        mkdir(path.dirname(firstRequirements), { recursive: true }),
        mkdir(path.dirname(secondRequirements), { recursive: true }),
      ]);
      await Promise.all([
        writeFile(firstRequirements, firstContents),
        writeFile(secondRequirements, "# mutated ProgramData evidence\n"),
      ]);

      const originalProgramData = process.env.ProgramData;
      try {
        process.env.ProgramData = firstProgramData;
        const resolution = freezeCodexHarnessResolution(project, {
          projectConfig: null,
          userConfig: null,
        });
        process.env.ProgramData = secondProgramData;

        const snapshot = await snapshotCodexHarnessWithResolution(resolution);
        const requirements = snapshot.layers.find((layer) => layer.kind === "requirements");

        expect(requirements).toMatchObject({
          pathSource: "detected",
          sha256: createHash("sha256").update(firstContents).digest("hex"),
          status: "parsed",
        });
      } finally {
        restoreEnvironmentVariable("ProgramData", originalProgramData);
      }
    },
  );
});

async function materializeFixture(port: number): Promise<{
  project: string;
  projectConfig: string;
  requirements: string;
  userConfig: string;
}> {
  const workspace = await makeTemporaryDirectory();
  const project = path.join(workspace, "project");
  const projectConfig = path.join(project, ".codex", "config.toml");
  const userConfig = path.join(workspace, "config.toml");
  const requirements = path.join(workspace, "requirements.toml");
  await mkdir(path.dirname(projectConfig), { recursive: true });
  const escapedProject = project.replaceAll("\\", "\\\\").replaceAll('"', '\\"');
  const replacements = (value: string): string =>
    value.replaceAll("__PROJECT_ROOT__", escapedProject).replaceAll("__PORT__", port.toString());
  await Promise.all([
    writeFixture("user-config.toml", userConfig, replacements),
    writeFixture("project-config.toml", projectConfig, replacements),
    writeFixture("requirements.toml", requirements, replacements),
    writeFixture("must-not-run.mjs", path.join(project, "must-not-run.mjs"), replacements),
  ]);
  return { project, projectConfig, requirements, userConfig };
}

async function writeFixture(
  fixture: string,
  destination: string,
  transform: (value: string) => string,
): Promise<void> {
  await writeFile(destination, transform(await readFile(path.join(fixtureRoot, fixture), "utf8")));
}

async function makeTemporaryDirectory(): Promise<string> {
  const directory = await mkdtemp(path.join(tmpdir(), "uleravo-codex-harness-"));
  temporaryDirectories.push(directory);
  return directory;
}

async function listen(server: Server): Promise<number> {
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => resolve());
  });
  const address = server.address();
  if (address === null || typeof address === "string") throw new Error("Test server has no port.");
  return address.port;
}

function restoreEnvironmentVariable(name: string, value: string | undefined): void {
  if (value === undefined) {
    delete process.env[name];
  } else {
    process.env[name] = value;
  }
}
