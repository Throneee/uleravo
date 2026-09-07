import * as filesystem from "node:fs/promises";
import { mkdir, mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  captureSkillCapabilityGraph,
  isUnsafeConfiguredSkillPath,
} from "../src/capability-graph/correlate.js";
import type { SkillCapabilityGraph } from "../src/capability-graph/domain.js";
import {
  buildCapabilityGraphIdentities,
  capabilityGraphDiagnostic,
  correlationReason,
  deriveCorrelationState,
  type EdgeCore,
} from "../src/capability-graph/identity.js";
import {
  parseSkillCapabilityGraph,
  readSkillCapabilityGraph,
} from "../src/capability-graph/read.js";
import * as safeDirectories from "../src/safe-directory.js";

vi.mock("node:fs/promises", async (importOriginal) => ({
  ...(await importOriginal<typeof filesystem>()),
}));

vi.mock("../src/safe-directory.js", async (importOriginal) => ({
  ...(await importOriginal<typeof safeDirectories>()),
}));

const temporaryDirectories: string[] = [];
const diagnosticEdgeCompatibilityCases = [
  {
    code: "HARNESS_CAPTURE_INCOMPLETE",
    compatible: false,
    diagnosticLayer: undefined,
    edgeLayer: "user-config",
    scenario: "incomplete harness / user edge",
  },
  {
    code: "HARNESS_CAPTURE_INCOMPLETE",
    compatible: false,
    diagnosticLayer: undefined,
    edgeLayer: "project-config",
    scenario: "incomplete harness / project edge",
  },
  {
    code: "SKILL_CAPTURE_CHANGED",
    compatible: false,
    diagnosticLayer: undefined,
    edgeLayer: "user-config",
    scenario: "changed Skill / user edge",
  },
  {
    code: "SKILL_CAPTURE_CHANGED",
    compatible: false,
    diagnosticLayer: undefined,
    edgeLayer: "project-config",
    scenario: "changed Skill / project edge",
  },
  {
    code: "DECLARATION_LAYER_DISABLED",
    compatible: false,
    diagnosticLayer: "user-config",
    edgeLayer: "user-config",
    scenario: "disabled user layer / user edge",
  },
  {
    code: "DECLARATION_LAYER_DISABLED",
    compatible: true,
    diagnosticLayer: "user-config",
    edgeLayer: "project-config",
    scenario: "disabled user layer / project edge",
  },
  {
    code: "DECLARATION_LAYER_DISABLED",
    compatible: false,
    diagnosticLayer: "project-config",
    edgeLayer: "project-config",
    scenario: "disabled project layer / project edge",
  },
  {
    code: "DECLARATION_LAYER_DISABLED",
    compatible: true,
    diagnosticLayer: "project-config",
    edgeLayer: "user-config",
    scenario: "disabled project layer / user edge",
  },
  {
    code: "DECLARATION_CONTEXT_UNAVAILABLE",
    compatible: false,
    diagnosticLayer: "user-config",
    edgeLayer: "user-config",
    scenario: "unavailable user context / user edge",
  },
  {
    code: "DECLARATION_CONTEXT_UNAVAILABLE",
    compatible: true,
    diagnosticLayer: "user-config",
    edgeLayer: "project-config",
    scenario: "unavailable user context / project edge",
  },
  {
    code: "DECLARATION_CONTEXT_UNAVAILABLE",
    compatible: false,
    diagnosticLayer: "project-config",
    edgeLayer: "project-config",
    scenario: "unavailable project context / project edge",
  },
  {
    code: "DECLARATION_CONTEXT_UNAVAILABLE",
    compatible: true,
    diagnosticLayer: "project-config",
    edgeLayer: "user-config",
    scenario: "unavailable project context / user edge",
  },
] as const;

afterEach(async () => {
  vi.restoreAllMocks();
  await Promise.all(
    temporaryDirectories
      .splice(0)
      .map((directory) => rm(directory, { force: true, recursive: true })),
  );
});

describe("declared Skill capability graph", () => {
  it("rejects network, device, rooted, drive-relative, and parent-traversal paths before I/O", () => {
    expect(isUnsafeConfiguredSkillPath("\\\\server\\share\\skill", "win32")).toBe(true);
    expect(isUnsafeConfiguredSkillPath("\\\\?\\C:\\skill", "win32")).toBe(true);
    expect(isUnsafeConfiguredSkillPath("\\\\.\\NUL", "win32")).toBe(true);
    expect(isUnsafeConfiguredSkillPath("\\rooted", "win32")).toBe(true);
    expect(isUnsafeConfiguredSkillPath("C:drive-relative", "win32")).toBe(true);
    expect(isUnsafeConfiguredSkillPath("../escape", "win32")).toBe(true);
    expect(isUnsafeConfiguredSkillPath("C:\\local\\skill", "win32")).toBe(false);
    expect(isUnsafeConfiguredSkillPath("./contained/skill", "win32")).toBe(false);
  });

  it.each([
    [true, "declared-enabled"],
    [false, "declared-disabled"],
  ] as const)("correlates one exact explicit enabled=%s declaration", async (enabled, state) => {
    const fixture = await makeFixture();
    await writeFile(
      fixture.userConfig,
      `[[skills.config]]\npath = "./skill"\nenabled = ${enabled.toString()}\n[mcp_servers.inert]\ncommand = "node"\nargs = ["./skill/must-not-run.mjs"]\nenv = { API_KEY = "sk-${"Q".repeat(32)}" }\n[hooks]\n[[hooks.PreToolUse]]\n[[hooks.PreToolUse.hooks]]\ntype = "command"\ncommand = "node ./skill/must-not-run.mjs"\n`,
    );

    const first = await graph(fixture);
    const second = await graph(fixture);
    const throughManifest = await captureSkillCapabilityGraph(
      path.join(fixture.skill, "SKILL.md"),
      path.join(fixture.project, "."),
      { requirements: null, userConfig: fixture.userConfig },
    );

    expect(first).toEqual(second);
    expect(throughManifest).toEqual(first);
    expect(first).toMatchObject({
      complete: true,
      correlation: { state },
      scope: {
        assertion: "declared-exposure-only",
        effectAuthority: "not-established",
        runtimeReachability: "not-observed",
      },
    });
    expect(first.edges).toMatchObject([
      {
        applicability: "applied",
        count: 1,
        enablement: enabled ? "enabled" : "disabled",
        identity: "exact-content",
        layer: "user-config",
      },
    ]);
    expect(JSON.stringify(first)).not.toContain(fixture.workspace);
    expect(JSON.stringify(first)).not.toContain(`sk-${"Q".repeat(32)}`);
    await expect(readFile(path.join(fixture.skill, "executed.txt"), "utf8")).rejects.toThrow();
  });

  it("distinguishes relative and absolute user declarations of same-name different bytes", async () => {
    const fixture = await makeFixture();
    const declared = path.join(fixture.workspace, "declared");
    await mkdir(declared);
    await writeSkill(declared, "minimal-skill", "Different bytes.");
    await writeFile(fixture.userConfig, '[[skills.config]]\npath = "./declared"\nenabled = true\n');

    const relative = await graph(fixture);

    expect(relative.correlation.state).toBe("not-declared");
    expect(relative.edges).toEqual([]);
    expect(relative.diagnostics).toEqual([]);

    await writeFile(
      fixture.userConfig,
      `[[skills.config]]\npath = ${JSON.stringify(declared)}\nenabled = true\n`,
    );
    const absolute = await graph(fixture);

    expect(absolute.correlation.state).toBe("not-declared");
    expect(absolute.edges).toEqual([]);
    expect(absolute.diagnostics).toEqual([]);
  });

  it.each([
    { applicability: "applied", trust: "trusted" },
    { applicability: "ignored", trust: "untrusted" },
    { applicability: "unknown", trust: undefined },
  ] as const)(
    "makes an unrelated project absolute path existence-independent when applicability is $applicability",
    async ({ trust }) => {
      const fixture = await makeFixture();
      const unrelated = path.join(fixture.workspace, "unrelated-external-skill");
      const projectConfig = await writeProjectSkillDeclaration(fixture, unrelated, trust);
      const configBefore = await readFile(projectConfig);

      const absent = await graph(fixture);
      await mkdir(unrelated);
      await writeSkill(unrelated, "minimal-skill", "Unrelated external bytes.");
      const present = await graph(fixture);

      expect(await readFile(projectConfig)).toEqual(configBefore);
      expect(present).toEqual(absent);
      expect(absent).toMatchObject({ complete: false, correlation: { state: "unknown" } });
      expect(absent.edges).toEqual([]);
      expect(absent.diagnostics).toEqual([
        capabilityGraphDiagnostic("DECLARATION_PATH_UNSAFE", "project-config"),
      ]);
      expect(present.graph.id).toBe(absent.graph.id);
      expect(present.correlation.id).toBe(absent.correlation.id);
    },
  );

  it.each([
    { declaration: "root", target: "root" },
    { declaration: "manifest", target: "root" },
    { declaration: "root", target: "manifest" },
    { declaration: "manifest", target: "manifest" },
  ] as const)(
    "accepts the selected absolute project $declaration when the caller supplies the $target",
    async ({ declaration, target }) => {
      const fixture = await makeFixture();
      const manifest = path.join(fixture.skill, "SKILL.md");
      await writeProjectSkillDeclaration(
        fixture,
        declaration === "root" ? fixture.skill : manifest,
        "trusted",
      );

      const result = await captureSkillCapabilityGraph(
        target === "root" ? fixture.skill : manifest,
        fixture.project,
        { requirements: null, userConfig: fixture.userConfig },
      );

      expect(result).toMatchObject({
        complete: true,
        correlation: { state: "declared-enabled" },
        edges: [
          {
            applicability: "applied",
            count: 1,
            enablement: "enabled",
            identity: "exact-content",
            layer: "project-config",
          },
        ],
      });
      expect(result.diagnostics).toEqual([]);
    },
  );

  it("keeps absolute and relative project declarations inside the project context", async () => {
    const fixture = await makeFixture();
    const selected = path.join(fixture.project, "selected-skill");
    const unrelated = path.join(fixture.project, "unrelated-skill");
    await Promise.all([mkdir(selected), mkdir(unrelated)]);
    await Promise.all([
      writeSkill(selected, "minimal-skill", "Project-selected bytes."),
      writeSkill(unrelated, "minimal-skill", "Project-unrelated bytes."),
    ]);

    await writeProjectSkillDeclaration(fixture, unrelated, "trusted");
    const unrelatedResult = await graph(fixture);
    expect(unrelatedResult.correlation.state).toBe("not-declared");
    expect(unrelatedResult.edges).toEqual([]);
    expect(unrelatedResult.diagnostics).toEqual([]);

    await writeProjectSkillDeclaration(fixture, selected, "trusted");
    const absolute = await captureSkillCapabilityGraph(selected, fixture.project, {
      requirements: null,
      userConfig: fixture.userConfig,
    });
    expect(absolute.correlation.state).toBe("declared-enabled");
    expect(absolute.diagnostics).toEqual([]);

    await writeProjectSkillDeclaration(fixture, "./selected-skill", "trusted");
    const relative = await captureSkillCapabilityGraph(selected, fixture.project, {
      requirements: null,
      userConfig: fixture.userConfig,
    });
    expect(relative.correlation.state).toBe("declared-enabled");
    expect(relative.diagnostics).toEqual([]);
  });

  it("rejects existing project-absolute prefix siblings and basename collisions", async () => {
    const fixture = await makeFixture();
    const prefixSibling = `${fixture.skill}-sibling`;
    const basenameCollision = path.join(fixture.workspace, "collision");
    await Promise.all([mkdir(prefixSibling), mkdir(basenameCollision)]);
    await Promise.all([
      writeSkill(prefixSibling, "minimal-skill", "Prefix sibling bytes."),
      writeSkill(basenameCollision, "minimal-skill", "Basename collision bytes."),
    ]);

    for (const declaration of [prefixSibling, path.join(basenameCollision, "SKILL.md")]) {
      await writeProjectSkillDeclaration(fixture, declaration, "trusted");
      const result = await graph(fixture);
      expect(result).toMatchObject({ complete: false, correlation: { state: "unknown" } });
      expect(result.edges).toEqual([]);
      expect(result.diagnostics).toEqual([
        capabilityGraphDiagnostic("DECLARATION_PATH_UNSAFE", "project-config"),
      ]);
    }
  });

  it.runIf(process.platform === "win32")(
    "rejects Windows drive, UNC, device, ADS, and trailing-dot project aliases before discovery",
    async () => {
      const fixture = await makeFixture();
      const projectDrive = path.parse(fixture.project).root.slice(0, 1).toUpperCase();
      const otherDrive = projectDrive === "Z" ? "Y" : "Z";
      const hostileDeclarations = [
        `${otherDrive}:\\uleravo-outside\\skill`,
        "\\\\server.invalid\\share\\skill",
        `\\\\?\\${fixture.skill}`,
        "\\\\.\\NUL",
        `${fixture.skill}:stream`,
        `${fixture.skill}.`,
      ];

      for (const declaration of hostileDeclarations) {
        await writeProjectSkillDeclaration(fixture, declaration, "trusted");
        const result = await graph(fixture);
        expect(result).toMatchObject({ complete: false, correlation: { state: "unknown" } });
        expect(result.edges).toEqual([]);
        expect(result.diagnostics).toEqual([
          capabilityGraphDiagnostic("DECLARATION_PATH_UNSAFE", "project-config"),
        ]);
      }
    },
  );

  it.runIf(process.platform === "win32")(
    "accepts caller-requested case aliases for the selected root and manifest",
    async () => {
      const fixture = await makeFixture();
      const requestedRoot = swapAsciiCase(fixture.skill);
      const requestedManifest = path.join(requestedRoot, "SKILL.md");
      for (const [target, declaration] of [
        [requestedRoot, requestedRoot],
        [requestedRoot, requestedManifest],
        [requestedManifest, requestedRoot],
        [requestedManifest, requestedManifest],
      ] as const) {
        await writeProjectSkillDeclaration(fixture, declaration, "trusted");
        const result = await captureSkillCapabilityGraph(target, fixture.project, {
          requirements: null,
          userConfig: fixture.userConfig,
        });
        expect(result.correlation.state).toBe("declared-enabled");
        expect(result.diagnostics).toEqual([]);
      }
    },
  );

  it.runIf(process.platform === "win32")(
    "accepts a modeled safe Windows 8.3 ancestor alias for selected roots and manifests",
    async () => {
      const fixture = await makeFixture();
      const aliasWorkspace = path.join(path.dirname(fixture.workspace), "ULERAV~1");
      const requestedRoot = path.join(aliasWorkspace, "skill");
      const requestedManifest = path.join(requestedRoot, "SKILL.md");
      const translate = (value: unknown): string => {
        const candidate = String(value);
        return candidate === aliasWorkspace || candidate.startsWith(`${aliasWorkspace}${path.sep}`)
          ? `${fixture.workspace}${candidate.slice(aliasWorkspace.length)}`
          : candidate;
      };
      const originalLstat = filesystem.lstat;
      const originalRealpath = filesystem.realpath;
      vi.spyOn(filesystem, "lstat").mockImplementation((candidate, options) =>
        originalLstat(translate(candidate), options),
      );
      vi.spyOn(filesystem, "realpath").mockImplementation((candidate, options) =>
        originalRealpath(translate(candidate), options),
      );

      for (const declaration of [requestedRoot, requestedManifest]) {
        await writeProjectSkillDeclaration(fixture, declaration, "trusted");
        const options = { requirements: null, userConfig: fixture.userConfig };
        const root = await captureSkillCapabilityGraph(requestedRoot, fixture.project, options);
        const manifest = await captureSkillCapabilityGraph(
          requestedManifest,
          fixture.project,
          options,
        );
        expect(root.correlation.state).toBe("declared-enabled");
        expect(root.diagnostics).toEqual([]);
        expect(manifest).toEqual(root);
      }
    },
  );

  it("accepts a selected directory named SKILL.md and its manifest", async () => {
    const fixture = await makeFixture();
    const selectedRoot = path.join(fixture.workspace, "SKILL.md");
    const selectedManifest = path.join(selectedRoot, "SKILL.md");
    await mkdir(selectedRoot);
    await writeSkill(selectedRoot, "directory-named-manifest", "Inert bytes.");
    for (const declaration of [selectedRoot, selectedManifest]) {
      await writeProjectSkillDeclaration(fixture, declaration, "trusted");
      const options = { requirements: null, userConfig: fixture.userConfig };
      const root = await captureSkillCapabilityGraph(selectedRoot, fixture.project, options);
      const manifest = await captureSkillCapabilityGraph(
        selectedManifest,
        fixture.project,
        options,
      );
      expect(root.correlation.state).toBe("declared-enabled");
      expect(root.diagnostics).toEqual([]);
      expect(manifest).toEqual(root);
    }
  });

  it("freezes the detected CODEX_HOME before the first asynchronous capture step", async () => {
    const workspace = await makeTemporaryDirectory();
    const firstHome = path.join(workspace, "home-a");
    const secondHome = path.join(workspace, "home-b");
    const firstSkill = path.join(firstHome, "skill");
    const requestedSkill = path.join(secondHome, "skill");
    const project = path.join(workspace, "project");
    await Promise.all([
      mkdir(firstSkill, { recursive: true }),
      mkdir(requestedSkill, { recursive: true }),
      mkdir(project),
    ]);
    await Promise.all([
      writeSkill(firstSkill, "minimal-skill", "Different bytes in the first home."),
      writeSkill(requestedSkill, "minimal-skill", "Requested bytes in the second home."),
      writeFile(
        path.join(firstHome, "config.toml"),
        '[[skills.config]]\npath = "./skill"\nenabled = true\n',
      ),
      writeFile(
        path.join(secondHome, "config.toml"),
        '[[skills.config]]\npath = "./skill"\nenabled = true\n',
      ),
    ]);

    const originalCodexHome = process.env.CODEX_HOME;
    try {
      process.env.CODEX_HOME = firstHome;
      const pending = captureSkillCapabilityGraph(requestedSkill, project, {
        requirements: null,
      });
      process.env.CODEX_HOME = secondHome;

      const result = await pending;

      expect(result).toMatchObject({ complete: true, correlation: { state: "not-declared" } });
      expect(result.edges).toEqual([]);
      expect(result.diagnostics).toEqual([]);
    } finally {
      restoreEnvironmentVariable("CODEX_HOME", originalCodexHome);
    }
  });

  it("freezes caller-relative Skill, project, and layer paths before cwd can change", async () => {
    const workspace = await makeTemporaryDirectory();
    const firstRoot = path.join(workspace, "root-a");
    const secondRoot = path.join(workspace, "root-b");
    const firstProject = await writeRelativeGraphFixture(firstRoot, true, "First Skill bytes.");
    await writeRelativeGraphFixture(secondRoot, false, "Second Skill bytes.");
    const absoluteOptions = {
      projectConfig: path.join(firstProject, ".codex", "config.toml"),
      requirements: path.join(firstRoot, "requirements.toml"),
      userConfig: path.join(firstRoot, "config.toml"),
    };
    const expected = await captureSkillCapabilityGraph(
      path.join(firstProject, "skill"),
      firstProject,
      absoluteOptions,
    );
    const cwd = vi.spyOn(process, "cwd").mockReturnValue(firstRoot);

    const pending = captureSkillCapabilityGraph("project/skill", "project", {
      projectConfig: "project/.codex/config.toml",
      requirements: "requirements.toml",
      userConfig: "config.toml",
    });
    cwd.mockReturnValue(secondRoot);
    const actual = await pending;

    expect(actual).toEqual(expected);
    expect(actual.correlation.state).toBe("declared-enabled");
  });

  it.runIf(process.platform === "win32")(
    "keeps graph identities stable across canonical path case aliases",
    async () => {
      const fixture = await makeFixture();
      await writeFile(fixture.userConfig, '[[skills.config]]\npath = "./skill"\nenabled = true\n');
      const canonical = await graph(fixture);
      const aliased = await captureSkillCapabilityGraph(
        swapAsciiCase(fixture.skill),
        swapAsciiCase(fixture.project),
        { requirements: null, userConfig: fixture.userConfig },
      );

      expect(aliased).toEqual(canonical);
      expect(aliased.graph.id).toBe(canonical.graph.id);
      expect(aliased.correlation.id).toBe(canonical.correlation.id);
    },
  );

  it.each([
    { absolute: false, layer: "project-config", manifest: false },
    { absolute: false, layer: "project-config", manifest: true },
    { absolute: true, layer: "project-config", manifest: false },
    { absolute: true, layer: "project-config", manifest: true },
    { absolute: false, layer: "user-config", manifest: false },
    { absolute: false, layer: "user-config", manifest: true },
    { absolute: true, layer: "user-config", manifest: false },
    { absolute: true, layer: "user-config", manifest: true },
  ] as const)(
    "checks ancestors before a linked $layer path (absolute=$absolute, manifest=$manifest)",
    async ({ absolute, layer, manifest }) => {
      const fixture = await makeFixture();
      const base = layer === "project-config" ? fixture.project : fixture.workspace;
      const prefix = path.join(base, "linked-prefix");
      const root = path.join(prefix, "nested", "skill");
      const candidate = manifest ? path.join(root, "SKILL.md") : root;
      const declaration = absolute ? candidate : path.relative(base, candidate);
      if (layer === "project-config") {
        await writeProjectSkillDeclaration(fixture, declaration, "trusted");
      } else {
        await writeFile(
          fixture.userConfig,
          `[[skills.config]]\npath = ${JSON.stringify(declaration)}\nenabled = true\n`,
        );
      }
      const calls = await observeLinkedPrefix(prefix, fixture.project, () => true);

      const result = await graph(fixture);

      expect(result).toMatchObject({ complete: false, correlation: { state: "unknown" } });
      expect(result.edges).toEqual([]);
      expect(result.diagnostics).toEqual([
        capabilityGraphDiagnostic("DECLARATION_PATH_UNSAFE", layer),
      ]);
      expectAncestorRejection(calls, prefix);
    },
  );

  it.each([false, true])(
    "checks ancestors again before lifecycle resolution (manifest=%s)",
    async (manifest) => {
      const fixture = await makeFixture();
      const prefix = path.join(fixture.project, "declaration-prefix");
      const declaredRoot = path.join(prefix, "nested", "skill");
      await mkdir(declaredRoot, { recursive: true });
      await writeSkill(declaredRoot, "different-skill", "Other inert bytes.");
      await writeProjectSkillDeclaration(
        fixture,
        manifest ? path.join(declaredRoot, "SKILL.md") : declaredRoot,
        "trusted",
      );
      let linked = false;
      const calls = await observeLinkedPrefix(prefix, fixture.project, () => linked);
      const originalOpen = filesystem.open;
      let selectedManifestReads = 0;
      vi.spyOn(filesystem, "open").mockImplementation(async (...args) => {
        if (String(args[0]) === path.join(fixture.skill, "SKILL.md")) {
          selectedManifestReads += 1;
          if (selectedManifestReads === 2) {
            linked = true;
            calls.length = 0;
          }
        }
        return originalOpen(...args);
      });

      const result = await graph(fixture);

      expect(linked).toBe(true);
      expect(result).toMatchObject({ complete: false, correlation: { state: "unknown" } });
      expect(result.edges).toEqual([]);
      expect(result.diagnostics).toEqual([
        capabilityGraphDiagnostic("DECLARATION_CONTEXT_CHANGED", "project-config"),
      ]);
      expectAncestorRejection(calls, prefix);
    },
  );

  it("retains the first failed user-context revalidation when later captures succeed", async () => {
    const fixture = await makeFixture();
    await writeFile(fixture.userConfig, '[[skills.config]]\npath = "./skill"\nenabled = true\n');
    const originalCapture = safeDirectories.captureSafeDirectory;
    let userContextCaptures = 0;
    vi.spyOn(safeDirectories, "captureSafeDirectory").mockImplementation(async (directory) => {
      if (path.resolve(directory) === fixture.workspace) {
        userContextCaptures += 1;
        if (userContextCaptures === 2) return undefined;
      }
      return originalCapture(directory);
    });

    const result = await graph(fixture);

    expect(await safeDirectories.captureSafeDirectory(fixture.workspace)).toBeDefined();
    expect(result).toMatchObject({ complete: false, correlation: { state: "unknown" } });
    expect(result.diagnostics).toEqual([
      capabilityGraphDiagnostic("DECLARATION_CONTEXT_CHANGED", "user-config"),
    ]);
    expect(result.edges).toEqual([
      expect.objectContaining({ identity: "exact-content", layer: "user-config" }),
    ]);
    expect(userContextCaptures).toBe(3);
    expect(parseSkillCapabilityGraph(JSON.stringify(result))).toEqual(result);
  });

  it("returns unknown for unknown project applicability", async () => {
    const fixture = await makeFixture();
    const projectSkill = path.join(fixture.project, "skill");
    await writeFile(fixture.userConfig, "# no trust declaration\n");
    await mkdir(path.join(fixture.project, ".codex"));
    await writeFile(
      path.join(fixture.project, ".codex", "config.toml"),
      '[[skills.config]]\npath = "./skill"\nenabled = true\n',
    );
    await mkdir(projectSkill);
    await writeSkill(projectSkill, "minimal-skill", "Project-local bytes.");

    const result = await captureSkillCapabilityGraph(projectSkill, fixture.project, {
      requirements: null,
      userConfig: fixture.userConfig,
    });

    expect(result).toMatchObject({ complete: false, correlation: { state: "unknown" } });
    expect(result.diagnostics).toContainEqual(
      expect.objectContaining({ code: "DECLARATION_APPLICABILITY_UNKNOWN" }),
    );
  });

  it("fails closed for incomplete configuration capture", async () => {
    const fixture = await makeFixture();
    await writeFile(fixture.userConfig, "[broken\nsecret = 'must-not-leak'\n");

    const result = await graph(fixture);

    expect(result).toMatchObject({ complete: false, correlation: { state: "unknown" } });
    expect(result.diagnostics).toContainEqual(
      expect.objectContaining({ code: "HARNESS_CAPTURE_INCOMPLETE", layer: "user-config" }),
    );
    expect(JSON.stringify(result)).not.toContain("must-not-leak");
    expect(parseSkillCapabilityGraph(JSON.stringify(result))).toEqual(result);

    await writeFile(fixture.userConfig, "# valid user configuration\n");
    const requirementsIncomplete = await captureSkillCapabilityGraph(
      fixture.skill,
      fixture.project,
      {
        requirements: path.join(fixture.workspace, "missing-requirements.toml"),
        userConfig: fixture.userConfig,
      },
    );
    expect(requirementsIncomplete.diagnostics).toContainEqual(
      capabilityGraphDiagnostic("HARNESS_CAPTURE_INCOMPLETE"),
    );
    expect(parseSkillCapabilityGraph(JSON.stringify(requirementsIncomplete))).toEqual(
      requirementsIncomplete,
    );
  });

  it("refuses relative escapes and linked declarations without following them", async () => {
    const fixture = await makeFixture();
    const configDirectory = path.join(fixture.workspace, "config-context");
    const escapedConfig = path.join(configDirectory, "config.toml");
    await mkdir(configDirectory);
    await writeFile(escapedConfig, '[[skills.config]]\npath = "../skill"\nenabled = true\n');
    const escaped = await captureSkillCapabilityGraph(fixture.skill, fixture.project, {
      requirements: null,
      userConfig: escapedConfig,
    });
    expect(escaped).toMatchObject({ complete: false, correlation: { state: "unknown" } });
    expect(escaped.diagnostics).toContainEqual(
      expect.objectContaining({ code: "DECLARATION_PATH_UNSAFE" }),
    );

    const link = path.join(fixture.workspace, "linked-skill");
    try {
      await symlink(fixture.skill, link, process.platform === "win32" ? "junction" : "dir");
    } catch (error) {
      if (process.platform === "win32") return;
      throw error;
    }
    await writeFile(
      fixture.userConfig,
      '[[skills.config]]\npath = "./linked-skill"\nenabled = true\n',
    );
    const linked = await graph(fixture);
    expect(linked).toMatchObject({ complete: false, correlation: { state: "unknown" } });
    expect(linked.diagnostics).toContainEqual(
      expect.objectContaining({ code: "DECLARATION_PATH_UNSAFE" }),
    );
  });

  it("returns unknown when exact declaration enablement is omitted", async () => {
    const fixture = await makeFixture();
    await writeFile(fixture.userConfig, '[[skills.config]]\npath = "./skill"\n');

    const result = await graph(fixture);

    expect(result).toMatchObject({ complete: false, correlation: { state: "unknown" } });
    expect(result.diagnostics).toContainEqual(
      expect.objectContaining({ code: "DECLARATION_ENABLEMENT_UNKNOWN" }),
    );
  });

  it("accepts a SKILL.md declaration and rejects ambiguous aliases", async () => {
    const fixture = await makeFixture();
    await writeFile(
      fixture.userConfig,
      '[[skills.config]]\npath = "./skill/SKILL.md"\nenabled = true\n',
    );
    expect((await graph(fixture)).correlation.state).toBe("declared-enabled");

    await writeFile(
      fixture.userConfig,
      `[[skills.config]]\npath = '${path.join(fixture.skill, "SKILL.md")}'\nenabled = true\n`,
    );
    expect((await graph(fixture)).correlation.state).toBe("declared-enabled");

    await writeFile(
      fixture.userConfig,
      [
        "[[skills.config]]",
        'path = "./skill"',
        "enabled = true",
        "[[skills.config]]",
        'path = "./skill/SKILL.md"',
        "enabled = true",
        "",
      ].join("\n"),
    );
    const ambiguous = await graph(fixture);
    expect(ambiguous).toMatchObject({ complete: false, correlation: { state: "unknown" } });
    expect(ambiguous.edges).toMatchObject([{ count: 2, identity: "exact-content" }]);
    expect(ambiguous.diagnostics).toContainEqual(
      expect.objectContaining({ code: "DECLARATION_AMBIGUOUS" }),
    );
  });

  it("strictly parses, reads, canonicalizes, and verifies every graph identity", async () => {
    const fixture = await makeFixture();
    await writeFile(fixture.userConfig, '[[skills.config]]\npath = "./skill"\nenabled = true\n');
    const original = await graph(fixture);
    expect(parseSkillCapabilityGraph(JSON.stringify(original))).toEqual(original);
    expect(parseSkillCapabilityGraph(JSON.stringify(reverseObjectKeys(original)))).toEqual(
      original,
    );

    const file = path.join(fixture.workspace, "graph.json");
    await writeFile(file, JSON.stringify(original));
    expect(await readSkillCapabilityGraph(file)).toEqual(original);

    const unknownField = { ...original, unexpected: true };
    expect(() => parseSkillCapabilityGraph(JSON.stringify(unknownField))).toThrow(/unknown/u);
    const duplicate = JSON.stringify(original).replace(
      '"complete":true',
      '"complete":true,"complete":true',
    );
    expect(() => parseSkillCapabilityGraph(duplicate)).toThrow(/duplicate/u);

    const tampered = structuredClone(original) as unknown as {
      correlation: { state: string };
    };
    tampered.correlation.state = "declared-disabled";
    expect(() => parseSkillCapabilityGraph(JSON.stringify(tampered))).toThrow(/correlation/u);

    const badId = structuredClone(original) as unknown as { graph: { id: string } };
    badId.graph.id = "0".repeat(24);
    expect(() => parseSkillCapabilityGraph(JSON.stringify(badId))).toThrow(/identity/u);

    const impossibleDiagnostics = [
      capabilityGraphDiagnostic("DECLARATION_ENABLEMENT_UNKNOWN", "project-config"),
    ];
    const edgeCores = original.edges.map(({ from: _from, id: _id, to: _to, ...edge }) => edge);
    const impossibleIdentities = buildCapabilityGraphIdentities({
      diagnostics: impossibleDiagnostics,
      edges: edgeCores,
      inputs: original.inputs,
      state: "unknown",
    });
    const semanticallyTampered: SkillCapabilityGraph = {
      ...original,
      complete: false,
      correlation: {
        id: impossibleIdentities.correlationId,
        reason: correlationReason("unknown"),
        state: "unknown",
      },
      diagnostics: impossibleDiagnostics,
      edges: impossibleIdentities.edges,
      graph: { id: impossibleIdentities.graphId },
      nodes: impossibleIdentities.nodes,
    };
    expect(() => parseSkillCapabilityGraph(JSON.stringify(semanticallyTampered))).toThrow(
      /recomputed edge classification/u,
    );

    await writeFile(
      fixture.userConfig,
      [
        "[[skills.config]]",
        'path = "./skill"',
        "enabled = true",
        "[[skills.config]]",
        'path = "./skill/SKILL.md"',
        "enabled = false",
        "",
      ].join("\n"),
    );
    const multiEdge = await graph(fixture);
    expect(multiEdge.edges).toHaveLength(2);
    expect(parseSkillCapabilityGraph(JSON.stringify(multiEdge))).toEqual(multiEdge);
    const reordered = { ...multiEdge, edges: [...multiEdge.edges].reverse() };
    expect(() => parseSkillCapabilityGraph(JSON.stringify(reordered))).toThrow(/ordered/u);
  });

  it("rejects recomputed identities with duplicate semantic declaration groups", async () => {
    const base = await declaredGraphFixture();
    const core = edgeCore(base.edges[0]);
    const duplicateGroups = reidentifyGraph(
      base,
      [core, { ...core, count: 2 }],
      [capabilityGraphDiagnostic("DECLARATION_AMBIGUOUS")],
    );

    expect(() => parseSkillCapabilityGraph(JSON.stringify(duplicateGroups))).toThrow(
      /aggregate duplicate semantic declaration groups/u,
    );
  });

  it.each(diagnosticEdgeCompatibilityCases)(
    "enforces the diagnostic/edge compatibility matrix: $scenario",
    async ({ code, compatible, diagnosticLayer, edgeLayer }) => {
      const base = await declaredGraphFixture();
      const edge: EdgeCore = { ...edgeCore(base.edges[0]), layer: edgeLayer };
      const diagnostic = capabilityGraphDiagnostic(code, diagnosticLayer);
      const candidate = reidentifyGraph(base, [edge], [diagnostic]);

      if (compatible) {
        expect(parseSkillCapabilityGraph(JSON.stringify(candidate))).toEqual(candidate);
      } else {
        expect(() => parseSkillCapabilityGraph(JSON.stringify(candidate))).toThrow(
          /diagnostic\/edge compatibility/u,
        );
      }
    },
  );

  it("represents an identity mismatch only as unknown evidence", async () => {
    const fixture = await makeFixture();
    await writeFile(fixture.userConfig, '[[skills.config]]\npath = "./skill"\nenabled = true\n');
    const base = await graph(fixture);
    const diagnostics = [capabilityGraphDiagnostic("DECLARATION_IDENTITY_MISMATCH")];
    const cores = [
      {
        applicability: "applied" as const,
        count: 1,
        enablement: "enabled" as const,
        identity: "mismatch" as const,
        kind: "declares-skill" as const,
        layer: "user-config" as const,
      },
    ];
    const identities = buildCapabilityGraphIdentities({
      diagnostics,
      edges: cores,
      inputs: base.inputs,
      state: "unknown",
    });
    const mismatch: SkillCapabilityGraph = {
      ...base,
      complete: false,
      correlation: {
        id: identities.correlationId,
        reason: correlationReason("unknown"),
        state: "unknown",
      },
      diagnostics,
      edges: identities.edges,
      graph: { id: identities.graphId },
      nodes: identities.nodes,
    };

    expect(parseSkillCapabilityGraph(JSON.stringify(mismatch))).toEqual(mismatch);
    expect(mismatch.correlation.state).toBe("unknown");
  });
});

async function graph(fixture: Awaited<ReturnType<typeof makeFixture>>) {
  return captureSkillCapabilityGraph(fixture.skill, fixture.project, {
    requirements: null,
    userConfig: fixture.userConfig,
  });
}

async function declaredGraphFixture(): Promise<SkillCapabilityGraph> {
  const fixture = await makeFixture();
  await writeFile(fixture.userConfig, '[[skills.config]]\npath = "./skill"\nenabled = true\n');
  return await graph(fixture);
}

function edgeCore(edge: SkillCapabilityGraph["edges"][number] | undefined): EdgeCore {
  expect(edge).toBeDefined();
  if (edge === undefined) throw new Error("Expected a declared Skill edge fixture.");
  const { from: _from, id: _id, to: _to, ...core } = edge;
  return core;
}

function reidentifyGraph(
  base: SkillCapabilityGraph,
  edges: readonly EdgeCore[],
  diagnostics: readonly SkillCapabilityGraph["diagnostics"][number][],
): SkillCapabilityGraph {
  const state = deriveCorrelationState(edges, diagnostics);
  const identities = buildCapabilityGraphIdentities({
    diagnostics,
    edges,
    inputs: base.inputs,
    state,
  });
  return {
    ...base,
    complete: state !== "unknown",
    correlation: {
      id: identities.correlationId,
      reason: correlationReason(state),
      state,
    },
    diagnostics,
    edges: identities.edges,
    graph: { id: identities.graphId },
    nodes: identities.nodes,
  };
}

async function makeFixture(): Promise<{
  project: string;
  skill: string;
  userConfig: string;
  workspace: string;
}> {
  const workspace = await mkdtemp(path.join(tmpdir(), "uleravo-capability-graph-"));
  temporaryDirectories.push(workspace);
  const project = path.join(workspace, "project");
  const skill = path.join(workspace, "skill");
  const userConfig = path.join(workspace, "config.toml");
  await Promise.all([mkdir(project), mkdir(skill)]);
  await writeSkill(skill, "minimal-skill", "Supplied bytes.");
  await writeFile(
    path.join(skill, "must-not-run.mjs"),
    'await import("node:fs/promises").then(({ writeFile }) => writeFile(new URL("./executed.txt", import.meta.url), "ran"));\n',
  );
  return { project, skill, userConfig, workspace };
}

async function makeTemporaryDirectory(): Promise<string> {
  const directory = await mkdtemp(path.join(tmpdir(), "uleravo-capability-graph-"));
  temporaryDirectories.push(directory);
  return directory;
}

async function writeProjectSkillDeclaration(
  fixture: Awaited<ReturnType<typeof makeFixture>>,
  declarationPath: string,
  trust: "trusted" | "untrusted" | undefined,
): Promise<string> {
  const projectConfig = path.join(fixture.project, ".codex", "config.toml");
  await mkdir(path.dirname(projectConfig), { recursive: true });
  await Promise.all([
    writeFile(
      projectConfig,
      `[[skills.config]]\npath = ${JSON.stringify(declarationPath)}\nenabled = true\n`,
    ),
    writeFile(
      fixture.userConfig,
      trust === undefined
        ? "# no project trust declaration\n"
        : `[projects.${JSON.stringify(fixture.project)}]\ntrust_level = ${JSON.stringify(trust)}\n`,
    ),
  ]);
  return projectConfig;
}

async function writeRelativeGraphFixture(
  root: string,
  enabled: boolean,
  body: string,
): Promise<string> {
  const project = path.join(root, "project");
  const skill = path.join(project, "skill");
  await mkdir(path.join(project, ".codex"), { recursive: true });
  await mkdir(skill);
  await writeSkill(skill, "minimal-skill", body);
  await Promise.all([
    writeFile(
      path.join(root, "config.toml"),
      `[projects.${JSON.stringify(project)}]\ntrust_level = "trusted"\n`,
    ),
    writeFile(
      path.join(project, ".codex", "config.toml"),
      `[[skills.config]]\npath = "./skill"\nenabled = ${enabled.toString()}\n`,
    ),
    writeFile(path.join(root, "requirements.toml"), "# no requirements\n"),
  ]);
  return project;
}

async function writeSkill(root: string, name: string, body: string): Promise<void> {
  await writeFile(
    path.join(root, "SKILL.md"),
    `---\nname: ${name}\ndescription: Inert test fixture.\n---\n\n${body}\n`,
  );
}

interface FilesystemCall {
  readonly operation: "lstat" | "realpath";
  readonly path: string;
}

async function observeLinkedPrefix(
  prefix: string,
  metadataSource: string,
  linked: () => boolean,
): Promise<FilesystemCall[]> {
  const metadata = await filesystem.lstat(metadataSource);
  const linkMetadata = Object.assign(Object.create(metadata) as typeof metadata, {
    isSymbolicLink: () => true,
  });
  const calls: FilesystemCall[] = [];
  const originalLstat = filesystem.lstat;
  const originalRealpath = filesystem.realpath;
  vi.spyOn(filesystem, "lstat").mockImplementation(async (...args) => {
    const candidate = String(args[0]);
    calls.push({ operation: "lstat", path: candidate });
    if (linked() && candidate === prefix) return linkMetadata;
    if (linked() && candidate.startsWith(`${prefix}${path.sep}`)) {
      throw new Error("Synthetic linked-prefix descendant must not be inspected.");
    }
    return originalLstat(...args);
  });
  vi.spyOn(filesystem, "realpath").mockImplementation(async (...args) => {
    const candidate = String(args[0]);
    calls.push({ operation: "realpath", path: candidate });
    if (linked() && (candidate === prefix || candidate.startsWith(`${prefix}${path.sep}`))) {
      throw new Error("Synthetic linked-prefix path must not be resolved.");
    }
    return originalRealpath(...args);
  });
  return calls;
}

function expectAncestorRejection(calls: readonly FilesystemCall[], prefix: string): void {
  expect(
    calls.filter((call) => call.path === prefix || call.path.startsWith(`${prefix}${path.sep}`)),
  ).toEqual([{ operation: "lstat", path: prefix }]);
  let current = path.parse(prefix).root;
  const ancestors = [{ operation: "lstat", path: current }];
  for (const component of prefix.slice(current.length).split(path.sep)) {
    current = path.join(current, component);
    ancestors.push({ operation: "lstat", path: current });
  }
  const rejection = calls.findIndex((call) => call.path === prefix);
  expect(calls.slice(rejection - ancestors.length + 1, rejection + 1)).toEqual(ancestors);
}

function reverseObjectKeys(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(reverseObjectKeys);
  if (typeof value !== "object" || value === null) return value;
  const object = value as Record<string, unknown>;
  return Object.fromEntries(
    Object.keys(object)
      .reverse()
      .map((key) => [key, reverseObjectKeys(object[key])]),
  );
}

function restoreEnvironmentVariable(name: string, value: string | undefined): void {
  if (value === undefined) {
    delete process.env[name];
  } else {
    process.env[name] = value;
  }
}

function swapAsciiCase(value: string): string {
  return value.replace(/[A-Za-z]/gu, (character) =>
    character === character.toUpperCase() ? character.toLowerCase() : character.toUpperCase(),
  );
}
