import { createHash } from "node:crypto";
import { access, mkdir, mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { artifactContentSha256, artifactObservationSha256 } from "../src/artifacts/digest.js";
import { parseArtifactSnapshot, readArtifactSnapshot } from "../src/artifacts/read.js";
import { snapshotPlugin } from "../src/artifacts/snapshot.js";

const MANIFEST_PATH = ".codex-plugin/plugin.json";
const temporaryDirectories: string[] = [];

const validManifest = {
  description: "A focused Plugin snapshot fixture.",
  name: "fixture-plugin",
  version: "1.2.3",
};

interface MutablePluginSnapshot {
  artifact: {
    adapter: { name: string };
    kind: string;
    manifest: {
      path: { value: string };
      version: unknown;
    };
  };
  diagnostics: unknown[];
}

afterEach(async () => {
  await Promise.all(
    temporaryDirectories
      .splice(0)
      .map((directory) => rm(directory, { force: true, recursive: true })),
  );
});

describe("Plugin artifact snapshots", () => {
  it("rejects linked or junction ancestors for directory and exact-manifest targets", async () => {
    const fixture = await makePlugin();
    const aliasWorkspace = await makeTemporaryDirectory();
    const linkedAncestor = path.join(aliasWorkspace, "linked-ancestor");
    await symlink(
      fixture.workspace,
      linkedAncestor,
      process.platform === "win32" ? "junction" : "dir",
    );
    const linkedRoot = path.join(linkedAncestor, path.basename(fixture.root));

    await expect(snapshotPlugin(linkedRoot)).rejects.toThrow(
      /without symbolic-link or junction ancestors/u,
    );
    await expect(snapshotPlugin(path.join(linkedRoot, MANIFEST_PATH))).rejects.toThrow(
      /without symbolic-link or junction ancestors/u,
    );
  });

  it("rejects an exact manifest reached through a linked .codex-plugin directory", async () => {
    const workspace = await makeTemporaryDirectory();
    const root = path.join(workspace, "plugin");
    const externalManifestDirectory = path.join(workspace, "external-manifest");
    await Promise.all([mkdir(root), mkdir(externalManifestDirectory)]);
    await writeFile(
      path.join(externalManifestDirectory, "plugin.json"),
      `${JSON.stringify(validManifest)}\n`,
    );
    await symlink(
      externalManifestDirectory,
      path.join(root, ".codex-plugin"),
      process.platform === "win32" ? "junction" : "dir",
    );

    await expect(snapshotPlugin(path.join(root, MANIFEST_PATH))).rejects.toThrow(
      /symbolic links or junctions/u,
    );
  });

  it("is deterministic from the root or exact manifest, round-trips through strict readers, and executes nothing", async () => {
    const fixture = await makePlugin({
      ...validManifest,
      hooks: "./hooks/must-not-run.mjs",
    });
    await mkdir(path.join(fixture.root, "hooks"));
    await writeFile(
      path.join(fixture.root, "hooks", "must-not-run.mjs"),
      [
        'import { writeFileSync } from "node:fs";',
        'writeFileSync(new URL("../EXECUTED", import.meta.url), "executed\\n");',
        "",
      ].join("\n"),
    );

    const fromRoot = await snapshotPlugin(fixture.root);
    const fromManifest = await snapshotPlugin(fixture.manifestPath);

    expect(fromRoot).toMatchObject({
      artifact: {
        adapter: { name: "openai-plugin", version: "1.0.0" },
        kind: "plugin",
        manifest: {
          description: { source: "declared", state: "resolved", value: validManifest.description },
          name: { source: "declared", state: "resolved", value: validManifest.name },
          path: { state: "resolved", value: MANIFEST_PATH },
          version: { source: "declared", state: "resolved", value: validManifest.version },
        },
      },
      complete: true,
      diagnostics: [],
    });
    expect(fromRoot.closure.files.map((file) => file.path.value)).toEqual([
      MANIFEST_PATH,
      "hooks/must-not-run.mjs",
    ]);
    expect(fromManifest.artifact.identity.contentSha256).toEqual(
      fromRoot.artifact.identity.contentSha256,
    );
    expect(fromManifest.closure).toEqual(fromRoot.closure);
    expect(fromManifest.diagnostics).toEqual(fromRoot.diagnostics);
    expect(fromManifest.snapshot.id).toBe(fromRoot.snapshot.id);

    const serialized = JSON.stringify(fromRoot);
    const reportPath = path.join(fixture.workspace, "plugin.snapshot.json");
    await writeFile(reportPath, `${serialized}\n`);
    expect(parseArtifactSnapshot(serialized)).toEqual(fromRoot);
    await expect(readArtifactSnapshot(reportPath)).resolves.toEqual(fromRoot);
    await expect(access(path.join(fixture.root, "EXECUTED"))).rejects.toThrow();
  });

  it.each(["name", "version", "description"] as const)("requires a non-empty %s", async (field) => {
    const manifest: Record<string, unknown> = { ...validManifest };
    delete manifest[field];
    const fixture = await makePlugin(manifest);

    const snapshot = await snapshotPlugin(fixture.root);

    expect(snapshot.complete).toBe(false);
    expect(snapshot.diagnostics).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          code: "PLUGIN_MANIFEST_INVALID",
          file: MANIFEST_PATH,
          message: expect.stringContaining(field),
        }),
      ]),
    );
    for (const claim of [
      snapshot.artifact.manifest.name,
      snapshot.artifact.manifest.version,
      snapshot.artifact.manifest.description,
    ]) {
      expect(claim).toMatchObject({ state: "unavailable" });
    }
    expect(() => parseArtifactSnapshot(JSON.stringify(snapshot))).not.toThrow();
  });

  it("rejects duplicate manifest keys even when one key is JSON-escaped", async () => {
    const fixture = await makePlugin(
      '{"name":"first","na\\u006de":"second","description":"Valid description.","version":"1.0.0"}',
    );

    const snapshot = await snapshotPlugin(fixture.root);

    expect(snapshot.complete).toBe(false);
    expect(snapshot.diagnostics).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          code: "PLUGIN_MANIFEST_INVALID",
          message: expect.stringContaining("duplicate"),
        }),
      ]),
    );
    expect(() => parseArtifactSnapshot(JSON.stringify(snapshot))).not.toThrow();
  });

  it("fails closed for invalid UTF-8 in the required manifest", async () => {
    const fixture = await makePlugin(Buffer.from([0xff, 0xfe, 0xfd]));

    const snapshot = await snapshotPlugin(fixture.root);

    expect(snapshot.complete).toBe(false);
    expect(snapshot.diagnostics).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          code: "PLUGIN_MANIFEST_INVALID",
          message: expect.stringContaining("UTF-8"),
        }),
      ]),
    );
    expect(() => parseArtifactSnapshot(JSON.stringify(snapshot))).not.toThrow();
  });

  it("rejects a 256001-byte manifest before parsing metadata", async () => {
    const base = Buffer.from(JSON.stringify(validManifest), "utf8");
    const manifest = Buffer.concat([base, Buffer.alloc(256_001 - base.byteLength, 0x20)]);
    expect(manifest.byteLength).toBe(256_001);
    const fixture = await makePlugin(manifest);

    const snapshot = await snapshotPlugin(fixture.root);

    expect(snapshot.complete).toBe(false);
    expect(snapshot.diagnostics).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          code: "PLUGIN_MANIFEST_INVALID",
          message: expect.stringContaining("256000-byte metadata limit"),
        }),
      ]),
    );
    expect(() => parseArtifactSnapshot(JSON.stringify(snapshot))).not.toThrow();
  });

  it("rejects JSON nested 129 levels beneath a manifest field", async () => {
    const base = JSON.stringify(validManifest);
    const nested = `${"[".repeat(129)}null${"]".repeat(129)}`;
    const fixture = await makePlugin(`${base.slice(0, -1)},"nested":${nested}}`);

    const snapshot = await snapshotPlugin(fixture.root);

    expect(snapshot.complete).toBe(false);
    expect(snapshot.diagnostics).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          code: "PLUGIN_MANIFEST_INVALID",
          message: expect.stringContaining("excessive nesting"),
        }),
      ]),
    );
    expect(() => parseArtifactSnapshot(JSON.stringify(snapshot))).not.toThrow();
  });

  it("accepts a UTF-8 BOM before the strict JSON manifest", async () => {
    const fixture = await makePlugin(`\uFEFF${JSON.stringify(validManifest)}`);

    const snapshot = await snapshotPlugin(fixture.root);

    expect(snapshot.complete).toBe(true);
    expect(snapshot.artifact.manifest.name).toMatchObject({
      state: "resolved",
      value: validManifest.name,
    });
  });

  it("rejects a JSON escape that decodes to a lone surrogate", async () => {
    const fixture = await makePlugin(
      `{"description":${JSON.stringify(validManifest.description)},"name":"fixture-\\uD800","version":"1.2.3"}`,
    );

    const snapshot = await snapshotPlugin(fixture.root);

    expect(snapshot.complete).toBe(false);
    expect(snapshot.diagnostics).toEqual(
      expect.arrayContaining([expect.objectContaining({ code: "PLUGIN_MANIFEST_INVALID" })]),
    );
    expect(() => parseArtifactSnapshot(JSON.stringify(snapshot))).not.toThrow();
  });

  it.each([
    ["zero-width", "fixture-\u200Bplugin"],
    ["default-ignorable", "fixture-\u2060plugin"],
    ["bidirectional control", "fixture-\u202Eplugin"],
    ["C0 control", "fixture-\u0001plugin"],
    ["NFC non-ASCII", "caf\u00E9-plugin"],
    ["NFD non-ASCII", "cafe\u0301-plugin"],
  ])("rejects a %s Plugin name outside stable ASCII kebab-case", async (_label, name) => {
    const fixture = await makePlugin({ ...validManifest, name });

    const snapshot = await snapshotPlugin(fixture.root);

    expect(snapshot.complete).toBe(false);
    expect(snapshot.diagnostics).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          code: "PLUGIN_MANIFEST_INVALID",
          message: expect.stringContaining("kebab-case"),
        }),
      ]),
    );
  });

  it.each([
    ["traversing skills path", { skills: "../outside" }, "skills"],
    ["missing MCP file", { mcpServers: "./missing-mcp.json" }, "mcpServers"],
    ["traversing app path", { apps: "../outside.json" }, "apps"],
    ["missing hook file", { hooks: "./missing-hook.mjs" }, "hooks"],
    [
      "traversing interface asset",
      { interface: { logoDark: "../outside.svg" } },
      "interface.logoDark",
    ],
    [
      "missing interface screenshot",
      { interface: { screenshots: ["./missing.png"] } },
      "screenshots",
    ],
  ] as const)("rejects a %s", async (_label, declaration, messageField) => {
    const fixture = await makePlugin({ ...validManifest, ...declaration });

    const snapshot = await snapshotPlugin(fixture.root);

    expect(snapshot.complete).toBe(false);
    expect(snapshot.diagnostics).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          code: "PLUGIN_MANIFEST_INVALID",
          message: expect.stringContaining(messageField),
        }),
      ]),
    );
  });

  it("rejects foreign-kind and warning manifest diagnostics", async () => {
    const fixture = await makePlugin();
    const original = await snapshotPlugin(fixture.root);
    const foreign = JSON.parse(JSON.stringify(original)) as MutablePluginSnapshot;
    foreign.diagnostics = [
      {
        code: "SKILL_MANIFEST_INVALID",
        file: "SKILL.md",
        message: "Invalid Skill metadata.",
        type: "error",
      },
    ];
    expect(() => parseArtifactSnapshot(JSON.stringify(foreign))).toThrow(/another artifact kind/u);

    const warning = JSON.parse(JSON.stringify(original)) as MutablePluginSnapshot;
    warning.diagnostics = [
      {
        code: "PLUGIN_MANIFEST_INVALID",
        file: MANIFEST_PATH,
        message: "Invalid Plugin metadata.",
        type: "warning",
      },
    ];
    expect(() => parseArtifactSnapshot(JSON.stringify(warning))).toThrow(/must be error/u);
  });

  it("accepts a non-empty array of observed Skill directories", async () => {
    const fixture = await makePlugin({
      ...validManifest,
      skills: ["./skills/alpha", "./skills/beta/"],
    });
    await Promise.all([
      mkdir(path.join(fixture.root, "skills", "alpha"), { recursive: true }),
      mkdir(path.join(fixture.root, "skills", "beta"), { recursive: true }),
    ]);
    await Promise.all([
      writeFile(path.join(fixture.root, "skills", "alpha", "SKILL.md"), "alpha\n"),
      writeFile(path.join(fixture.root, "skills", "beta", "SKILL.md"), "beta\n"),
    ]);

    const snapshot = await snapshotPlugin(fixture.root);

    expect(snapshot.complete).toBe(true);
    expect(snapshot.closure.files.map((file) => file.path.value)).toEqual([
      MANIFEST_PATH,
      "skills/alpha/SKILL.md",
      "skills/beta/SKILL.md",
    ]);
  });

  it.each([
    [0, false],
    [1_000, true],
    [1_001, false],
  ] as const)("bounds a skills path array containing %i entries", async (length, complete) => {
    const fixture = await makePlugin({
      ...validManifest,
      skills: Array.from({ length }, () => "./skills/alpha"),
    });
    await mkdir(path.join(fixture.root, "skills", "alpha"), { recursive: true });

    const snapshot = await snapshotPlugin(fixture.root);

    expect(snapshot.complete).toBe(complete);
    if (complete) {
      expect(snapshot.diagnostics).toEqual([]);
    } else {
      expect(snapshot.diagnostics).toEqual(
        expect.arrayContaining([expect.objectContaining({ code: "PLUGIN_MANIFEST_INVALID" })]),
      );
    }
  });

  it("round-trips bounded identity text after safe display escaping expands it", async () => {
    const fixture = await makePlugin({ ...validManifest, version: "\u0001".repeat(256) });

    const snapshot = await snapshotPlugin(fixture.root);

    expect(snapshot.complete).toBe(true);
    expect(snapshot.artifact.manifest.version).toMatchObject({
      redacted: true,
      state: "resolved",
    });
    expect("value" in snapshot.artifact.manifest.version).toBe(true);
    expect(() => parseArtifactSnapshot(JSON.stringify(snapshot))).not.toThrow();
  });

  it("treats an inline mcpServers object as opaque metadata", async () => {
    const fixture = await makePlugin({
      ...validManifest,
      mcpServers: {
        local: {
          args: ["../not-a-plugin-reference", "./also-missing.json"],
          command: "./missing-executable",
        },
      },
    });

    const snapshot = await snapshotPlugin(fixture.root);

    expect(snapshot.complete).toBe(true);
    expect(snapshot.diagnostics).toEqual([]);
  });

  it.each([
    [
      "object",
      {
        onInstall: {
          command: "../not-a-plugin-reference",
          nested: { path: "./missing-hook.mjs" },
        },
      },
    ],
    [
      "object array",
      [
        { command: "../not-a-plugin-reference", event: "install" },
        { command: "./missing-hook.mjs", event: "uninstall" },
      ],
    ],
  ] as const)("does not recursively path-interpret an inline hooks %s", async (_label, hooks) => {
    const fixture = await makePlugin({ ...validManifest, hooks });

    const snapshot = await snapshotPlugin(fixture.root);

    expect(snapshot.complete).toBe(true);
    expect(snapshot.diagnostics).toEqual([]);
  });

  it("rejects a mixed path-and-object hooks array", async () => {
    const fixture = await makePlugin({
      ...validManifest,
      hooks: ["./hooks/observed.mjs", { command: "./opaque-inline-command" }],
    });
    await mkdir(path.join(fixture.root, "hooks"));
    await writeFile(path.join(fixture.root, "hooks", "observed.mjs"), "export {};\n");

    const snapshot = await snapshotPlugin(fixture.root);

    expect(snapshot.complete).toBe(false);
    expect(snapshot.diagnostics).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          code: "PLUGIN_MANIFEST_INVALID",
          message: expect.stringContaining("homogeneous"),
        }),
      ]),
    );
  });

  it("resolves logoDark beneath assets and includes the raw asset in the closure", async () => {
    const fixture = await makePlugin({
      ...validManifest,
      interface: { logoDark: "./assets/logo-dark.svg" },
    });
    await mkdir(path.join(fixture.root, "assets"));
    await writeFile(
      path.join(fixture.root, "assets", "logo-dark.svg"),
      '<svg xmlns="http://www.w3.org/2000/svg"><path d="M0 0h1v1H0z"/></svg>\n',
    );

    const snapshot = await snapshotPlugin(fixture.root);

    expect(snapshot.complete).toBe(true);
    expect(snapshot.closure.files.map((file) => file.path.value)).toEqual([
      MANIFEST_PATH,
      "assets/logo-dark.svg",
    ]);
  });

  it("domain-separates identical closure inputs by artifact kind", () => {
    const bytes = Buffer.from("identical bytes\n");
    const files = [
      {
        bytes,
        relativePath: "identical.bin",
        sha256: createHash("sha256").update(bytes).digest("hex"),
      },
    ];

    expect(artifactContentSha256("plugin", files)).not.toBe(artifactContentSha256("skill", files));
    expect(artifactObservationSha256("plugin", files)).not.toBe(
      artifactObservationSha256("skill", files),
    );
  });

  it.each([
    ["adapter", (root: MutablePluginSnapshot) => (root.artifact.adapter.name = "openai-skill")],
    ["kind", (root: MutablePluginSnapshot) => (root.artifact.kind = "skill")],
    [
      "manifest path",
      (root: MutablePluginSnapshot) => (root.artifact.manifest.path.value = "SKILL.md"),
    ],
    [
      "mixed identity state",
      (root: MutablePluginSnapshot) => {
        root.artifact.manifest.version = {
          evidence: [],
          reason: "withheld",
          source: "observed",
          state: "unavailable",
        };
      },
    ],
  ])("rejects a hybrid Plugin report with mismatched %s", async (_label, mutate) => {
    const fixture = await makePlugin();
    const root = JSON.parse(
      JSON.stringify(await snapshotPlugin(fixture.root)),
    ) as MutablePluginSnapshot;
    mutate(root);

    expect(() => parseArtifactSnapshot(JSON.stringify(root))).toThrow();
  });

  it("returns a parseable incomplete snapshot when the manifest is missing", async () => {
    const workspace = await makeTemporaryDirectory();
    const root = path.join(workspace, "plugin");
    await mkdir(root);

    const snapshot = await snapshotPlugin(root);

    expect(snapshot.complete).toBe(false);
    expect(snapshot.artifact.manifest.path).toMatchObject({
      evidence: [],
      state: "unresolved",
      value: MANIFEST_PATH,
    });
    expect(snapshot.diagnostics).toEqual([
      expect.objectContaining({
        code: "PLUGIN_MANIFEST_MISSING",
        file: MANIFEST_PATH,
      }),
    ]);
    expect(() => parseArtifactSnapshot(JSON.stringify(snapshot))).not.toThrow();
  });
});

async function makePlugin(
  manifest: Record<string, unknown> | string | Buffer = validManifest,
): Promise<{ readonly manifestPath: string; readonly root: string; readonly workspace: string }> {
  const workspace = await makeTemporaryDirectory();
  const root = path.join(workspace, "plugin");
  const manifestPath = path.join(root, MANIFEST_PATH);
  await mkdir(path.dirname(manifestPath), { recursive: true });
  await writeFile(
    manifestPath,
    typeof manifest === "string" || Buffer.isBuffer(manifest)
      ? manifest
      : `${JSON.stringify(manifest, null, 2)}\n`,
  );
  return { manifestPath, root, workspace };
}

async function makeTemporaryDirectory(): Promise<string> {
  const directory = await mkdtemp(path.join(tmpdir(), "uleravo-plugin-snapshot-"));
  temporaryDirectories.push(directory);
  return directory;
}
