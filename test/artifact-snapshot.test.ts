import { access, mkdir, mkdtemp, rename, rm, symlink, utimes, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import { artifactDisplayTarget, collectBoundedEntries } from "../src/artifacts/discovery.js";
import { isPortableArtifactPath } from "../src/artifacts/path.js";
import { parseArtifactSnapshot } from "../src/artifacts/read.js";
import { snapshotSkill } from "../src/artifacts/snapshot.js";
import { formatArtifactSnapshotText } from "../src/formatters/artifact-snapshot.js";
import { redactEvidence } from "../src/redact.js";

const minimalSkill = fileURLToPath(new URL("./fixtures/skills/minimal", import.meta.url));
const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryDirectories
      .splice(0)
      .map((directory) => rm(directory, { force: true, recursive: true })),
  );
});

describe("Agent Skill artifact snapshots", () => {
  it("rejects linked or junction ancestors for directory and exact-manifest targets", async () => {
    const sourceWorkspace = await makeTemporaryDirectory();
    const root = path.join(sourceWorkspace, "skill");
    await mkdir(root);
    await writeFile(
      path.join(root, "SKILL.md"),
      [
        "---",
        "name: linked-ancestor-skill",
        "description: A useful description.",
        "---",
        "Instructions.",
      ].join("\n"),
    );
    const aliasWorkspace = await makeTemporaryDirectory();
    const linkedAncestor = path.join(aliasWorkspace, "linked-ancestor");
    await symlink(
      sourceWorkspace,
      linkedAncestor,
      process.platform === "win32" ? "junction" : "dir",
    );
    const linkedRoot = path.join(linkedAncestor, path.basename(root));

    await expect(snapshotSkill(linkedRoot)).rejects.toThrow(
      /without symbolic-link or junction ancestors/u,
    );
    await expect(snapshotSkill(path.join(linkedRoot, "SKILL.md"))).rejects.toThrow(
      /without symbolic-link or junction ancestors/u,
    );
  });

  it.each([
    "CON",
    "con.txt",
    "CONIN$",
    "conout$.txt",
    "nested/PRN.json",
    "nested/COM¹",
    "nested/com².log",
    "nested/LPT³",
    "nested/trailing.",
    "nested/trailing ",
    "nested/colon:name",
    "nested/star*name",
    `nested/${"a".repeat(256)}`,
  ])("rejects cross-platform hostile path %s", (candidate) => {
    expect(isPortableArtifactPath(candidate)).toBe(false);
  });

  it("bounds safely escaped artifact display targets", () => {
    const rawTarget = `${"\u007F".repeat(122)}----AKIA${"A".repeat(16)}X`;
    const target = artifactDisplayTarget(path.join("root", rawTarget));

    expect(target.length).toBeLessThanOrEqual(1_000);
    expect(target).not.toContain("\u007F");
    expect(redactEvidence(target)).toBe(target);
    expect(target).not.toContain(`AKIA${"A".repeat(16)}`);
  });

  it("stops streaming directory entries after the configured bound plus one", async () => {
    let yielded = 0;
    let closed = false;
    async function* entries(): AsyncGenerator<number> {
      try {
        while (true) {
          yielded += 1;
          yield yielded;
        }
      } finally {
        closed = true;
      }
    }

    const collected = await collectBoundedEntries(entries(), 3);
    expect(collected).toEqual({ entries: [], overflow: true });
    expect(yielded).toBe(4);
    expect(closed).toBe(true);
  });

  it("captures a deterministic raw-byte closure without executing the artifact", async () => {
    const first = await snapshotSkill(minimalSkill);
    const second = await snapshotSkill(path.join(minimalSkill, "SKILL.md"));

    expect(first.complete).toBe(true);
    expect(first.artifact.manifest.name).toMatchObject({
      source: "declared",
      state: "resolved",
      value: "minimal-skill",
    });
    expect(first.artifact.manifest.version).toMatchObject({ state: "unavailable" });
    expect(first.artifact.identity.contentSha256).toEqual(second.artifact.identity.contentSha256);
    expect(first.snapshot.id).toBe(second.snapshot.id);
    expect(first.snapshot.consistency).toBe("best-effort");
    expect(first.closure.files.map((file) => file.path.value)).toEqual([
      "SKILL.md",
      "assets/note.txt",
      "scripts/must-not-run.mjs",
    ]);
    expect(first.coverage).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          area: "capability-normalization",
          claim: expect.objectContaining({ state: "unsupported" }),
        }),
        expect.objectContaining({
          area: "harness-permissions",
          claim: expect.objectContaining({ state: "unavailable" }),
        }),
      ]),
    );
    await expect(access(path.join(minimalSkill, "EXECUTED"))).rejects.toThrow();
  });

  it("changes identity for bytes or paths, but not for timestamps", async () => {
    const directory = await makeSkill("digest-skill", "A useful description.");
    const asset = path.join(directory, "asset.bin");
    await writeFile(asset, Buffer.from([0, 255, 1, 254]));
    const first = await snapshotSkill(directory);
    await utimes(asset, new Date("2020-01-01T00:00:00.000Z"), new Date("2020-01-01T00:00:00.000Z"));
    const timestampOnly = await snapshotSkill(directory);
    await writeFile(asset, Buffer.from([0, 255, 2, 254]));
    const changed = await snapshotSkill(directory);
    await rename(asset, path.join(directory, "renamed.bin"));
    const renamed = await snapshotSkill(directory);

    expect(contentDigest(timestampOnly)).toBe(contentDigest(first));
    expect(contentDigest(changed)).not.toBe(contentDigest(first));
    expect(contentDigest(renamed)).not.toBe(contentDigest(changed));
  });

  it("rejects sensitive data embedded in repository identity", async () => {
    const credential = `sk-${"Q".repeat(24)}`;

    await expect(
      snapshotSkill(minimalSkill, {
        repository: {
          commit: "a".repeat(40),
          url: `https://example.com/repos/${credential}`,
        },
      }),
    ).rejects.toThrow(/Repository URL must not contain sensitive data/u);
  });

  it("rejects repository identity longer than the report claim bound", async () => {
    await expect(
      snapshotSkill(minimalSkill, {
        repository: {
          commit: "a".repeat(40),
          url: `https://example.com/${"a".repeat(10_001)}`,
        },
      }),
    ).rejects.toThrow(/10000-character artifact claim limit/u);
  });

  it("accepts a BOM, quoted values, and multiline YAML scalars", async () => {
    const directory = await makeTemporaryDirectory();
    await writeFile(
      path.join(directory, "SKILL.md"),
      [
        "\uFEFF---",
        'name: "quoted-skill"',
        "description: >",
        "  A folded description for",
        "  a valid skill.",
        "---",
        "",
        "Follow the workflow.",
        "",
      ].join("\r\n"),
    );

    const snapshot = await snapshotSkill(directory);
    expect(snapshot.complete).toBe(true);
    expect(snapshot.artifact.manifest.description).toMatchObject({
      state: "resolved",
      value: "A folded description for a valid skill.",
    });
  });

  it("fails closed when safe display escaping would exceed a claim bound", async () => {
    const directory = await makeTemporaryDirectory();
    await writeFile(
      path.join(directory, "SKILL.md"),
      [
        "---",
        "name: escaped-description",
        `description: "${"\u202E".repeat(1_251)}"`,
        "---",
        "Instructions.",
      ].join("\n"),
    );

    const snapshot = await snapshotSkill(directory);
    expect(snapshot.complete).toBe(false);
    expect(snapshot.diagnostics).toEqual(
      expect.arrayContaining([expect.objectContaining({ code: "SKILL_MANIFEST_INVALID" })]),
    );
    expect(() => parseArtifactSnapshot(JSON.stringify(snapshot))).not.toThrow();
  });

  it("fully redacts manifest text when one replacement creates another credential boundary", async () => {
    const directory = await makeTemporaryDirectory();
    const credential = `AKIA${"A".repeat(16)}`;
    const description = `${credential}SECRETVALUE password=SECRETVALUE`;
    await writeFile(
      path.join(directory, "SKILL.md"),
      [
        "---",
        "name: fixed-point-redaction",
        `description: "${description}"`,
        "---",
        "Instructions.",
      ].join("\n"),
    );

    const snapshot = await snapshotSkill(directory);
    const serialized = JSON.stringify(snapshot);
    expect(snapshot.complete).toBe(true);
    expect(serialized).not.toContain(credential);
    expect(() => parseArtifactSnapshot(serialized)).not.toThrow();
  });

  it("fails closed for a YAML escape that decodes to an unpaired surrogate", async () => {
    const directory = await makeTemporaryDirectory();
    await writeFile(
      path.join(directory, "SKILL.md"),
      ["---", "name: invalid-unicode", 'description: "\\uD800"', "---", "Instructions."].join("\n"),
    );

    const snapshot = await snapshotSkill(directory);
    const serialized = JSON.stringify(snapshot);
    expect(snapshot.complete).toBe(false);
    expect(serialized).not.toContain("\\ud800");
    expect(() => parseArtifactSnapshot(serialized)).not.toThrow();
  });

  it.each([
    [
      "duplicate keys",
      ["---", "name: first", "name: second", "description: valid", "---", "Instructions"].join(
        "\n",
      ),
    ],
    [
      "aliases",
      ["---", "name: &shared aliased", "description: *shared", "---", "Instructions"].join("\n"),
    ],
    [
      "custom tags",
      ["---", "name: !custom tagged", "description: valid", "---", "Instructions"].join("\n"),
    ],
    [
      "missing instructions",
      ["---", "name: empty-body", "description: valid", "---", ""].join("\n"),
    ],
  ])("fails closed for %s", async (_label, manifest) => {
    const directory = await makeTemporaryDirectory();
    await writeFile(path.join(directory, "SKILL.md"), manifest);

    const snapshot = await snapshotSkill(directory);
    expect(snapshot.complete).toBe(false);
    expect(snapshot.diagnostics.some((diagnostic) => diagnostic.type === "error")).toBe(true);
    expect(snapshot.coverage).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          area: "manifest-metadata",
          claim: expect.objectContaining({ state: "unavailable" }),
        }),
      ]),
    );
  });

  it("fails closed for invalid UTF-8 in the required manifest", async () => {
    const directory = await makeTemporaryDirectory();
    await writeFile(path.join(directory, "SKILL.md"), Buffer.from([0xff, 0xfe, 0xfd]));

    const snapshot = await snapshotSkill(directory);
    expect(snapshot.complete).toBe(false);
    expect(snapshot.diagnostics[0]?.message).toContain("UTF-8");
  });

  it("keeps a partial observation but withholds identity when a limit is hit", async () => {
    const directory = await makeSkill("limited-skill", "A useful description.");
    await writeFile(path.join(directory, "extra.txt"), "extra\n");

    const snapshot = await snapshotSkill(directory, { maxFiles: 1 });
    expect(snapshot.complete).toBe(false);
    expect(snapshot.artifact.identity.contentSha256).toMatchObject({ state: "unavailable" });
    expect(snapshot.closure.observedSha256).toMatchObject({ state: "resolved" });
    expect(snapshot.coverage[0]?.claim).toMatchObject({ state: "unresolved" });
  });

  it("keeps bounded incomplete identity stable across creation order", async () => {
    const first = await makeSkill("bounded-skill", "A useful description.");
    const second = await makeSkill("bounded-skill", "A useful description.");
    await writeFile(path.join(first, "a.txt"), "a\n");
    await writeFile(path.join(first, "b.txt"), "b\n");
    await writeFile(path.join(second, "b.txt"), "b\n");
    await writeFile(path.join(second, "a.txt"), "a\n");

    const [firstSnapshot, secondSnapshot] = await Promise.all([
      snapshotSkill(first, { maxFiles: 1 }),
      snapshotSkill(second, { maxFiles: 1 }),
    ]);
    expect(firstSnapshot.complete).toBe(false);
    expect(secondSnapshot.complete).toBe(false);
    expect(firstSnapshot.snapshot.id).toBe(secondSnapshot.snapshot.id);
    expect(firstSnapshot.diagnostics).toEqual(secondSnapshot.diagnostics);
  });

  it("rejects unsafe display-control characters from artifact paths", async () => {
    const directory = await makeSkill("portable-paths", "A useful description.");
    await writeFile(path.join(directory, "misleading\u202Etxt"), "unsafe name\n");

    const snapshot = await snapshotSkill(directory);
    expect(snapshot.complete).toBe(false);
    expect(snapshot.diagnostics).toEqual(
      expect.arrayContaining([expect.objectContaining({ code: "ARTIFACT_NON_PORTABLE_PATH" })]),
    );
    expect(() => parseArtifactSnapshot(JSON.stringify(snapshot))).not.toThrow();
  });

  it("withholds paths that resemble sensitive credentials", async () => {
    const directory = await makeSkill("sensitive-paths", "A useful description.");
    const credential = `ghp_${"A".repeat(36)}`;
    await writeFile(path.join(directory, `${credential}.txt`), "sensitive name\n");

    const snapshot = await snapshotSkill(directory);
    const serialized = JSON.stringify(snapshot);
    expect(snapshot.complete).toBe(false);
    expect(snapshot.diagnostics).toEqual(
      expect.arrayContaining([expect.objectContaining({ code: "ARTIFACT_SENSITIVE_PATH" })]),
    );
    expect(
      snapshot.diagnostics.find((diagnostic) => diagnostic.code === "ARTIFACT_SENSITIVE_PATH")
        ?.file,
    ).toBeUndefined();
    expect(serialized).not.toContain(credential);
    expect(() => parseArtifactSnapshot(serialized)).not.toThrow();
  });

  it("caps diagnostics while retaining the limit and manifest errors", async () => {
    const directory = await makeTemporaryDirectory();
    const pointer = [
      "version https://git-lfs.github.com/spec/v1",
      `oid sha256:${"a".repeat(64)}`,
      "size 12345",
      "",
    ].join("\n");
    for (let start = 0; start < 1_000; start += 50) {
      await Promise.all(
        Array.from({ length: 50 }, async (_value, offset) => {
          const index = start + offset;
          await writeFile(
            path.join(directory, `${index.toString().padStart(4, "0")}.lfs`),
            pointer,
          );
        }),
      );
    }

    const snapshot = await snapshotSkill(directory);
    expect(snapshot.diagnostics).toHaveLength(1_000);
    expect(snapshot.diagnostics).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ code: "ARTIFACT_DIAGNOSTIC_LIMIT" }),
        expect.objectContaining({ code: "SKILL_MANIFEST_MISSING" }),
      ]),
    );
    expect(() => parseArtifactSnapshot(JSON.stringify(snapshot))).not.toThrow();
  });

  it("fails closed before returning a JSON report larger than the reader bound", async () => {
    const directory = await makeSkill("large-report", "A useful description.");
    let nested = directory;
    for (let depth = 0; depth < 45; depth += 1) {
      nested = path.join(nested, `segment-${depth.toString().padStart(2, "0")}-${"x".repeat(38)}`);
    }
    await mkdir(nested, { recursive: true });
    for (let start = 0; start < 999; start += 50) {
      await Promise.all(
        Array.from({ length: Math.min(50, 999 - start) }, async (_value, offset) => {
          const index = start + offset;
          await writeFile(path.join(nested, `${index.toString().padStart(4, "0")}.txt`), "x");
        }),
      );
    }

    await expect(snapshotSkill(directory)).rejects.toThrow(/10000000-byte report limit/u);
  }, 30_000);

  it("never reports a complete closure after an ancestor changes during final-child descent", async () => {
    const directory = await makeSkill("mutable-root", "A useful description.");
    const child = path.join(directory, "z");
    await mkdir(child);
    const content = Buffer.alloc(50_000, 0x61);
    for (let start = 0; start < 600; start += 50) {
      await Promise.all(
        Array.from({ length: 50 }, async (_value, offset) => {
          const index = start + offset;
          await writeFile(path.join(child, `${index.toString().padStart(4, "0")}.bin`), content);
        }),
      );
    }

    const pending = snapshotSkill(directory);
    await delay(50);
    await writeFile(path.join(directory, "hidden.txt"), "added during traversal\n");
    const snapshot = await pending;
    const reportedHidden = snapshot.closure.files.some((file) => file.path.value === "hidden.txt");
    expect(reportedHidden || !snapshot.complete).toBe(true);
    if (!reportedHidden) {
      expect(snapshot.diagnostics).toEqual(
        expect.arrayContaining([expect.objectContaining({ code: "ARTIFACT_DIRECTORY_CHANGED" })]),
      );
    }
  }, 30_000);

  it("fails closed when an auxiliary asset is an unresolved Git LFS pointer", async () => {
    const directory = await makeSkill("lfs-skill", "A useful description.");
    await writeFile(
      path.join(directory, "asset.bin"),
      [
        "version https://git-lfs.github.com/spec/v1",
        `oid sha256:${"a".repeat(64)}`,
        "size 12345",
        "",
      ].join("\n"),
    );

    const snapshot = await snapshotSkill(directory);
    expect(snapshot.complete).toBe(false);
    expect(snapshot.diagnostics).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ file: "asset.bin", message: expect.stringContaining("LFS") }),
      ]),
    );
  });

  it("excludes VCS control data from the documented closure", async () => {
    const directory = await makeSkill("vcs-skill", "A useful description.");
    await mkdir(path.join(directory, ".git"));
    await writeFile(path.join(directory, ".git", "config"), "private metadata\n");

    const snapshot = await snapshotSkill(directory);
    expect(snapshot.complete).toBe(true);
    expect(snapshot.closure.files.map((file) => file.path.value)).toEqual(["SKILL.md"]);
  });

  it("includes regular files named like VCS control directories", async () => {
    const directory = await makeSkill("control-files", "A useful description.");
    for (const name of [".git", ".hg", ".svn"]) {
      await writeFile(path.join(directory, name), `${name}\n`);
    }

    const snapshot = await snapshotSkill(directory);
    expect(snapshot.complete).toBe(true);
    expect(snapshot.closure.files.map((file) => file.path.value)).toEqual([
      ".git",
      ".hg",
      ".svn",
      "SKILL.md",
    ]);
  });

  it("never traverses a nested directory link", async () => {
    const directory = await makeSkill("directory-link", "A useful description.");
    const outside = await makeTemporaryDirectory();
    await writeFile(path.join(outside, "outside-secret.txt"), "outside\n");
    await symlink(
      outside,
      path.join(directory, "linked-directory"),
      process.platform === "win32" ? "junction" : "dir",
    );

    const snapshot = await snapshotSkill(directory);
    expect(snapshot.complete).toBe(false);
    expect(snapshot.diagnostics).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          code: "ARTIFACT_SYMLINK_UNSUPPORTED",
          file: "linked-directory",
        }),
      ]),
    );
    expect(snapshot.closure.files.map((file) => file.path.value)).not.toContain(
      "linked-directory/outside-secret.txt",
    );
  });

  it("does not silently exclude linked VCS control names", async () => {
    const directory = await makeSkill("control-links", "A useful description.");
    const outside = await makeTemporaryDirectory();
    await writeFile(path.join(outside, "outside-secret.txt"), "outside\n");
    for (const name of [".git", ".hg", ".svn"]) {
      await symlink(
        outside,
        path.join(directory, name),
        process.platform === "win32" ? "junction" : "dir",
      );
    }

    const snapshot = await snapshotSkill(directory);
    expect(snapshot.complete).toBe(false);
    expect(
      snapshot.diagnostics
        .filter((diagnostic) => diagnostic.code === "ARTIFACT_SYMLINK_UNSUPPORTED")
        .map((diagnostic) => diagnostic.file),
    ).toEqual([".git", ".hg", ".svn"]);
    expect(snapshot.closure.files.map((file) => file.path.value)).toEqual(["SKILL.md"]);
  });

  it.runIf(process.platform !== "win32")("marks a nested symbolic link as unresolved", async () => {
    const directory = await makeSkill("link-skill", "A useful description.");
    const outside = path.join(await makeTemporaryDirectory(), "outside.txt");
    await writeFile(outside, "outside\n");
    await symlink(outside, path.join(directory, "linked.txt"), "file");

    const snapshot = await snapshotSkill(directory);
    expect(snapshot.complete).toBe(false);
    expect(snapshot.diagnostics).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ file: "linked.txt", message: expect.stringContaining("link") }),
      ]),
    );
    expect(snapshot.artifact.identity.contentSha256).toMatchObject({ state: "unavailable" });
  });

  it("renders unsupported and unavailable coverage visibly", async () => {
    const text = formatArtifactSnapshotText(await snapshotSkill(minimalSkill));
    expect(text).toContain("capability-normalization: unsupported");
    expect(text).toContain("harness-permissions: unavailable");
    expect(text).toContain("Complete: yes");
  });
});

function contentDigest(snapshot: Awaited<ReturnType<typeof snapshotSkill>>): string {
  const claim = snapshot.artifact.identity.contentSha256;
  if (!("value" in claim)) {
    throw new Error("Expected a resolved content digest.");
  }
  return claim.value;
}

async function makeSkill(name: string, description: string): Promise<string> {
  const directory = await makeTemporaryDirectory();
  await writeFile(
    path.join(directory, "SKILL.md"),
    [
      "---",
      `name: ${name}`,
      `description: ${description}`,
      "---",
      "",
      "Follow instructions.",
      "",
    ].join("\n"),
  );
  return directory;
}

async function makeTemporaryDirectory(): Promise<string> {
  const directory = await mkdtemp(path.join(tmpdir(), "uleravo-skill-"));
  temporaryDirectories.push(directory);
  return directory;
}
