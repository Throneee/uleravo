import { mkdir, mkdtemp, readdir, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { main } from "../src/cli.js";

const minimalSkill = fileURLToPath(new URL("./fixtures/skills/minimal", import.meta.url));
const temporaryDirectories: string[] = [];

beforeEach(() => {
  vi.spyOn(process.stdout, "write").mockImplementation(() => true);
  vi.spyOn(process.stderr, "write").mockImplementation(() => true);
});

afterEach(async () => {
  await Promise.all(
    temporaryDirectories
      .splice(0)
      .map((directory) => rm(directory, { force: true, recursive: true })),
  );
});

describe("artifact snapshot CLI", () => {
  it("emits a complete JSON snapshot with explicit user-supplied provenance", async () => {
    const exitCode = await main([
      "snapshot",
      minimalSkill,
      "--kind",
      "skill",
      "--format",
      "json",
      "--repository-url",
      "https://github.com/example/skill.git",
      "--commit-sha",
      "a".repeat(40),
    ]);
    const output = vi.mocked(process.stdout.write).mock.calls.join("");
    const snapshot = JSON.parse(output) as {
      artifact: { repository: { commit: { state: string }; url: { state: string } } };
      complete: boolean;
      documentType: string;
    };

    expect(exitCode).toBe(0);
    expect(snapshot.complete).toBe(true);
    expect(snapshot.documentType).toBe("uleravo.artifact-snapshot");
    expect(snapshot.artifact.repository.commit.state).toBe("endpoint-unverified");
    expect(snapshot.artifact.repository.url.state).toBe("endpoint-unverified");
  });

  it("writes atomically and exits 2 for an incomplete snapshot", async () => {
    const workspace = await makeTemporaryDirectory();
    const directory = path.join(workspace, "skill");
    const output = path.join(workspace, "snapshot.json");
    await mkdir(directory);
    await writeFile(path.join(directory, "SKILL.md"), "not front matter\n");

    expect(
      await main([
        "snapshot",
        directory,
        "--kind",
        "skill",
        "--format",
        "json",
        "--output",
        output,
      ]),
    ).toBe(2);
    const parsed = JSON.parse(await readFile(output, "utf8")) as { complete: boolean };
    expect(parsed.complete).toBe(false);
  });

  it("rejects self-output and preserves deterministic identity for external outputs", async () => {
    const workspace = await makeTemporaryDirectory();
    const skill = path.join(workspace, "skill");
    const firstOutput = path.join(workspace, "first.json");
    const secondOutput = path.join(workspace, "second.json");
    await mkdir(skill);
    await writeFile(
      path.join(skill, "SKILL.md"),
      "---\nname: stable\ndescription: Stable fixture.\n---\n\nFollow instructions.\n",
    );

    expect(
      await main([
        "snapshot",
        skill,
        "--kind",
        "skill",
        "--format",
        "json",
        "--output",
        path.join(skill, "self.json"),
      ]),
    ).toBe(2);
    await expect(readFile(path.join(skill, "self.json"))).rejects.toThrow();

    for (const output of [firstOutput, secondOutput]) {
      expect(
        await main(["snapshot", skill, "--kind", "skill", "--format", "json", "--output", output]),
      ).toBe(0);
    }
    const first = JSON.parse(await readFile(firstOutput, "utf8")) as {
      artifact: { identity: { contentSha256: { value: string } } };
    };
    const second = JSON.parse(await readFile(secondOutput, "utf8")) as typeof first;
    expect(first.artifact.identity.contentSha256.value).toBe(
      second.artifact.identity.contentSha256.value,
    );
  });

  it("never overwrites through a linked output ancestor or leaf", async () => {
    const workspace = await makeTemporaryDirectory();
    const skill = path.join(workspace, "skill");
    const outside = path.join(workspace, "outside");
    const linkedParent = path.join(workspace, "linked-parent");
    await Promise.all([mkdir(skill), mkdir(outside)]);
    await writeFile(
      path.join(skill, "SKILL.md"),
      "---\nname: safe\ndescription: Safe fixture.\n---\n\nFollow instructions.\n",
    );
    const victim = path.join(outside, "victim.json");
    await writeFile(victim, "sentinel\n");
    await symlink(outside, linkedParent, process.platform === "win32" ? "junction" : "dir");

    expect(
      await main([
        "snapshot",
        skill,
        "--kind",
        "skill",
        "--format",
        "json",
        "--output",
        path.join(linkedParent, "victim.json"),
      ]),
    ).toBe(2);
    expect(await readFile(victim, "utf8")).toBe("sentinel\n");

    if (process.platform !== "win32") {
      const linkedLeaf = path.join(workspace, "linked-leaf.json");
      await symlink(victim, linkedLeaf, "file");
      expect(
        await main([
          "snapshot",
          skill,
          "--kind",
          "skill",
          "--format",
          "json",
          "--output",
          linkedLeaf,
        ]),
      ).toBe(2);
      expect(await readFile(victim, "utf8")).toBe("sentinel\n");
    }
    expect((await readdir(workspace)).some((name) => name.endsWith(".tmp"))).toBe(false);
  });

  it("rejects unsupported kinds and unsafe numeric options", async () => {
    expect(await main(["snapshot", minimalSkill, "--kind", "plugin"])).toBe(2);
    expect(await main(["snapshot", minimalSkill, "--kind", "skill", "--max-files", "0"])).toBe(2);
    expect(vi.mocked(process.stderr.write).mock.calls.join(" ")).toContain(
      "currently requires --kind skill",
    );
  });
});

async function makeTemporaryDirectory(): Promise<string> {
  const directory = await mkdtemp(path.join(tmpdir(), "uleravo-cli-skill-"));
  temporaryDirectories.push(directory);
  return directory;
}
