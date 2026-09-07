import { link, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { SkillCapabilityGraphComparison } from "../src/capability-graph/comparison.js";
import { captureSkillCapabilityGraph } from "../src/capability-graph/correlate.js";
import { MAX_CAPABILITY_GRAPH_REPORT_BYTES } from "../src/capability-graph/domain.js";
import { main } from "../src/cli.js";

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

describe("saved graph comparison CLI", () => {
  it("documents the separate saved-graph command and completeness exit codes", async () => {
    expect(await main(["capability-graph-compare", "--help"])).toBe(0);
    expect(stdout()).toContain("capability-graph-compare <baseline.json> <current.json>");
    expect(stdout()).toContain("incomplete/version-limited exit 2");
    expect(stdout()).toContain("never overwrite");
  });

  it.each([
    [],
    ["one.json"],
    ["one.json", "two.json", "three.json"],
    ["one.json", "two.json", "--format", "sarif"],
    ["one.json", "two.json", "--fail-on", "high"],
  ])("rejects invalid usage without a result: %j", async (...args) => {
    expect(await main(["capability-graph-compare", ...args])).toBe(2);
    expect(stdout()).toBe("");
  });

  it("compares actual saved graphs as text and deterministic JSON, preserving byte-only changes", async () => {
    const fixture = await makeFixture();
    const baseline = await fixture.save("baseline");
    expect(await main(["capability-graph-compare", baseline, baseline])).toBe(0);
    expect(stdout()).toContain("Result: unchanged");
    clearOutput();
    await writeFile(
      path.join(fixture.skill, "SKILL.md"),
      "---\nname: synthetic\ndescription: Inert synthetic test.\n---\n\nRead local files carefully.\n",
    );
    const current = await fixture.save("current");
    const args = ["capability-graph-compare", baseline, current, "--format", "json"];
    expect(await main(args)).toBe(0);
    const first = stdout();
    const parsed = JSON.parse(first) as SkillCapabilityGraphComparison;
    expect(parsed).toMatchObject({
      status: "changed",
      observations: { skillBytes: "different", declarations: "same", harnessContext: "same" },
    });
    expect(first).not.toContain(fixture.workspace);
    expect(first).not.toContain("Read local files carefully");
    clearOutput();
    expect(await main(args)).toBe(0);
    expect(stdout()).toBe(first);
    clearOutput();
    const output = path.join(fixture.workspace, "comparison.json");
    expect(await main([...args, "--output", output])).toBe(0);
    expect(await readFile(output, "utf8")).toBe(first);
    expect(stdout()).toBe("");
  });

  it("shows explicit enabled-to-disabled declarations and reverses the comparison direction", async () => {
    const fixture = await makeFixture();
    const baseline = await fixture.save("enabled");
    await writeFile(fixture.config, '[[skills.config]]\npath = "./skill"\nenabled = false\n');
    const current = await fixture.save("disabled");
    for (const [before, after, beforeState, afterState] of [
      [baseline, current, "declared-enabled", "declared-disabled"],
      [current, baseline, "declared-disabled", "declared-enabled"],
    ] as const) {
      clearOutput();
      expect(await main(["capability-graph-compare", before, after, "--format", "json"])).toBe(0);
      expect(JSON.parse(stdout())).toMatchObject({
        status: "changed",
        baseline: { state: beforeState },
        current: { state: afterState },
        observations: { skillBytes: "same", declarations: "different" },
      });
    }
  });

  it("emits incomplete evidence with exit 2, even when baseline and current are identical", async () => {
    const fixture = await makeFixture();
    await writeFile(fixture.config, "[broken\n");
    const incomplete = await fixture.save("incomplete");
    expect(
      await main(["capability-graph-compare", incomplete, incomplete, "--format", "json"]),
    ).toBe(2);
    expect(JSON.parse(stdout())).toMatchObject({
      complete: false,
      status: "incomplete",
      baseline: { state: "unknown" },
      current: { state: "unknown" },
    });
    clearOutput();
    expect(await main(["capability-graph-compare", incomplete, incomplete])).toBe(2);
    expect(stdout()).toContain("Result: incomplete");
    expect(stdout()).toContain("HARNESS_CAPTURE_INCOMPLETE");
    expect(stdout()).not.toContain("Result: unchanged");
  });

  it("rejects malformed, duplicate-key, oversized, inconsistent, unsupported and non-UTF8 inputs before writing any result", async () => {
    const fixture = await makeFixture();
    const valid = await fixture.save("valid");
    const graph = await readFile(valid, "utf8");
    const cases = [
      "{broken",
      graph.replace('"schemaVersion":', '"schemaVersion":"1.0.0","schemaVersion":'),
      " ".repeat(MAX_CAPABILITY_GRAPH_REPORT_BYTES + 1),
      graph.replace('"complete":true', '"complete":false'),
      graph.replace('"version":"1.0.0"', '"version":"2.0.0"'),
      graph
        .replace('"message":', '"unexpected": "synthetic-private-value", "message":')
        .replace('"documentType":', '"unexpected": "synthetic-private-value", "documentType":'),
      Buffer.from([0xff, 0xfe, 0xfd]),
    ];
    const invalid = path.join(fixture.workspace, "invalid.json");
    const output = path.join(fixture.workspace, "must-not-exist.json");
    for (const content of cases) {
      await writeFile(invalid, content);
      for (const inputs of [
        [valid, invalid],
        [invalid, valid],
      ]) {
        clearOutput();
        expect(
          await main([
            "capability-graph-compare",
            ...inputs,
            "--format",
            "json",
            "--output",
            output,
          ]),
        ).toBe(2);
        expect(stdout()).toBe("");
        await expect(readFile(output)).rejects.toThrow();
      }
    }
  });

  it("refuses to overwrite either input, an evidence hardlink, or an existing output", async () => {
    const fixture = await makeFixture();
    const baseline = await fixture.save("baseline");
    const current = await fixture.save("current");
    const alias = path.join(fixture.workspace, "evidence-alias.json");
    await link(baseline, alias);
    const output = path.join(fixture.workspace, "existing.json");
    await writeFile(output, "preserve this evidence\n");
    const originals = await Promise.all(
      [baseline, current, alias, output].map((file) => readFile(file, "utf8")),
    );
    for (const destination of [baseline, current, alias, output]) {
      expect(
        await main(["capability-graph-compare", baseline, current, "--output", destination]),
      ).toBe(2);
    }
    expect(
      await Promise.all([baseline, current, alias, output].map((file) => readFile(file, "utf8"))),
    ).toEqual(originals);
    expect(stdout()).toBe("");
  });
});

function stdout(): string {
  return vi.mocked(process.stdout.write).mock.calls.join("");
}
function clearOutput(): void {
  vi.mocked(process.stdout.write).mockClear();
  vi.mocked(process.stderr.write).mockClear();
}

async function makeFixture() {
  const workspace = await mkdtemp(path.join(tmpdir(), "uleravo-graph-comparison-"));
  temporaryDirectories.push(workspace);
  const skill = path.join(workspace, "skill");
  const project = path.join(workspace, "project");
  const config = path.join(workspace, "config.toml");
  await Promise.all([mkdir(skill), mkdir(project)]);
  await writeFile(
    path.join(skill, "SKILL.md"),
    "---\nname: synthetic\ndescription: Inert synthetic test.\n---\n\nDo nothing.\n",
  );
  await writeFile(config, '[[skills.config]]\npath = "./skill"\nenabled = true\n');
  return {
    config,
    project,
    skill,
    workspace,
    async save(name: string) {
      const graph = await captureSkillCapabilityGraph(skill, project, {
        userConfig: config,
        requirements: null,
      });
      const file = path.join(workspace, `${name}.json`);
      await writeFile(file, JSON.stringify(graph));
      return file;
    },
  };
}
