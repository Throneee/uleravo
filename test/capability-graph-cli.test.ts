import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
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

describe("declared Skill capability-graph CLI", () => {
  it("documents exact controls, bounds, defaults, and exit semantics", async () => {
    expect(await main(["capability-graph", "--help"])).toBe(0);
    const output = vi.mocked(process.stdout.write).mock.calls.join("");

    expect(output).toContain("--skip-user-config");
    expect(output).toContain("--skip-project-config");
    expect(output).toContain("--skip-requirements");
    expect(output).toContain("--max-skill-file-bytes <n>");
    expect(output).toContain("--max-skill-files <count>");
    expect(output).toContain("--max-skill-total-bytes <n>");
    expect(output).toContain("Project root (default: .)");
    expect(output).toContain("capability graphs reached a definitive declared-exposure state");
    expect(output).toContain("Capability-graph unknown exits 2");
  });

  it("emits JSON for exact declared exposure without host paths", async () => {
    const fixture = await makeFixture();
    await writeFile(
      fixture.config,
      '[[skills.config]]\npath = "./skill/SKILL.md"\nenabled = true\n',
    );

    const exitCode = await main([
      "capability-graph",
      fixture.skill,
      fixture.project,
      "--user-config",
      fixture.config,
      "--skip-requirements",
      "--format",
      "json",
    ]);
    const output = vi.mocked(process.stdout.write).mock.calls.join("");
    const parsed = JSON.parse(output) as {
      complete: boolean;
      correlation: { state: string };
      documentType: string;
      scope: { assertion: string; effectAuthority: string; runtimeReachability: string };
    };

    expect(exitCode).toBe(0);
    expect(parsed).toMatchObject({
      complete: true,
      correlation: { state: "declared-enabled" },
      documentType: "uleravo.skill-capability-graph",
      scope: {
        assertion: "declared-exposure-only",
        effectAuthority: "not-established",
        runtimeReachability: "not-observed",
      },
    });
    expect(output).not.toContain(fixture.workspace);
  });

  it.each([
    ["declared-disabled", '[[skills.config]]\npath = "./skill"\nenabled = false\n'],
    ["not-declared", "# no exact Skill declaration\n"],
  ] as const)("exits 0 for a definitive %s correlation", async (expectedState, config) => {
    const fixture = await makeFixture();
    await writeFile(fixture.config, config);

    const exitCode = await main([
      "capability-graph",
      fixture.skill,
      fixture.project,
      "--user-config",
      fixture.config,
      "--skip-requirements",
      "--format",
      "json",
    ]);
    const parsed = JSON.parse(vi.mocked(process.stdout.write).mock.calls.join("")) as {
      correlation: { state: string };
    };

    expect(exitCode).toBe(0);
    expect(parsed.correlation.state).toBe(expectedState);
  });

  it("emits declared-exposure-only text without host paths", async () => {
    const fixture = await makeFixture();
    await writeFile(fixture.config, '[[skills.config]]\npath = "./skill"\nenabled = false\n');

    expect(
      await main([
        "capability-graph",
        fixture.skill,
        fixture.project,
        "--user-config",
        fixture.config,
        "--skip-requirements",
      ]),
    ).toBe(0);
    const output = vi.mocked(process.stdout.write).mock.calls.join("");
    expect(output).toContain("Correlation: declared-disabled");
    expect(output).toContain("Scope: declared exposure only");
    expect(output).not.toContain(fixture.workspace);
  });

  it("emits unknown JSON and exits 2 for incomplete capture", async () => {
    const fixture = await makeFixture();
    await writeFile(fixture.config, "[broken\n");

    const exitCode = await main([
      "capability-graph",
      fixture.skill,
      fixture.project,
      "--user-config",
      fixture.config,
      "--skip-requirements",
      "--format",
      "json",
    ]);
    const parsed = JSON.parse(vi.mocked(process.stdout.write).mock.calls.join("")) as {
      correlation: { state: string };
    };
    expect(exitCode).toBe(2);
    expect(parsed.correlation.state).toBe("unknown");
  });

  it("refuses self-output and contradictory harness controls", async () => {
    const fixture = await makeFixture();
    await writeFile(fixture.config, '[[skills.config]]\npath = "./skill"\nenabled = false\n');
    const selfOutput = path.join(fixture.skill, "graph.json");
    expect(
      await main([
        "capability-graph",
        fixture.skill,
        fixture.project,
        "--user-config",
        fixture.config,
        "--skip-requirements",
        "--output",
        selfOutput,
      ]),
    ).toBe(2);
    await expect(readFile(selfOutput)).rejects.toThrow();

    expect(
      await main([
        "capability-graph",
        fixture.skill,
        "--user-config",
        fixture.config,
        "--skip-user-config",
      ]),
    ).toBe(2);
  });

  it("exits 2 without emitting a graph for incomplete target capture", async () => {
    const fixture = await makeFixture();
    await rm(path.join(fixture.skill, "SKILL.md"));
    await writeFile(fixture.config, "# inert config\n");

    expect(
      await main([
        "capability-graph",
        fixture.skill,
        fixture.project,
        "--user-config",
        fixture.config,
        "--skip-requirements",
        "--format",
        "json",
      ]),
    ).toBe(2);
    expect(vi.mocked(process.stdout.write).mock.calls).toHaveLength(0);
    expect(vi.mocked(process.stderr.write).mock.calls.join("")).toContain(
      "requires a complete exact Skill byte identity",
    );
  });
});

async function makeFixture(): Promise<{
  config: string;
  project: string;
  skill: string;
  workspace: string;
}> {
  const workspace = await mkdtemp(path.join(tmpdir(), "uleravo-graph-cli-"));
  temporaryDirectories.push(workspace);
  const project = path.join(workspace, "project");
  const skill = path.join(workspace, "skill");
  const config = path.join(workspace, "config.toml");
  await Promise.all([mkdir(project), mkdir(skill)]);
  await writeFile(
    path.join(skill, "SKILL.md"),
    "---\nname: cli-fixture\ndescription: Inert CLI fixture.\n---\n\nDo nothing.\n",
  );
  return { config, project, skill, workspace };
}
