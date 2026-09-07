import { link, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { captureSkillCapabilityGraph } from "../src/capability-graph/correlate.js";
import {
  MAX_SKILL_REVIEW_RECEIPT_BYTES,
  type SkillReviewReceipt,
} from "../src/capability-graph/review.js";
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

describe("Skill review record/check CLI", () => {
  it("documents record/check, their local exits, advisory scope and recapture guidance", async () => {
    expect(await main(["review-record", "--help"])).toBe(0);
    expect(stdout()).toContain("review-record <graph.json>");
    expect(stdout()).toContain("review-check <receipt.json> <current.json>");
    expect(stdout()).toContain("0 matches-evidence, 1 changed-since-review, 2 cannot-check/error");
    expect(stdout()).toContain("Recapture before checking");
    expect(stdout()).toContain("caller-declared and unsigned");
    expect(stdout()).toContain("never overwrite");
  });

  it.each([
    ["review-record"],
    ["review-record", "one", "two"],
    ["review-record", "one", "--format", "sarif"],
    ["review-record", "one", "--disposition", "approved"],
    ["review-check"],
    ["review-check", "one"],
    ["review-check", "one", "two", "three"],
    ["review-check", "one", "two", "--format", "sarif"],
    ["review-check", "one", "two", "--fail-on", "high"],
  ])("rejects invalid usage without output: %j", async (...args) => {
    expect(await main(args)).toBe(2);
    expect(stdout()).toBe("");
  });

  it("retains a complete review as text/JSON, reads it back and checks newly captured matching evidence", async () => {
    const fixture = await makeFixture();
    const baseline = await fixture.save("baseline");
    expect(await main(["review-record", baseline])).toBe(0);
    expect(stdout()).toContain("reviewed-captured-evidence (caller-declared)");
    expect(stdout()).toContain("unsigned-unauthenticated");
    clearOutput();
    const args = ["review-record", baseline, "--format", "json"];
    expect(await main(args)).toBe(0);
    const first = stdout();
    expect(JSON.parse(first)).toMatchObject({
      documentType: "uleravo.skill-review-receipt",
      graph: { complete: true, correlation: { state: "declared-disabled" } },
    });
    expect(first).not.toContain(fixture.workspace);
    expect(first).not.toContain("Inert synthetic test");
    const reordered = path.join(fixture.workspace, "reordered.json");
    await writeFile(
      reordered,
      JSON.stringify(
        JSON.parse(await readFile(baseline, "utf8"), (_key, value: unknown) =>
          typeof value === "object" && value !== null && !Array.isArray(value)
            ? Object.fromEntries(Object.entries(value).reverse())
            : value,
        ),
      ),
    );
    clearOutput();
    expect(await main(["review-record", reordered, "--format", "json"])).toBe(0);
    expect(stdout()).toBe(first);
    const receipt = path.join(fixture.workspace, "review.json");
    clearOutput();
    expect(await main([...args, "--output", receipt])).toBe(0);
    expect(stdout()).toBe("");
    expect(await readFile(receipt, "utf8")).toBe(first);
    const current = await fixture.save("current");
    expect(await main(["review-check", receipt, current])).toBe(0);
    expect(stdout()).toContain("Review result: matches-evidence");
    expect(stdout()).toContain("Recapture before checking");
    expect(stdout()).toContain("never promotes new evidence or changes the receipt");
    const output = path.join(fixture.workspace, "check.json");
    clearOutput();
    expect(
      await main(["review-check", receipt, current, "--format", "json", "--output", output]),
    ).toBe(0);
    expect(stdout()).toBe("");
    expect(JSON.parse(await readFile(output, "utf8"))).toMatchObject({
      status: "matches-evidence",
      receiptId: (JSON.parse(first) as SkillReviewReceipt).receipt.id,
      comparison: { complete: true, status: "unchanged" },
    });
    expect(await readFile(receipt, "utf8")).toBe(first);
  });

  it("reports declaration and byte-only changes with exit 1; compares restoration to the original baseline before retention", async () => {
    const fixture = await makeFixture();
    const baseline = await fixture.save("baseline");
    const receipt = path.join(fixture.workspace, "review.json");
    expect(await main(["review-record", baseline, "--format", "json", "--output", receipt])).toBe(
      0,
    );
    const original = await readFile(receipt, "utf8");
    await writeFile(fixture.config, fixture.configText.replace("false", "true"));
    const enabled = await fixture.save("enabled");
    expect(await main(["review-check", receipt, enabled, "--format", "json"])).toBe(1);
    expect(JSON.parse(stdout())).toMatchObject({
      status: "changed-since-review",
      comparison: {
        baseline: { state: "declared-disabled" },
        current: { state: "declared-enabled" },
        observations: {
          skillBytes: "same",
          declarations: "different",
          harnessContext: "different",
        },
      },
    });
    clearOutput();
    expect(await main(["review-check", receipt, enabled])).toBe(1);
    expect(stdout()).toContain("declared-disabled -> declared-enabled");
    await writeFile(fixture.config, fixture.configText);
    const restored = await fixture.save("restored");
    clearOutput();
    expect(await main(["capability-graph-compare", baseline, restored])).toBe(0);
    expect(stdout()).toContain("Result: unchanged");
    clearOutput();
    const restoredReceipt = path.join(fixture.workspace, "restored.review.json");
    expect(
      await main(["review-record", restored, "--format", "json", "--output", restoredReceipt]),
    ).toBe(0);
    expect(await readFile(restoredReceipt, "utf8")).toBe(original);
    await writeFile(
      path.join(fixture.skill, "SKILL.md"),
      `${fixture.skillText}\nExplain local evidence.\n`,
    );
    const bytes = await fixture.save("bytes");
    expect(await main(["review-check", receipt, bytes, "--format", "json"])).toBe(1);
    expect(JSON.parse(stdout())).toMatchObject({
      status: "changed-since-review",
      comparison: {
        observations: { skillBytes: "different", declarations: "same", harnessContext: "same" },
      },
    });
    expect(await readFile(receipt, "utf8")).toBe(original);
  });

  it("cannot retain unknown evidence and checks unknown current evidence with exit 2 and directional diagnostics", async () => {
    const fixture = await makeFixture();
    const baseline = await fixture.save("baseline");
    const receipt = path.join(fixture.workspace, "review.json");
    expect(await main(["review-record", baseline, "--format", "json", "--output", receipt])).toBe(
      0,
    );
    await writeFile(fixture.config, "[broken\n");
    const unknown = await fixture.save("unknown");
    const rejectedReceipt = path.join(fixture.workspace, "unknown.review.json");
    expect(
      await main(["review-record", unknown, "--format", "json", "--output", rejectedReceipt]),
    ).toBe(2);
    expect(stdout()).toBe("");
    await expect(readFile(rejectedReceipt)).rejects.toThrow();
    expect(stderr()).toContain("Resolve the graph diagnostics and recapture");
    clearOutput();
    expect(await main(["review-check", receipt, unknown, "--format", "json"])).toBe(2);
    expect(JSON.parse(stdout())).toMatchObject({
      status: "cannot-check",
      comparison: { status: "incomplete", current: { state: "unknown" } },
    });
    clearOutput();
    expect(await main(["review-check", receipt, unknown])).toBe(2);
    expect(stdout()).toContain("HARNESS_CAPTURE_INCOMPLETE");
    expect(stdout()).not.toContain("Review result: matches-evidence");
  });

  it("rejects invalid receipts and graphs without emitting imported text or writing a check", async () => {
    const fixture = await makeFixture();
    const baseline = await fixture.save("baseline");
    expect(await main(["review-record", baseline, "--format", "json"])).toBe(0);
    const valid = stdout();
    const invalid = path.join(fixture.workspace, "invalid.json");
    const output = path.join(fixture.workspace, "must-not-exist.json");
    const cases = [
      "{synthetic-private-marker",
      " ".repeat(MAX_SKILL_REVIEW_RECEIPT_BYTES + 1),
      valid.replace('"scope":', '"scope":"advisory-only","scope":'),
      valid.replace('"schemaVersion": "1.0.0"', '"schemaVersion": "2.0.0"'),
      valid.replace(
        '"disposition": "reviewed-captured-evidence"',
        '"disposition": "synthetic-private-marker"',
      ),
      valid.replace('"complete": true', '"complete": false'),
      await readFile(baseline, "utf8"),
      Buffer.from([0xff, 0xfe]),
    ];
    for (const content of cases) {
      await writeFile(invalid, content);
      clearOutput();
      expect(
        await main(["review-check", invalid, baseline, "--format", "json", "--output", output]),
      ).toBe(2);
      expect(stdout()).toBe("");
      expect(stderr()).not.toContain("synthetic-private-marker");
      await expect(readFile(output)).rejects.toThrow();
    }
    await writeFile(invalid, valid);
    clearOutput();
    expect(await main(["review-record", invalid])).toBe(2);
    expect(await main(["review-check", invalid, invalid, "--output", output])).toBe(2);
    expect(stdout()).toBe("");
    await expect(readFile(output)).rejects.toThrow();
  });

  it("preserves inputs, hardlink aliases, and existing outputs on both commands", async () => {
    const fixture = await makeFixture();
    const baseline = await fixture.save("baseline");
    const current = await fixture.save("current");
    const receipt = path.join(fixture.workspace, "review.json");
    const alias = path.join(fixture.workspace, "alias.json");
    const output = path.join(fixture.workspace, "existing.json");
    expect(await main(["review-record", baseline, "--format", "json", "--output", receipt])).toBe(
      0,
    );
    await link(receipt, alias);
    await writeFile(output, "keep this evidence\n");
    const files = [baseline, current, receipt, alias, output];
    const originals = await Promise.all(files.map((file) => readFile(file, "utf8")));
    for (const destination of files) {
      for (const args of [
        ["review-record", baseline],
        ["review-check", receipt, current],
      ]) {
        clearOutput();
        expect(await main([...args, "--format", "json", "--output", destination])).toBe(2);
        expect(stdout()).toBe("");
      }
    }
    expect(await Promise.all(files.map((file) => readFile(file, "utf8")))).toEqual(originals);
  });
});

function stdout(): string {
  return vi.mocked(process.stdout.write).mock.calls.join("");
}
function stderr(): string {
  return vi.mocked(process.stderr.write).mock.calls.join("");
}
function clearOutput(): void {
  vi.mocked(process.stdout.write).mockClear();
  vi.mocked(process.stderr.write).mockClear();
}

async function makeFixture() {
  const workspace = await mkdtemp(path.join(tmpdir(), "uleravo-review-cli-"));
  temporaryDirectories.push(workspace);
  const skill = path.join(workspace, "skill");
  const project = path.join(workspace, "project");
  const config = path.join(workspace, "config.toml");
  await Promise.all([mkdir(skill), mkdir(project)]);
  const skillText =
    "---\nname: synthetic\ndescription: Inert synthetic test.\n---\n\nDo nothing.\n";
  const configText = '[[skills.config]]\npath = "./skill"\nenabled = false\n';
  await writeFile(path.join(skill, "SKILL.md"), skillText);
  await writeFile(config, configText);
  return {
    config,
    configText,
    skill,
    skillText,
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
