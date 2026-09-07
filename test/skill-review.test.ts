import { createHash } from "node:crypto";
import { mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { compareSkillCapabilityGraphs } from "../src/capability-graph/comparison.js";
import type { SkillCapabilityGraph } from "../src/capability-graph/domain.js";
import {
  buildCapabilityGraphIdentities,
  capabilityGraphDiagnostic,
  correlationReason,
  type EdgeCore,
} from "../src/capability-graph/identity.js";
import { parseSkillCapabilityGraph } from "../src/capability-graph/read.js";
import { readSkillReviewReceipt } from "../src/capability-graph/read-review.js";
import {
  checkSkillReview,
  MAX_SKILL_REVIEW_RECEIPT_BYTES,
  parseSkillReviewReceipt,
  recordSkillReview,
  type SkillReviewReceipt,
} from "../src/capability-graph/review.js";
import {
  formatSkillReviewCheckJson,
  formatSkillReviewCheckText,
  formatSkillReviewReceiptJson,
  formatSkillReviewReceiptText,
} from "../src/formatters/skill-review.js";
import { ARTIFACT_ANALYZER_VERSION, HARNESS_ANALYZER_VERSION } from "../src/version.js";

const temporaryDirectories: string[] = [];
afterEach(async () => {
  await Promise.all(
    temporaryDirectories
      .splice(0)
      .map((directory) => rm(directory, { recursive: true, force: true })),
  );
});

describe("retained Skill evidence review", () => {
  it.each(["declared-disabled", "declared-enabled", "not-declared"] as const)(
    "can retain %s as reviewed evidence without a safety rating",
    (state) => {
      const graph = makeGraph({ state });
      const receipt = recordSkillReview(graph);
      expect(receipt).toMatchObject({
        authentication: "unsigned-unauthenticated",
        declaration: "caller-declared",
        disposition: "reviewed-captured-evidence",
        graph,
        scope: "advisory-only",
      });
      expect(receipt.receipt.id).toMatch(/^[a-f0-9]{64}$/u);
      expect(parseSkillReviewReceipt(formatSkillReviewReceiptJson(receipt))).toEqual(receipt);
      const checked = checkSkillReview(receipt, graph);
      expect(checked.status).toBe("matches-evidence");
      expect(checked.comparison).toEqual(compareSkillCapabilityGraphs(graph, graph));
      const text = formatSkillReviewReceiptText(receipt);
      expect(text).toContain("caller-declared");
      expect(text).toContain("unsigned-unauthenticated");
      expect(text).toContain("does not prove a human reviewed");
      expect(text).toContain("Recapture before checking");
      expect(formatSkillReviewCheckText(checked)).toContain(
        "matches this recorded evidence review",
      );
      expect(checked.limitations.join(" ")).toContain("Time alone does not establish freshness");
    },
  );

  it("binds the whole normalized graph and fixed declaration with a full domain-separated digest", () => {
    const graph = makeGraph();
    const receipt = recordSkillReview(graph);
    const { receipt: _identity, ...payload } = receipt;
    const expected = createHash("sha256")
      .update("uleravo:skill-review-receipt:v1\0")
      .update(JSON.stringify(payload))
      .digest("hex");
    expect(receipt.receipt.id).toBe(expected);
    for (const changed of [
      makeGraph({ skillContent: "b".repeat(64) }),
      makeGraph({ skillSnapshot: "b".repeat(24) }),
      makeGraph({ harnessContent: "c".repeat(64) }),
      makeGraph({ harnessSnapshot: "c".repeat(24) }),
      makeGraph({ state: "declared-enabled" }),
      makeGraph({ state: "not-declared" }),
    ]) {
      expect(recordSkillReview(changed).receipt.id).not.toBe(receipt.receipt.id);
      expect(() => parseSkillReviewReceipt(JSON.stringify({ ...receipt, graph: changed }))).toThrow(
        "identity does not match",
      );
    }
  });

  it("normalizes reordered object keys, serializes identically, and never mutates inputs", () => {
    const graph = makeGraph();
    const receipt = recordSkillReview(graph);
    const original = JSON.stringify([graph, receipt]);
    const reorderedGraph = reverseKeys(graph) as SkillCapabilityGraph;
    const reorderedReceipt = reverseKeys(receipt) as SkillReviewReceipt;
    const serialized = formatSkillReviewReceiptJson(receipt);
    expect(formatSkillReviewReceiptJson(recordSkillReview(reorderedGraph))).toBe(serialized);
    expect(formatSkillReviewReceiptJson(reorderedReceipt)).toBe(serialized);
    expect(parseSkillReviewReceipt(JSON.stringify(reorderedReceipt))).toEqual(receipt);
    const current = makeGraph({ skillContent: "b".repeat(64) });
    expect(formatSkillReviewCheckJson(checkSkillReview(reorderedReceipt, current))).toBe(
      formatSkillReviewCheckJson(checkSkillReview(receipt, current)),
    );
    checkSkillReview(receipt, current);
    expect(JSON.stringify([graph, receipt])).toBe(original);
    expect(receipt.graph).not.toBe(graph);
  });

  it("preserves byte-only drift, harness context and directional declarations from CG002", () => {
    const before = makeGraph();
    const receipt = recordSkillReview(before);
    const bytes = checkSkillReview(receipt, makeGraph({ skillContent: "b".repeat(64) }));
    expect(bytes).toMatchObject({
      status: "changed-since-review",
      comparison: {
        observations: { skillBytes: "different", declarations: "same", harnessContext: "same" },
      },
    });
    expect(formatSkillReviewCheckText(bytes)).toContain("Review the changed Skill files locally");
    const context = checkSkillReview(receipt, makeGraph({ harnessContent: "c".repeat(64) }));
    expect(context.comparison.observations).toMatchObject({
      skillBytes: "same",
      declarations: "same",
      harnessContext: "different",
    });
    expect(formatSkillReviewCheckText(context)).toContain(
      "configuration semantics are not exposed",
    );
    const enabled = makeGraph({ state: "declared-enabled" });
    for (const [baseline, current] of [
      [before, enabled],
      [enabled, before],
    ] as const) {
      const check = checkSkillReview(recordSkillReview(baseline), current);
      expect(check.status).toBe("changed-since-review");
      expect(check.comparison.baseline.state).toBe(baseline.correlation.state);
      expect(check.comparison.current.state).toBe(current.correlation.state);
    }
  });

  it("refuses unknown receipts and keeps matching recorded fields unable to check with current-side diagnostics", () => {
    const incomplete = makeGraph({ state: "unknown" });
    expect(() => recordSkillReview(incomplete)).toThrow(
      "Resolve the graph diagnostics and recapture",
    );
    const check = checkSkillReview(recordSkillReview(makeGraph()), incomplete);
    expect(check).toMatchObject({
      status: "cannot-check",
      comparison: {
        complete: false,
        status: "incomplete",
        baseline: { diagnostics: [] },
        current: { state: "unknown", diagnostics: [{ code: "HARNESS_CAPTURE_CHANGED" }] },
      },
    });
    expect(Object.values(check.comparison.observations)).toEqual(Array(7).fill("same"));
    expect(formatSkillReviewCheckText(check)).toContain("Unable to check complete evidence");
    expect(formatSkillReviewCheckText(check)).toContain("HARNESS_CAPTURE_CHANGED");
  });

  it.each(["skillAnalyzer", "harnessAnalyzer"] as const)(
    "excludes arbitrary %s tokens from receipts while retaining version-limited comparison",
    (field) => {
      const marker = "synthetic-private-version";
      const graph = makeGraph({ [field]: marker });
      // Receipt eligibility is narrower; the original graph reader stays compatible.
      expect(parseSkillCapabilityGraph(JSON.stringify(graph))).toEqual(graph);
      expect(() => recordSkillReview(graph)).toThrow("unsupported analyzer versions");
      const receipt = recordSkillReview(makeGraph());
      expect(() => parseSkillReviewReceipt(JSON.stringify({ ...receipt, graph }))).toThrow(
        "unsupported analyzer versions",
      );
      const check = checkSkillReview(receipt, graph);
      expect(check.status).toBe("cannot-check");
      expect(check.comparison.status).toBe("version-limited");
      expect(formatSkillReviewCheckJson(check)).not.toContain(marker);
      expect(formatSkillReviewCheckText(check)).not.toContain(marker);
    },
  );

  it("rejects malformed, nested duplicate-key, oversized, inconsistent and unsupported receipts without echoing imported text", () => {
    const receipt = recordSkillReview(makeGraph());
    const serialized = JSON.stringify(receipt);
    const marker = "synthetic-private-marker";
    const invalid = [
      "null",
      "[]",
      "{}",
      `{${marker}`,
      " ".repeat(MAX_SKILL_REVIEW_RECEIPT_BYTES + 1),
      serialized.replace('"receipt":', '"receipt":{},"receipt":'),
      serialized.replace('"complete":', '"complete":true,"compl\\u0065te":'),
      serialized.replace('"complete":true', '"complete":false'),
      serialized.replace('"version":"1.0.0"', '"version":"2.0.0"'),
      JSON.stringify({ ...receipt, [marker]: marker }),
      JSON.stringify({ ...receipt, authentication: marker }),
      JSON.stringify({ ...receipt, declaration: marker }),
      JSON.stringify({ ...receipt, disposition: marker }),
      JSON.stringify({ ...receipt, documentType: marker }),
      JSON.stringify({ ...receipt, schemaVersion: "2.0.0" }),
      JSON.stringify({ ...receipt, scope: marker }),
      JSON.stringify({ ...receipt, receipt: { id: receipt.receipt.id.slice(0, 24) } }),
      JSON.stringify({ ...receipt, receipt: { id: "f".repeat(64) } }),
      JSON.stringify({ ...receipt, graph: { ...receipt.graph, [marker]: marker } }),
      JSON.stringify({ ...receipt, graph: makeGraph({ state: "unknown" }) }),
    ];
    for (const input of invalid) {
      let error: unknown;
      try {
        parseSkillReviewReceipt(input);
      } catch (caught) {
        error = caught;
      }
      expect(error).toBeInstanceOf(Error);
      expect(String(error)).not.toContain(marker);
    }
    expect(() => recordSkillReview({ ...receipt.graph, complete: false })).toThrow();
    expect(() =>
      checkSkillReview({ ...receipt, receipt: { id: "0".repeat(64) } }, receipt.graph),
    ).toThrow();
    expect(() => checkSkillReview(receipt, { ...receipt.graph, complete: false })).toThrow();
    // A comparison report is never an input to either review operation.
    const comparison = compareSkillCapabilityGraphs(receipt.graph, receipt.graph);
    expect(() => recordSkillReview(comparison as unknown as SkillCapabilityGraph)).toThrow();
    expect(() =>
      checkSkillReview(receipt, comparison as unknown as SkillCapabilityGraph),
    ).toThrow();
  });

  it("reads only bounded regular UTF-8 receipts", async () => {
    const directory = await temporaryDirectory();
    const file = path.join(directory, "review.json");
    const receipt = recordSkillReview(makeGraph());
    await writeFile(file, formatSkillReviewReceiptJson(receipt));
    expect(await readSkillReviewReceipt(file)).toEqual(receipt);
    await expect(readSkillReviewReceipt(directory)).rejects.toThrow("regular, non-linked");
    await writeFile(file, Buffer.from([0xff, 0xfe]));
    await expect(readSkillReviewReceipt(file)).rejects.toThrow("not valid UTF-8");
    await writeFile(file, " ".repeat(MAX_SKILL_REVIEW_RECEIPT_BYTES + 1));
    await expect(readSkillReviewReceipt(file)).rejects.toThrow("byte limit");
  });

  it.skipIf(process.platform === "win32")("refuses a symbolic receipt input", async () => {
    const directory = await temporaryDirectory();
    const file = path.join(directory, "review.json");
    const linked = path.join(directory, "linked.json");
    await writeFile(file, formatSkillReviewReceiptJson(recordSkillReview(makeGraph())));
    await symlink(file, linked);
    await expect(readSkillReviewReceipt(linked)).rejects.toThrow("regular, non-linked");
  });

  it("ships an exact receipt schema constrained to supported embedded analyzer versions", async () => {
    const schema = JSON.parse(
      await readFile(
        new URL("../schemas/skill-review-receipt.schema.json", import.meta.url),
        "utf8",
      ),
    );
    const constraints = schema.properties.graph.allOf[1].properties;
    const graphSchema = JSON.parse(
      await readFile(new URL("../schemas/capability-graph.schema.json", import.meta.url), "utf8"),
    );
    expect(schema.properties.graph.allOf[0].$ref).toBe(graphSchema.$id);
    expect(schema.additionalProperties).toBe(false);
    expect(schema.properties.receipt.properties.id.pattern).toBe("^[a-f0-9]{64}$");
    expect(constraints.complete.const).toBe(true);
    expect(constraints.inputs.properties.skill.properties.analyzerVersion.const).toBe(
      ARTIFACT_ANALYZER_VERSION,
    );
    expect(constraints.inputs.properties.harness.properties.analyzerVersion.const).toBe(
      HARNESS_ANALYZER_VERSION,
    );
  });
});

function reverseKeys(value: unknown): unknown {
  return JSON.parse(JSON.stringify(value), (_key, entry: unknown) =>
    typeof entry === "object" && entry !== null && !Array.isArray(entry)
      ? Object.fromEntries(Object.entries(entry).reverse())
      : entry,
  );
}

async function temporaryDirectory(): Promise<string> {
  const directory = await mkdtemp(path.join(tmpdir(), "uleravo-review-"));
  temporaryDirectories.push(directory);
  return directory;
}

function makeGraph(
  options: {
    state?: SkillCapabilityGraph["correlation"]["state"];
    skillContent?: string;
    skillSnapshot?: string;
    harnessContent?: string;
    harnessSnapshot?: string;
    skillAnalyzer?: string;
    harnessAnalyzer?: string;
  } = {},
): SkillCapabilityGraph {
  const state = options.state ?? "declared-disabled";
  const diagnostics =
    state === "unknown" ? [capabilityGraphDiagnostic("HARNESS_CAPTURE_CHANGED")] : [];
  const edges: EdgeCore[] =
    state === "not-declared"
      ? []
      : [
          {
            applicability: "applied",
            count: 1,
            enablement: state === "declared-enabled" ? "enabled" : "disabled",
            identity: "exact-content",
            kind: "declares-skill",
            layer: "user-config",
          },
        ];
  const inputs: SkillCapabilityGraph["inputs"] = {
    harness: {
      adapter: { name: "openai-codex-local", version: "1.0.0" },
      analyzerVersion: options.harnessAnalyzer ?? HARNESS_ANALYZER_VERSION,
      inputSha256: options.harnessContent ?? "a".repeat(64),
      schemaVersion: "1.0.0",
      snapshotId: options.harnessSnapshot ?? "a".repeat(24),
    },
    skill: {
      adapter: { name: "openai-skill", version: "1.0.0" },
      analyzerVersion: options.skillAnalyzer ?? ARTIFACT_ANALYZER_VERSION,
      contentSha256: options.skillContent ?? "a".repeat(64),
      schemaVersion: "1.0.0",
      snapshotId: options.skillSnapshot ?? "a".repeat(24),
    },
  };
  const identities = buildCapabilityGraphIdentities({ diagnostics, edges, inputs, state });
  return parseSkillCapabilityGraph(
    JSON.stringify({
      adapter: { name: "openai-skill-codex-correlation", version: "1.0.0" },
      complete: state !== "unknown",
      correlation: { id: identities.correlationId, reason: correlationReason(state), state },
      diagnostics,
      documentType: "uleravo.skill-capability-graph",
      edges: identities.edges,
      graph: { id: identities.graphId },
      inputs,
      nodes: identities.nodes,
      schemaVersion: "1.0.0",
      scope: {
        assertion: "declared-exposure-only",
        effectAuthority: "not-established",
        runtimeReachability: "not-observed",
      },
    }),
  );
}
