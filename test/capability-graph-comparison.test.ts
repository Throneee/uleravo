import { readFile } from "node:fs/promises";
import { describe, expect, it } from "vitest";
import { compareSkillCapabilityGraphs } from "../src/capability-graph/comparison.js";
import type { SkillCapabilityGraph } from "../src/capability-graph/domain.js";
import {
  buildCapabilityGraphIdentities,
  capabilityGraphDiagnostic,
  classificationDiagnostics,
  compareCapabilityGraphDiagnostics,
  correlationReason,
  deriveCorrelationState,
  type EdgeCore,
} from "../src/capability-graph/identity.js";
import {
  formatSkillCapabilityGraphComparisonJson,
  formatSkillCapabilityGraphComparisonText,
} from "../src/formatters/capability-graph-comparison.js";

describe("saved Skill graph comparison", () => {
  it.each(["enabled", "disabled", "absent"] as const)(
    "reports identical complete %s evidence without a safety or installation verdict",
    (enablement) => {
      const graph = makeGraph({ edges: enablement === "absent" ? [] : [edge({ enablement })] });
      const result = compareSkillCapabilityGraphs(graph, graph);
      expect(result).toMatchObject({
        complete: true,
        status: "unchanged",
        pairing: { installationContinuity: "not-established", selection: "caller-selected" },
      });
      expect(Object.values(result.observations)).toEqual(Array(7).fill("same"));
      const text = formatSkillCapabilityGraphComparisonText(result);
      expect(text).toContain("not a safety, trust, approval, or runtime enforcement verdict");
      expect(text).toContain("Graphs contain no stable installation identity");
      expect(result.nextReviewActions).toContain(
        "Continue the human review using the same complete recorded evidence; no safety or approval decision is made here.",
      );
    },
  );

  it("separates changed Skill bytes from unchanged declarations despite all derived node/edge IDs changing", () => {
    const baseline = makeGraph();
    const current = makeGraph({ skillContent: "b".repeat(64), skillSnapshot: "b".repeat(24) });
    expect(baseline.nodes).not.toEqual(current.nodes);
    expect(baseline.edges[0]?.id).not.toEqual(current.edges[0]?.id);
    const result = compareSkillCapabilityGraphs(baseline, current);
    expect(result).toMatchObject({
      status: "changed",
      complete: true,
      observations: {
        declarations: "same",
        harnessContext: "same",
        skillBytes: "different",
        skillSnapshot: "different",
      },
    });
    expect(result.baseline.declarations).toEqual(result.current.declarations);
    expect(result.nextReviewActions.join(" ")).toContain("Review the changed Skill files locally");
    expect(formatSkillCapabilityGraphComparisonText(result)).toContain(
      "do not establish capability expansion",
    );
    expect(result.current.declarations[0]).not.toHaveProperty("id");
    expect(result.current.graphId).toBe(current.graph.id);
    expect(result.baseline.skillContentSha256).toBe(baseline.inputs.skill.contentSha256);
  });

  it("preserves direction for explicit declaration enablement and removal", () => {
    const disabled = makeGraph({ edges: [edge({ enablement: "disabled" })] });
    const enabled = makeGraph();
    for (const [before, after] of [
      [disabled, enabled],
      [enabled, disabled],
      [enabled, makeGraph({ edges: [] })],
    ] as const) {
      const result = compareSkillCapabilityGraphs(before, after);
      expect(result).toMatchObject({
        complete: true,
        status: "changed",
        observations: { skillBytes: "same", declarations: "different" },
      });
      expect(result.baseline.state).toBe(before.correlation.state);
      expect(result.current.state).toBe(after.correlation.state);
      expect(result.nextReviewActions.join(" ")).toContain(
        "including enablement, applicability, layer, count",
      );
    }
  });

  it.each([
    { applicability: "ignored" },
    { applicability: "unknown" },
    { count: 2 },
    { enablement: "unspecified" },
    { identity: "mismatch" },
  ] as const)("keeps changed declaration classification incomplete: %j", (change) => {
    const baseline = makeGraph();
    const current = makeGraph({ edges: [edge(change)] });
    const result = compareSkillCapabilityGraphs(baseline, current);
    expect(result).toMatchObject({
      status: "incomplete",
      complete: false,
      baseline: { complete: true },
      current: { complete: false, state: "unknown" },
      observations: { declarations: "different" },
    });
    expect(result.current.diagnostics).toEqual(current.diagnostics);
    expect(result.current.declarations[0]).toMatchObject(change);
  });

  it("shows a changed harness context without inventing permission semantics", () => {
    const result = compareSkillCapabilityGraphs(
      makeGraph(),
      makeGraph({ harnessContent: "c".repeat(64), harnessSnapshot: "c".repeat(24) }),
    );
    expect(result).toMatchObject({
      complete: true,
      status: "changed",
      observations: {
        harnessContext: "different",
        harnessSnapshot: "different",
        declarations: "same",
        skillBytes: "same",
      },
    });
    expect(formatSkillCapabilityGraphComparisonText(result)).toContain(
      "configuration semantics are not exposed",
    );
    expect(result.nextReviewActions.join(" ")).toContain(
      "harness-delta on complete supported snapshots",
    );
  });

  it("does not erase changed snapshot references when byte digests match", () => {
    const result = compareSkillCapabilityGraphs(
      makeGraph(),
      makeGraph({ skillSnapshot: "f".repeat(24) }),
    );
    expect(result).toMatchObject({
      status: "changed",
      observations: { skillBytes: "same", skillSnapshot: "different" },
    });
    expect(result.nextReviewActions.join(" ")).toContain(
      "changed snapshot reference despite the same recorded content digest",
    );
  });

  it.each(["baseline", "current", "both"] as const)(
    "preserves incomplete %s evidence and diagnostics even for identical graphs",
    (side) => {
      const incomplete = makeGraph({ diagnostic: "HARNESS_CAPTURE_CHANGED" });
      const baseline = side === "current" ? makeGraph() : incomplete;
      const current = side === "baseline" ? makeGraph() : incomplete;
      const result = compareSkillCapabilityGraphs(baseline, current);
      expect(result).toMatchObject({ complete: false, status: "incomplete" });
      expect(result.baseline.diagnostics).toEqual(baseline.diagnostics);
      expect(result.current.diagnostics).toEqual(current.diagnostics);
      expect(Object.values(result.observations)).toEqual(Array(7).fill("same"));
      const text = formatSkillCapabilityGraphComparisonText(result);
      expect(text).toContain("Result: incomplete");
      expect(text).not.toContain("Result: unchanged");
      expect(text).toContain("ERROR HARNESS_CAPTURE_CHANGED");
      expect(text).toContain("Resolve the diagnostics on each affected side");
    },
  );

  it.each(["skillAnalyzer", "harnessAnalyzer"] as const)(
    "limits comparison across %s versions without echoing imported version text",
    (field) => {
      const marker = "synthetic-private-marker";
      const result = compareSkillCapabilityGraphs(makeGraph(), makeGraph({ [field]: marker }));
      expect(result).toMatchObject({
        status: "version-limited",
        complete: false,
        observations: { [field]: "different" },
      });
      expect(result.nextReviewActions.join(" ")).toContain("same supported analyzer versions");
      expect(formatSkillCapabilityGraphComparisonJson(result)).not.toContain(marker);
      expect(formatSkillCapabilityGraphComparisonText(result)).not.toContain(marker);
    },
  );

  it("keeps both version limits and capture diagnostics when both apply", () => {
    const result = compareSkillCapabilityGraphs(
      makeGraph(),
      makeGraph({ skillAnalyzer: "9.0.0", diagnostic: "HARNESS_CAPTURE_CHANGED" }),
    );
    expect(result.status).toBe("incomplete");
    expect(result.limitations.join(" ")).toContain("Input analyzer versions differ");
    expect(result.current.diagnostics).toHaveLength(1);
  });

  it("validates library inputs, including identities, semantic consistency and supported adapter versions", () => {
    const valid = makeGraph();
    const tampered = [
      { ...valid, complete: false },
      { ...valid, graph: { id: "0".repeat(24) } },
      { ...valid, adapter: { ...valid.adapter, version: "2.0.0" } },
      { ...valid, schemaVersion: "2.0.0" },
      { ...valid, source: "synthetic-private-source" },
      {
        ...valid,
        diagnostics: [
          { code: "HARNESS_CAPTURE_CHANGED", type: "error", message: "synthetic-private-source" },
        ],
      },
    ];
    for (const graph of tampered) {
      expect(() => compareSkillCapabilityGraphs(valid, graph as SkillCapabilityGraph)).toThrow();
      expect(() => compareSkillCapabilityGraphs(graph as SkillCapabilityGraph, valid)).toThrow();
    }
  });

  it("produces deterministic canonical output without mutating inputs", () => {
    const baseline = makeGraph();
    const current = makeGraph({ skillContent: "c".repeat(64) });
    const original = JSON.stringify([baseline, current]);
    // Reverse every object's property order while retaining all nested evidence.
    const reversed = JSON.parse(JSON.stringify(current), (_key, value: unknown) => {
      if (typeof value === "object" && value !== null && !Array.isArray(value)) {
        return Object.fromEntries(Object.entries(value).reverse());
      }
      return value;
    }) as SkillCapabilityGraph;
    const first = compareSkillCapabilityGraphs(baseline, current);
    const second = compareSkillCapabilityGraphs(baseline, reversed);
    expect(formatSkillCapabilityGraphComparisonJson(first)).toBe(
      formatSkillCapabilityGraphComparisonJson(second),
    );
    expect(formatSkillCapabilityGraphComparisonText(first)).toBe(
      formatSkillCapabilityGraphComparisonText(second),
    );
    expect(JSON.stringify([baseline, current])).toBe(original);
  });

  it("ships a bounded versioned output schema whose evidence and observation fields match the result", async () => {
    const schema = JSON.parse(
      await readFile(
        new URL("../schemas/capability-graph-comparison.schema.json", import.meta.url),
        "utf8",
      ),
    ) as {
      required: string[];
      properties: {
        documentType: { const: string };
        schemaVersion: { const: string };
        observations: { required: string[] };
      };
      $defs: {
        evidence: { required: string[] };
        guidance: { maxItems: number; items: { maxLength: number } };
      };
    };
    const result = compareSkillCapabilityGraphs(
      makeGraph(),
      makeGraph({
        diagnostic: "HARNESS_CAPTURE_CHANGED",
        skillAnalyzer: "2.0.0",
        skillContent: "c".repeat(64),
        harnessContent: "d".repeat(64),
        edges: [edge({ count: 2 })],
      }),
    );
    expect(Object.keys(result).sort()).toEqual(schema.required.sort());
    expect(result.documentType).toBe(schema.properties.documentType.const);
    expect(result.schemaVersion).toBe(schema.properties.schemaVersion.const);
    expect(Object.keys(result.observations).sort()).toEqual(
      schema.properties.observations.required.sort(),
    );
    expect(Object.keys(result.baseline).sort()).toEqual(schema.$defs.evidence.required.sort());
    for (const lines of [result.limitations, result.nextReviewActions]) {
      expect(lines.length).toBeLessThanOrEqual(schema.$defs.guidance.maxItems);
      for (const line of lines)
        expect(line.length).toBeLessThanOrEqual(schema.$defs.guidance.items.maxLength);
    }
  });
});

function edge(overrides: Partial<EdgeCore> = {}): EdgeCore {
  return {
    applicability: "applied",
    count: 1,
    enablement: "enabled",
    identity: "exact-content",
    kind: "declares-skill",
    layer: "user-config",
    ...overrides,
  };
}

function makeGraph(
  options: {
    diagnostic?: "HARNESS_CAPTURE_CHANGED";
    edges?: EdgeCore[];
    harnessAnalyzer?: string;
    harnessContent?: string;
    harnessSnapshot?: string;
    skillAnalyzer?: string;
    skillContent?: string;
    skillSnapshot?: string;
  } = {},
): SkillCapabilityGraph {
  const edges = options.edges ?? [edge()];
  const diagnostics = [
    ...classificationDiagnostics(edges),
    ...(options.diagnostic === undefined ? [] : [capabilityGraphDiagnostic(options.diagnostic)]),
  ].sort(compareCapabilityGraphDiagnostics);
  const state = deriveCorrelationState(edges, diagnostics);
  const inputs: SkillCapabilityGraph["inputs"] = {
    harness: {
      adapter: { name: "openai-codex-local", version: "1.0.0" },
      analyzerVersion: options.harnessAnalyzer ?? "0.7.0",
      inputSha256: options.harnessContent ?? "a".repeat(64),
      schemaVersion: "1.0.0",
      snapshotId: options.harnessSnapshot ?? "a".repeat(24),
    },
    skill: {
      adapter: { name: "openai-skill", version: "1.0.0" },
      analyzerVersion: options.skillAnalyzer ?? "0.7.0",
      contentSha256: options.skillContent ?? "a".repeat(64),
      schemaVersion: "1.0.0",
      snapshotId: options.skillSnapshot ?? "a".repeat(24),
    },
  };
  const identities = buildCapabilityGraphIdentities({ diagnostics, edges, inputs, state });
  return {
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
  };
}
