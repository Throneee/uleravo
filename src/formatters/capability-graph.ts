import {
  MAX_CAPABILITY_GRAPH_REPORT_BYTES,
  type SkillCapabilityGraph,
} from "../capability-graph/domain.js";

export function formatSkillCapabilityGraphJson(graph: SkillCapabilityGraph): string {
  const serialized = `${JSON.stringify(graph, null, 2)}\n`;
  if (Buffer.byteLength(serialized, "utf8") > MAX_CAPABILITY_GRAPH_REPORT_BYTES) {
    throw new Error("Capability graph exceeds the bounded report size.");
  }
  return serialized;
}

export function formatSkillCapabilityGraphText(graph: SkillCapabilityGraph): string {
  const lines = [
    `Uleravo declared Skill exposure graph ${graph.graph.id}`,
    `Correlation: ${graph.correlation.state}`,
    `Complete: ${graph.complete ? "yes" : "no"}`,
    `Skill content SHA-256: ${graph.inputs.skill.contentSha256}`,
    `Codex harness snapshot: ${graph.inputs.harness.snapshotId}`,
    "Scope: declared exposure only; runtime reachability was not observed and effect authority was not established.",
    `Reason: ${graph.correlation.reason}`,
    `Exact declaration groups: ${graph.edges.length.toString()}`,
  ];
  if (graph.edges.length > 0) {
    lines.push(
      "Declarations:",
      ...graph.edges.map(
        (edge) =>
          `  ${edge.layer} · ${edge.applicability} · ${edge.enablement} · ${edge.identity} · count ${edge.count.toString()}`,
      ),
    );
  }
  if (graph.diagnostics.length > 0) {
    lines.push(
      "Diagnostics:",
      ...graph.diagnostics.map(
        (diagnostic) =>
          `  ERROR${diagnostic.layer === undefined ? "" : ` ${diagnostic.layer}`}: ${diagnostic.message}`,
      ),
    );
  }
  return `${lines.join("\n")}\n`;
}
