import type {
  SkillCapabilityGraphComparison,
  SkillGraphComparisonEvidence,
} from "../capability-graph/comparison.js";

export function formatSkillCapabilityGraphComparisonJson(
  comparison: SkillCapabilityGraphComparison,
): string {
  return `${JSON.stringify(comparison, null, 2)}\n`;
}

export function formatSkillCapabilityGraphComparisonText(
  comparison: SkillCapabilityGraphComparison,
): string {
  const { observations } = comparison;
  return `${[
    "Uleravo saved Skill graph comparison (baseline -> current)",
    `Result: ${comparison.status}`,
    `Complete comparison: ${comparison.complete ? "yes" : "no"}`,
    `Declared exposure: ${comparison.baseline.state} -> ${comparison.current.state}`,
    "Recorded observations (same/different describes fields, not evidence completeness):",
    `  Skill bytes: ${observations.skillBytes}`,
    `  Declaration groups: ${observations.declarations}`,
    `  Harness context digest: ${observations.harnessContext} (configuration semantics are not exposed)`,
    `  Snapshot references: Skill ${observations.skillSnapshot}; harness ${observations.harnessSnapshot}`,
    `  Analyzer versions: Skill ${observations.skillAnalyzer}; harness ${observations.harnessAnalyzer}`,
    "Next review actions:",
    ...comparison.nextReviewActions.map((line) => `  ${line}`),
    ...evidenceLines("Baseline", comparison.baseline),
    ...evidenceLines("Current", comparison.current),
    "Limits:",
    ...comparison.limitations.map((line) => `  ${line}`),
    "Pairing: caller-selected; installation continuity is not established.",
    "Use --format json for all bound identities and machine-readable evidence.",
  ].join("\n")}\n`;
}

function evidenceLines(label: string, evidence: SkillGraphComparisonEvidence): string[] {
  return [
    `${label}: evidence complete: ${evidence.complete ? "yes" : "no"}; declaration groups: ${evidence.declarations.length.toString()}`,
    ...evidence.declarations.map(
      (edge) =>
        `    ${edge.layer} | ${edge.applicability} | ${edge.enablement} | ${edge.identity} | count ${edge.count.toString()}`,
    ),
    ...evidence.diagnostics.map(
      (diagnostic) =>
        `  ERROR ${diagnostic.code}${diagnostic.layer === undefined ? "" : ` (${diagnostic.layer})`}: ${diagnostic.message}`,
    ),
  ];
}
