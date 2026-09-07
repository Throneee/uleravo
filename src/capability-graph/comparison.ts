import type {
  CapabilityGraphDiagnostic,
  SkillCapabilityGraph,
  SkillCorrelationState,
} from "./domain.js";
import type { EdgeCore } from "./identity.js";
import { parseSkillCapabilityGraph } from "./read.js";

export const CAPABILITY_GRAPH_COMPARISON_SCHEMA_VERSION = "1.0.0" as const;

export interface SkillGraphComparisonEvidence {
  readonly complete: boolean;
  readonly correlationId: string;
  readonly declarations: readonly EdgeCore[];
  readonly diagnostics: readonly CapabilityGraphDiagnostic[];
  readonly graphId: string;
  readonly harnessInputSha256: string;
  readonly harnessSnapshotId: string;
  readonly skillContentSha256: string;
  readonly skillSnapshotId: string;
  readonly state: SkillCorrelationState;
}

export type SkillGraphEvidenceChange = "same" | "different";

export interface SkillCapabilityGraphComparison {
  readonly baseline: SkillGraphComparisonEvidence;
  readonly complete: boolean;
  readonly current: SkillGraphComparisonEvidence;
  readonly documentType: "uleravo.skill-capability-graph-comparison";
  readonly limitations: readonly string[];
  readonly nextReviewActions: readonly string[];
  readonly observations: {
    readonly declarations: SkillGraphEvidenceChange;
    readonly harnessAnalyzer: SkillGraphEvidenceChange;
    readonly harnessContext: SkillGraphEvidenceChange;
    readonly harnessSnapshot: SkillGraphEvidenceChange;
    readonly skillAnalyzer: SkillGraphEvidenceChange;
    readonly skillBytes: SkillGraphEvidenceChange;
    readonly skillSnapshot: SkillGraphEvidenceChange;
  };
  readonly pairing: {
    readonly installationContinuity: "not-established";
    readonly selection: "caller-selected";
  };
  readonly schemaVersion: typeof CAPABILITY_GRAPH_COMPARISON_SCHEMA_VERSION;
  readonly scope: SkillCapabilityGraph["scope"];
  readonly status: "changed" | "incomplete" | "unchanged" | "version-limited";
}

/** Compare two caller-selected reports as inert evidence, without inferring installation lineage. */
export function compareSkillCapabilityGraphs(
  baseline: SkillCapabilityGraph,
  current: SkillCapabilityGraph,
): SkillCapabilityGraphComparison {
  // A TypeScript annotation is not a trust boundary. Reuse the full saved-report validator
  // for library callers too, including semantic consistency and recomputed graph identities.
  const before = parseSkillCapabilityGraph(JSON.stringify(baseline), "Baseline capability graph");
  const after = parseSkillCapabilityGraph(JSON.stringify(current), "Current capability graph");
  const baselineEvidence = evidence(before);
  const currentEvidence = evidence(after);
  const observations = {
    declarations: difference(baselineEvidence.declarations, currentEvidence.declarations),
    harnessAnalyzer: difference(
      before.inputs.harness.analyzerVersion,
      after.inputs.harness.analyzerVersion,
    ),
    harnessContext: difference(before.inputs.harness.inputSha256, after.inputs.harness.inputSha256),
    harnessSnapshot: difference(before.inputs.harness.snapshotId, after.inputs.harness.snapshotId),
    skillAnalyzer: difference(
      before.inputs.skill.analyzerVersion,
      after.inputs.skill.analyzerVersion,
    ),
    skillBytes: difference(before.inputs.skill.contentSha256, after.inputs.skill.contentSha256),
    skillSnapshot: difference(before.inputs.skill.snapshotId, after.inputs.skill.snapshotId),
  };
  const versionsDiffer =
    observations.harnessAnalyzer === "different" || observations.skillAnalyzer === "different";
  const complete = before.complete && after.complete && !versionsDiffer;
  const status =
    !before.complete || !after.complete
      ? "incomplete"
      : versionsDiffer
        ? "version-limited"
        : Object.values(observations).includes("different")
          ? "changed"
          : "unchanged";
  return {
    baseline: baselineEvidence,
    complete,
    current: currentEvidence,
    documentType: "uleravo.skill-capability-graph-comparison",
    ...reviewGuidance(!before.complete || !after.complete, versionsDiffer, observations, status),
    observations,
    pairing: { installationContinuity: "not-established", selection: "caller-selected" },
    schemaVersion: CAPABILITY_GRAPH_COMPARISON_SCHEMA_VERSION,
    scope: before.scope,
    status,
  };
}

function reviewGuidance(
  incomplete: boolean,
  versionsDiffer: boolean,
  observations: SkillCapabilityGraphComparison["observations"],
  status: SkillCapabilityGraphComparison["status"],
): Pick<SkillCapabilityGraphComparison, "limitations" | "nextReviewActions"> {
  const limitations = [
    "The caller selected this baseline and current pair. Graphs contain no stable installation identity; matching identities do not establish installation continuity.",
    "Report validation checks internal consistency; capture authenticity and publisher identity are not established.",
    "Completeness concerns captured declared-exposure evidence only. It is not a safety, trust, approval, or runtime enforcement verdict.",
    "Runtime reachability was not observed and effect authority was not established.",
    "Skill-byte differences do not establish capability expansion or explain changed instruction meaning.",
    "Harness context is bound by digest; its configuration and permission semantics are not exposed in these graphs.",
  ];
  const nextReviewActions = [
    "Confirm that the caller-selected baseline and current are the intended review pair using your own installation records.",
  ];
  if (incomplete) {
    limitations.push(
      "At least one input is unknown or incomplete. Matching recorded fields cannot establish unchanged complete evidence.",
    );
    nextReviewActions.push(
      "Resolve the diagnostics on each affected side, recapture that evidence, and compare again before drawing a complete change conclusion.",
    );
  }
  if (versionsDiffer) {
    limitations.push(
      "Input analyzer versions differ. Recorded digests and declarations can be contrasted, but analysis continuity is not established.",
    );
    nextReviewActions.push(
      "Recapture both inputs with the same supported analyzer versions before relying on a complete comparison.",
    );
  }
  if (observations.skillBytes === "different") {
    nextReviewActions.push(
      "Review the changed Skill files locally against the baseline bytes; this report does not interpret instructions.",
    );
  }
  if (observations.declarations === "different") {
    nextReviewActions.push(
      "Review the baseline and current declaration groups, including enablement, applicability, layer, count, and exact-content status.",
    );
  }
  if (observations.harnessContext === "different" || observations.harnessSnapshot === "different") {
    nextReviewActions.push(
      "Inspect the paired harness snapshots or use harness-delta on complete supported snapshots to explain configuration and permission changes.",
    );
  }
  if (observations.skillSnapshot === "different" && observations.skillBytes === "same") {
    nextReviewActions.push(
      "Inspect the paired Skill snapshots to explain the changed snapshot reference despite the same recorded content digest.",
    );
  }
  if (status === "unchanged") {
    nextReviewActions.push(
      "Continue the human review using the same complete recorded evidence; no safety or approval decision is made here.",
    );
  }
  return { limitations, nextReviewActions };
}

function evidence(graph: SkillCapabilityGraph): SkillGraphComparisonEvidence {
  return {
    complete: graph.complete,
    correlationId: graph.correlation.id,
    declarations: graph.edges.map((edge) => ({
      applicability: edge.applicability,
      count: edge.count,
      enablement: edge.enablement,
      identity: edge.identity,
      kind: edge.kind,
      layer: edge.layer,
    })),
    diagnostics: graph.diagnostics,
    graphId: graph.graph.id,
    harnessInputSha256: graph.inputs.harness.inputSha256,
    harnessSnapshotId: graph.inputs.harness.snapshotId,
    skillContentSha256: graph.inputs.skill.contentSha256,
    skillSnapshotId: graph.inputs.skill.snapshotId,
    state: graph.correlation.state,
  };
}

function difference(left: unknown, right: unknown): SkillGraphEvidenceChange {
  return JSON.stringify(left) === JSON.stringify(right) ? "same" : "different";
}
