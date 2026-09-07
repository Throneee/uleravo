import { createHash } from "node:crypto";
import { compareCodeUnits } from "../order.js";
import type {
  CapabilityGraphDiagnostic,
  CapabilityGraphDiagnosticCode,
  SkillCapabilityGraph,
  SkillCorrelationState,
  SkillDeclarationEdge,
} from "./domain.js";
import { CAPABILITY_GRAPH_SCHEMA_VERSION, SKILL_CORRELATION_ADAPTER_VERSION } from "./domain.js";

export type EdgeCore = Omit<SkillDeclarationEdge, "from" | "id" | "to">;

const CLASSIFICATION_DIAGNOSTIC_CODES = new Set<CapabilityGraphDiagnosticCode>([
  "DECLARATION_AMBIGUOUS",
  "DECLARATION_APPLICABILITY_UNKNOWN",
  "DECLARATION_ENABLEMENT_UNKNOWN",
  "DECLARATION_IDENTITY_MISMATCH",
  "DECLARATION_NOT_APPLIED",
]);

export function classificationDiagnostics(edges: readonly EdgeCore[]): CapabilityGraphDiagnostic[] {
  const diagnostics: CapabilityGraphDiagnostic[] = [];
  const count = edges.reduce((total, edge) => total + edge.count, 0);
  if (count > 1) diagnostics.push(capabilityGraphDiagnostic("DECLARATION_AMBIGUOUS"));
  if (edges.some((edge) => edge.identity === "mismatch")) {
    diagnostics.push(capabilityGraphDiagnostic("DECLARATION_IDENTITY_MISMATCH"));
  }
  if (count === 1) {
    const edge = edges[0];
    if (edge?.applicability === "unknown") {
      diagnostics.push(capabilityGraphDiagnostic("DECLARATION_APPLICABILITY_UNKNOWN", edge.layer));
    } else if (edge !== undefined && edge.applicability !== "applied") {
      diagnostics.push(capabilityGraphDiagnostic("DECLARATION_NOT_APPLIED", edge.layer));
    }
    if (edge?.enablement === "unspecified") {
      diagnostics.push(capabilityGraphDiagnostic("DECLARATION_ENABLEMENT_UNKNOWN", edge.layer));
    }
  }
  return diagnostics.sort(compareCapabilityGraphDiagnostics);
}

export function isClassificationDiagnostic(diagnostic: CapabilityGraphDiagnostic): boolean {
  return CLASSIFICATION_DIAGNOSTIC_CODES.has(diagnostic.code);
}

export function buildCapabilityGraphIdentities(input: {
  readonly diagnostics: readonly CapabilityGraphDiagnostic[];
  readonly edges: readonly EdgeCore[];
  readonly inputs: SkillCapabilityGraph["inputs"];
  readonly state: SkillCorrelationState;
}): {
  readonly correlationId: string;
  readonly edges: readonly SkillDeclarationEdge[];
  readonly graphId: string;
  readonly nodes: SkillCapabilityGraph["nodes"];
} {
  const coreEdges = [...input.edges].sort(compareEdgeCores);
  const seed = {
    adapterVersion: SKILL_CORRELATION_ADAPTER_VERSION,
    edges: coreEdges,
    inputs: input.inputs,
    schemaVersion: CAPABILITY_GRAPH_SCHEMA_VERSION,
  };
  const harnessId = digestId("uleravo:skill-capability-node:codex-harness:v1\0", seed);
  const skillId = digestId("uleravo:skill-capability-node:skill:v1\0", seed);
  const nodes = [
    { id: harnessId, kind: "codex-harness" as const },
    { id: skillId, kind: "skill" as const },
  ] as const;
  const edges = coreEdges.map((edge) => ({
    ...edge,
    from: harnessId,
    id: digestId("uleravo:skill-capability-edge:v1\0", {
      edge,
      inputs: input.inputs,
      schemaVersion: CAPABILITY_GRAPH_SCHEMA_VERSION,
      version: SKILL_CORRELATION_ADAPTER_VERSION,
    }),
    to: skillId,
  }));
  const graphIdentity = {
    diagnostics: input.diagnostics.map(({ code, layer }) => ({
      code,
      ...(layer === undefined ? {} : { layer }),
    })),
    edges,
    inputs: input.inputs,
    nodes,
    state: input.state,
    schemaVersion: CAPABILITY_GRAPH_SCHEMA_VERSION,
    version: SKILL_CORRELATION_ADAPTER_VERSION,
  };
  return {
    correlationId: digestId("uleravo:skill-correlation:v1\0", graphIdentity),
    edges,
    graphId: digestId("uleravo:skill-capability-graph:v1\0", graphIdentity),
    nodes,
  };
}

export function compareEdgeCores(left: EdgeCore, right: EdgeCore): number {
  return (
    compareCodeUnits(left.layer, right.layer) ||
    compareCodeUnits(left.applicability, right.applicability) ||
    compareCodeUnits(left.enablement, right.enablement) ||
    compareCodeUnits(left.identity, right.identity) ||
    left.count - right.count
  );
}

export function compareCapabilityGraphDiagnostics(
  left: CapabilityGraphDiagnostic,
  right: CapabilityGraphDiagnostic,
): number {
  return (
    compareCodeUnits(left.layer ?? "", right.layer ?? "") ||
    compareCodeUnits(left.code, right.code) ||
    compareCodeUnits(left.message, right.message)
  );
}

export function capabilityGraphDiagnostic(
  code: CapabilityGraphDiagnosticCode,
  layer?: CapabilityGraphDiagnostic["layer"],
): CapabilityGraphDiagnostic {
  const message = diagnosticMessage(code);
  return {
    code,
    ...(layer === undefined ? {} : { layer }),
    message,
    type: "error",
  };
}

export function diagnosticMessage(code: CapabilityGraphDiagnosticCode): string {
  switch (code) {
    case "DECLARATION_AMBIGUOUS":
      return "Multiple exact Skill declarations prevent a unique declared-exposure classification.";
    case "DECLARATION_APPLICABILITY_UNKNOWN":
      return "A declaring configuration layer has unknown applicability.";
    case "DECLARATION_CONTEXT_CHANGED":
      return "A declaring configuration context changed during correlation.";
    case "DECLARATION_CONTEXT_UNAVAILABLE":
      return "A declaring configuration context could not be established safely.";
    case "DECLARATION_ENABLEMENT_UNKNOWN":
      return "The exact Skill declaration does not explicitly state enablement.";
    case "DECLARATION_IDENTITY_MISMATCH":
      return "The exact declared Skill identity did not remain byte-equivalent during correlation.";
    case "DECLARATION_LAYER_DISABLED":
      return "A declaration-bearing configuration layer was excluded from capture.";
    case "DECLARATION_NOT_APPLIED":
      return "An exact Skill declaration belongs to a configuration layer that was not applied.";
    case "DECLARATION_PATH_UNSAFE":
      return "A configured Skill path could not be resolved safely and unambiguously.";
    case "HARNESS_CAPTURE_CHANGED":
      return "The Codex harness evidence changed during correlation.";
    case "HARNESS_CAPTURE_INCOMPLETE":
      return "The Codex harness evidence is incomplete.";
    case "SKILL_CAPTURE_CHANGED":
      return "The supplied Skill identity changed during correlation.";
  }
}

export function correlationReason(state: SkillCorrelationState): string {
  switch (state) {
    case "declared-disabled":
      return "One exact, applicable declaration explicitly disables these Skill bytes.";
    case "declared-enabled":
      return "One exact, applicable declaration explicitly enables these Skill bytes.";
    case "not-declared":
      return "No exact declaration was found in the safely captured applicable user or project configuration.";
    case "unknown":
      return "The captured evidence does not support a definitive declared-exposure classification.";
  }
}

export function deriveCorrelationState(
  edges: readonly EdgeCore[],
  diagnostics: readonly CapabilityGraphDiagnostic[],
): SkillCorrelationState {
  if (diagnostics.length > 0) return "unknown";
  if (edges.length === 0) return "not-declared";
  const edge = edges[0];
  if (
    edges.length !== 1 ||
    edge === undefined ||
    edge.count !== 1 ||
    edge.identity !== "exact-content" ||
    edge.applicability !== "applied"
  ) {
    return "unknown";
  }
  if (edge.enablement === "enabled") return "declared-enabled";
  if (edge.enablement === "disabled") return "declared-disabled";
  return "unknown";
}

function digestId(domain: string, value: unknown): string {
  return createHash("sha256").update(domain).update(stableJson(value)).digest("hex").slice(0, 24);
}

function stableJson(value: unknown): string {
  return JSON.stringify(sortJsonValue(value));
}

function sortJsonValue(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortJsonValue);
  if (typeof value !== "object" || value === null) return value;
  const object = value as Record<string, unknown>;
  return Object.fromEntries(
    Object.keys(object)
      .sort(compareCodeUnits)
      .map((key) => [key, sortJsonValue(object[key])]),
  );
}
