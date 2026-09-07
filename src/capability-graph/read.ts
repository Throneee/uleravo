import { constants, type Stats } from "node:fs";
import { lstat, open } from "node:fs/promises";
import path from "node:path";
import { validateJsonStructure } from "../artifacts/read.js";
import {
  CODEX_HARNESS_ADAPTER_VERSION,
  CODEX_HARNESS_SCHEMA_VERSION,
  type CodexHarnessApplicability,
  MAX_HARNESS_FACTS,
} from "../harnesses/domain.js";
import { compareCodeUnits } from "../order.js";
import { sameOpenedFileSnapshot, samePathAndOpenedFileSnapshot } from "../scanner/files.js";
import {
  CAPABILITY_GRAPH_DIAGNOSTIC_CODES,
  CAPABILITY_GRAPH_SCHEMA_VERSION,
  type CapabilityGraphDiagnostic,
  type CapabilityGraphDiagnosticCode,
  MAX_CAPABILITY_GRAPH_REPORT_BYTES,
  SKILL_CORRELATION_ADAPTER_VERSION,
  type SkillCapabilityGraph,
  type SkillDeclarationEnablement,
  type SkillDeclarationIdentity,
} from "./domain.js";
import {
  buildCapabilityGraphIdentities,
  classificationDiagnostics,
  compareCapabilityGraphDiagnostics,
  compareEdgeCores,
  correlationReason,
  deriveCorrelationState,
  diagnosticMessage,
  type EdgeCore,
  isClassificationDiagnostic,
} from "./identity.js";

const utf8Decoder = new TextDecoder("utf-8", { fatal: true });
const ID_PATTERN = /^[a-f0-9]{24}$/u;
const SHA256_PATTERN = /^[a-f0-9]{64}$/u;
const VERSION_PATTERN = /^[A-Za-z0-9][A-Za-z0-9.+_-]{0,99}$/u;
const MAX_EDGES = 100;
const MAX_DIAGNOSTICS = 100;
const DIAGNOSTIC_CODES = new Set<CapabilityGraphDiagnosticCode>(CAPABILITY_GRAPH_DIAGNOSTIC_CODES);
const DIAGNOSTIC_EDGE_COMPATIBILITY = {
  DECLARATION_AMBIGUOUS: "permits-edges",
  DECLARATION_APPLICABILITY_UNKNOWN: "permits-edges",
  DECLARATION_CONTEXT_CHANGED: "permits-edges",
  DECLARATION_CONTEXT_UNAVAILABLE: "prohibits-same-layer-edges",
  DECLARATION_ENABLEMENT_UNKNOWN: "permits-edges",
  DECLARATION_IDENTITY_MISMATCH: "permits-edges",
  DECLARATION_LAYER_DISABLED: "prohibits-same-layer-edges",
  DECLARATION_NOT_APPLIED: "permits-edges",
  DECLARATION_PATH_UNSAFE: "permits-edges",
  HARNESS_CAPTURE_CHANGED: "permits-edges",
  HARNESS_CAPTURE_INCOMPLETE: "prohibits-all-edges",
  SKILL_CAPTURE_CHANGED: "prohibits-all-edges",
} as const satisfies Record<
  CapabilityGraphDiagnosticCode,
  "permits-edges" | "prohibits-all-edges" | "prohibits-same-layer-edges"
>;

type JsonObject = Record<string, unknown>;

export async function readSkillCapabilityGraph(source: string): Promise<SkillCapabilityGraph> {
  const resolved = path.resolve(source);
  const listed = await lstat(resolved);
  assertGraphFile(listed);
  const handle = await open(resolved, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  try {
    const opened = await handle.stat();
    assertGraphFile(opened);
    if (!samePathAndOpenedFileSnapshot(listed, opened)) {
      throw new Error("Capability graph changed before it could be read safely.");
    }
    const buffer = Buffer.allocUnsafe(opened.size + 1);
    let used = 0;
    while (used < buffer.byteLength) {
      const { bytesRead } = await handle.read(buffer, used, buffer.byteLength - used, used);
      if (bytesRead === 0) break;
      used += bytesRead;
    }
    if (used > MAX_CAPABILITY_GRAPH_REPORT_BYTES) {
      throw new Error("Capability graph exceeds the report byte limit.");
    }
    const [after, pathAfter] = await Promise.all([handle.stat(), lstat(resolved)]);
    if (
      used !== opened.size ||
      !sameOpenedFileSnapshot(opened, after) ||
      !samePathAndOpenedFileSnapshot(pathAfter, opened)
    ) {
      throw new Error("Capability graph changed while it was being read.");
    }
    let serialized: string;
    try {
      serialized = utf8Decoder.decode(buffer.subarray(0, used));
    } catch {
      throw new Error("Capability graph is not valid UTF-8.");
    }
    return parseSkillCapabilityGraph(serialized, source);
  } finally {
    await handle.close();
  }
}

export function parseSkillCapabilityGraph(
  serialized: string,
  label = "Capability graph",
): SkillCapabilityGraph {
  if (Buffer.byteLength(serialized, "utf8") > MAX_CAPABILITY_GRAPH_REPORT_BYTES) {
    throw new Error(`${label} exceeds the report byte limit.`);
  }
  validateJsonStructure(serialized, label);
  const root = exactObject(JSON.parse(serialized) as unknown, label, [
    "adapter",
    "complete",
    "correlation",
    "diagnostics",
    "documentType",
    "edges",
    "graph",
    "inputs",
    "nodes",
    "schemaVersion",
    "scope",
  ]);
  literal(root.documentType, "uleravo.skill-capability-graph", `${label}.documentType`);
  literal(root.schemaVersion, CAPABILITY_GRAPH_SCHEMA_VERSION, `${label}.schemaVersion`);
  const adapter = parseAdapter(root.adapter, `${label}.adapter`);
  const inputs = parseInputs(root.inputs, `${label}.inputs`);
  const diagnostics = parseDiagnostics(root.diagnostics, `${label}.diagnostics`);
  const parsedEdges = parseEdges(root.edges, `${label}.edges`);
  const edgeCores = parsedEdges.map(({ from: _from, id: _id, to: _to, ...edge }) => edge);
  assertSemanticDiagnostics(edgeCores, diagnostics, label);
  const state = deriveCorrelationState(edgeCores, diagnostics);
  if (state === "unknown" && diagnostics.length === 0) {
    invalid(`${label}.diagnostics`, "must explain an unknown correlation");
  }
  const complete = booleanValue(root.complete, `${label}.complete`);
  if (complete !== (state !== "unknown")) {
    invalid(`${label}.complete`, "does not match correlation completeness");
  }
  const correlation = exactObject(root.correlation, `${label}.correlation`, [
    "id",
    "reason",
    "state",
  ]);
  if (correlation.state !== state || correlation.reason !== correlationReason(state)) {
    invalid(`${label}.correlation`, "does not match the recomputed declared-exposure state");
  }
  const correlationId = digest(correlation.id, `${label}.correlation.id`, ID_PATTERN);
  const graph = exactObject(root.graph, `${label}.graph`, ["id"]);
  const graphId = digest(graph.id, `${label}.graph.id`, ID_PATTERN);
  const nodes = parseNodes(root.nodes, `${label}.nodes`);
  parseScope(root.scope, `${label}.scope`);

  const expected = buildCapabilityGraphIdentities({ diagnostics, edges: edgeCores, inputs, state });
  if (
    nodes.some(
      (node, index) =>
        node.id !== expected.nodes[index]?.id || node.kind !== expected.nodes[index]?.kind,
    ) ||
    parsedEdges.some((edge, index) => !sameEdge(edge, expected.edges[index])) ||
    parsedEdges.length !== expected.edges.length
  ) {
    invalid(label, "has noncanonical node or edge ordering/identities");
  }
  if (graphId !== expected.graphId || correlationId !== expected.correlationId) {
    invalid(label, "has an identity that does not match its contents");
  }
  return {
    adapter,
    complete,
    correlation: { id: correlationId, reason: correlationReason(state), state },
    diagnostics,
    documentType: "uleravo.skill-capability-graph",
    edges: parsedEdges,
    graph: { id: graphId },
    inputs,
    nodes,
    schemaVersion: CAPABILITY_GRAPH_SCHEMA_VERSION,
    scope: {
      assertion: "declared-exposure-only",
      effectAuthority: "not-established",
      runtimeReachability: "not-observed",
    },
  };
}

function sameEdge(
  left: SkillCapabilityGraph["edges"][number],
  right: SkillCapabilityGraph["edges"][number] | undefined,
): boolean {
  return (
    right !== undefined &&
    left.applicability === right.applicability &&
    left.count === right.count &&
    left.enablement === right.enablement &&
    left.from === right.from &&
    left.id === right.id &&
    left.identity === right.identity &&
    left.kind === right.kind &&
    left.layer === right.layer &&
    left.to === right.to
  );
}

function assertGraphFile(metadata: Stats): void {
  if (!metadata.isFile() || metadata.isSymbolicLink()) {
    throw new Error("Capability graph must be a regular, non-linked file.");
  }
  if (metadata.size < 0 || metadata.size > MAX_CAPABILITY_GRAPH_REPORT_BYTES) {
    throw new Error("Capability graph exceeds the report byte limit.");
  }
}

function parseAdapter(value: unknown, label: string): SkillCapabilityGraph["adapter"] {
  const adapter = exactObject(value, label, ["name", "version"]);
  literal(adapter.name, "openai-skill-codex-correlation", `${label}.name`);
  literal(adapter.version, SKILL_CORRELATION_ADAPTER_VERSION, `${label}.version`);
  return {
    name: "openai-skill-codex-correlation",
    version: SKILL_CORRELATION_ADAPTER_VERSION,
  };
}

function parseInputs(value: unknown, label: string): SkillCapabilityGraph["inputs"] {
  const inputs = exactObject(value, label, ["harness", "skill"]);
  const harness = exactObject(inputs.harness, `${label}.harness`, [
    "adapter",
    "analyzerVersion",
    "inputSha256",
    "schemaVersion",
    "snapshotId",
  ]);
  const harnessAdapter = exactObject(harness.adapter, `${label}.harness.adapter`, [
    "name",
    "version",
  ]);
  literal(harnessAdapter.name, "openai-codex-local", `${label}.harness.adapter.name`);
  literal(
    harnessAdapter.version,
    CODEX_HARNESS_ADAPTER_VERSION,
    `${label}.harness.adapter.version`,
  );
  literal(harness.schemaVersion, CODEX_HARNESS_SCHEMA_VERSION, `${label}.harness.schemaVersion`);

  const skill = exactObject(inputs.skill, `${label}.skill`, [
    "adapter",
    "analyzerVersion",
    "contentSha256",
    "schemaVersion",
    "snapshotId",
  ]);
  const skillAdapter = exactObject(skill.adapter, `${label}.skill.adapter`, ["name", "version"]);
  literal(skillAdapter.name, "openai-skill", `${label}.skill.adapter.name`);
  literal(skillAdapter.version, "1.0.0", `${label}.skill.adapter.version`);
  literal(skill.schemaVersion, "1.0.0", `${label}.skill.schemaVersion`);
  return {
    harness: {
      adapter: { name: "openai-codex-local", version: CODEX_HARNESS_ADAPTER_VERSION },
      analyzerVersion: version(harness.analyzerVersion, `${label}.harness.analyzerVersion`),
      inputSha256: digest(harness.inputSha256, `${label}.harness.inputSha256`, SHA256_PATTERN),
      schemaVersion: CODEX_HARNESS_SCHEMA_VERSION,
      snapshotId: digest(harness.snapshotId, `${label}.harness.snapshotId`, ID_PATTERN),
    },
    skill: {
      adapter: { name: "openai-skill", version: "1.0.0" },
      analyzerVersion: version(skill.analyzerVersion, `${label}.skill.analyzerVersion`),
      contentSha256: digest(skill.contentSha256, `${label}.skill.contentSha256`, SHA256_PATTERN),
      schemaVersion: "1.0.0",
      snapshotId: digest(skill.snapshotId, `${label}.skill.snapshotId`, ID_PATTERN),
    },
  };
}

function parseDiagnostics(value: unknown, label: string): CapabilityGraphDiagnostic[] {
  const entries = arrayValue(value, label, MAX_DIAGNOSTICS);
  const diagnostics = entries.map((raw, index) => {
    const location = `${label}[${index.toString()}]`;
    const entry = objectValue(raw, location);
    const code = diagnosticCode(entry.code, `${location}.code`);
    const layerRequired = diagnosticLayerRequired(code);
    const layerPresent = Object.hasOwn(entry, "layer");
    const layerAllowed = layerRequired || code === "HARNESS_CAPTURE_INCOMPLETE";
    if (layerRequired && !layerPresent) invalid(`${location}.layer`, "is required");
    if (!layerAllowed && layerPresent) invalid(`${location}.layer`, "is not allowed");
    const expectedKeys = layerPresent
      ? ["code", "layer", "message", "type"]
      : ["code", "message", "type"];
    exactKeys(entry, location, expectedKeys);
    literal(entry.message, diagnosticMessage(code), `${location}.message`);
    literal(entry.type, "error", `${location}.type`);
    const layer = layerPresent ? declarationLayer(entry.layer, `${location}.layer`) : undefined;
    return {
      code,
      ...(layer === undefined ? {} : { layer }),
      message: diagnosticMessage(code),
      type: "error" as const,
    };
  });
  assertOrdered(diagnostics, label, compareCapabilityGraphDiagnostics);
  return diagnostics;
}

function parseEdges(value: unknown, label: string): SkillCapabilityGraph["edges"] {
  const edges = arrayValue(value, label, MAX_EDGES).map((raw, index) => {
    const location = `${label}[${index.toString()}]`;
    const edge = exactObject(raw, location, [
      "applicability",
      "count",
      "enablement",
      "from",
      "id",
      "identity",
      "kind",
      "layer",
      "to",
    ]);
    literal(edge.kind, "declares-skill", `${location}.kind`);
    return {
      applicability: applicability(edge.applicability, `${location}.applicability`),
      count: positiveInteger(edge.count, `${location}.count`),
      enablement: enablement(edge.enablement, `${location}.enablement`),
      from: digest(edge.from, `${location}.from`, ID_PATTERN),
      id: digest(edge.id, `${location}.id`, ID_PATTERN),
      identity: identity(edge.identity, `${location}.identity`),
      kind: "declares-skill" as const,
      layer: declarationLayer(edge.layer, `${location}.layer`),
      to: digest(edge.to, `${location}.to`, ID_PATTERN),
    };
  });
  const cores = edges.map(({ from: _from, id: _id, to: _to, ...edge }) => edge);
  assertOrdered(cores, label, compareEdgeCores);
  return edges;
}

function parseNodes(value: unknown, label: string): SkillCapabilityGraph["nodes"] {
  const entries = arrayValue(value, label, 2);
  if (entries.length !== 2) invalid(label, "must contain exactly two nodes");
  const parseNode = (raw: unknown, index: number, expectedKind: "codex-harness" | "skill") => {
    const location = `${label}[${index.toString()}]`;
    const node = exactObject(raw, location, ["id", "kind"]);
    literal(node.kind, expectedKind, `${location}.kind`);
    return { id: digest(node.id, `${location}.id`, ID_PATTERN), kind: expectedKind };
  };
  return [parseNode(entries[0], 0, "codex-harness"), parseNode(entries[1], 1, "skill")];
}

function parseScope(value: unknown, label: string): void {
  const scope = exactObject(value, label, ["assertion", "effectAuthority", "runtimeReachability"]);
  literal(scope.assertion, "declared-exposure-only", `${label}.assertion`);
  literal(scope.effectAuthority, "not-established", `${label}.effectAuthority`);
  literal(scope.runtimeReachability, "not-observed", `${label}.runtimeReachability`);
}

function assertSemanticDiagnostics(
  edges: readonly EdgeCore[],
  diagnostics: readonly CapabilityGraphDiagnostic[],
  label: string,
): void {
  assertUniqueSemanticEdgeGroups(edges, `${label}.edges`);
  const count = edges.reduce((total, edge) => total + edge.count, 0);
  if (count > MAX_HARNESS_FACTS) {
    invalid(`${label}.edges`, "exceeds the bounded Codex Skill declaration inventory");
  }
  const expected = classificationDiagnostics(edges);
  const actual = diagnostics.filter(isClassificationDiagnostic);
  if (
    actual.length !== expected.length ||
    actual.some(
      (diagnostic, index) =>
        compareCapabilityGraphDiagnostics(
          diagnostic,
          expected[index] as CapabilityGraphDiagnostic,
        ) !== 0,
    )
  ) {
    invalid(`${label}.diagnostics`, "does not match the recomputed edge classification");
  }
  assertDiagnosticEdgeCompatibility(edges, diagnostics, `${label}.diagnostics`);
}

function assertDiagnosticEdgeCompatibility(
  edges: readonly EdgeCore[],
  diagnostics: readonly CapabilityGraphDiagnostic[],
  label: string,
): void {
  for (const diagnostic of diagnostics) {
    const compatibility = DIAGNOSTIC_EDGE_COMPATIBILITY[diagnostic.code];
    const prohibited =
      compatibility === "prohibits-all-edges"
        ? edges.length > 0
        : compatibility === "prohibits-same-layer-edges" &&
          diagnostic.layer !== undefined &&
          edges.some((edge) => edge.layer === diagnostic.layer);
    if (prohibited) {
      invalid(label, `violates diagnostic/edge compatibility for ${diagnostic.code}`);
    }
  }
}

function assertUniqueSemanticEdgeGroups(edges: readonly EdgeCore[], label: string): void {
  const groups = new Set<string>();
  for (const edge of edges) {
    const key = [edge.layer, edge.applicability, edge.enablement, edge.identity].join("\0");
    if (groups.has(key)) {
      invalid(label, "must aggregate duplicate semantic declaration groups");
    }
    groups.add(key);
  }
}

function diagnosticLayerRequired(code: CapabilityGraphDiagnosticCode): boolean {
  return (
    code === "DECLARATION_APPLICABILITY_UNKNOWN" ||
    code === "DECLARATION_CONTEXT_CHANGED" ||
    code === "DECLARATION_CONTEXT_UNAVAILABLE" ||
    code === "DECLARATION_ENABLEMENT_UNKNOWN" ||
    code === "DECLARATION_LAYER_DISABLED" ||
    code === "DECLARATION_NOT_APPLIED" ||
    code === "DECLARATION_PATH_UNSAFE"
  );
}

function diagnosticCode(value: unknown, label: string): CapabilityGraphDiagnosticCode {
  if (typeof value !== "string" || !DIAGNOSTIC_CODES.has(value as CapabilityGraphDiagnosticCode)) {
    invalid(label, "is unsupported");
  }
  return value as CapabilityGraphDiagnosticCode;
}

function declarationLayer(value: unknown, label: string): "project-config" | "user-config" {
  if (value !== "project-config" && value !== "user-config") invalid(label, "is unsupported");
  return value;
}

function applicability(
  value: unknown,
  label: string,
): Exclude<CodexHarnessApplicability, "constraints"> {
  if (value !== "applied" && value !== "ignored" && value !== "unknown") {
    invalid(label, "is unsupported");
  }
  return value;
}

function enablement(value: unknown, label: string): SkillDeclarationEnablement {
  if (value !== "disabled" && value !== "enabled" && value !== "unspecified") {
    invalid(label, "is unsupported");
  }
  return value;
}

function identity(value: unknown, label: string): SkillDeclarationIdentity {
  if (value !== "exact-content" && value !== "mismatch") invalid(label, "is unsupported");
  return value;
}

function version(value: unknown, label: string): string {
  if (typeof value !== "string" || !VERSION_PATTERN.test(value)) invalid(label, "is invalid");
  return value;
}

function digest(value: unknown, label: string, pattern: RegExp): string {
  if (typeof value !== "string" || !pattern.test(value)) invalid(label, "is invalid");
  return value;
}

function positiveInteger(value: unknown, label: string): number {
  if (!Number.isSafeInteger(value) || (value as number) < 1 || (value as number) > 10_000) {
    invalid(label, "must be a positive safe integer no greater than 10000");
  }
  return value as number;
}

function booleanValue(value: unknown, label: string): boolean {
  if (typeof value !== "boolean") invalid(label, "must be boolean");
  return value;
}

function arrayValue(value: unknown, label: string, maximum: number): unknown[] {
  if (!Array.isArray(value) || value.length > maximum) {
    invalid(label, `must be an array with at most ${maximum.toString()} entries`);
  }
  return value;
}

function exactObject(value: unknown, label: string, keys: readonly string[]): JsonObject {
  const object = objectValue(value, label);
  exactKeys(object, label, keys);
  return object;
}

function exactKeys(object: JsonObject, label: string, keys: readonly string[]): void {
  const actual = Object.keys(object).sort(compareCodeUnits);
  const expected = [...keys].sort(compareCodeUnits);
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    invalid(label, "has unknown or missing fields");
  }
}

function objectValue(value: unknown, label: string): JsonObject {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    invalid(label, "must be an object");
  }
  return value as JsonObject;
}

function literal<T extends string>(value: unknown, expected: T, label: string): T {
  if (value !== expected) invalid(label, `must be ${JSON.stringify(expected)}`);
  return expected;
}

function assertOrdered<T>(
  entries: readonly T[],
  label: string,
  compare: (left: T, right: T) => number,
): void {
  for (let index = 1; index < entries.length; index += 1) {
    if (compare(entries[index - 1] as T, entries[index] as T) >= 0) {
      invalid(label, "must be canonically ordered without duplicates");
    }
  }
}

function invalid(label: string, reason: string): never {
  throw new Error(`${label} ${reason}.`);
}
