import { createHash } from "node:crypto";
import { validateJsonStructure } from "../artifacts/read.js";
import { ARTIFACT_ANALYZER_VERSION, HARNESS_ANALYZER_VERSION } from "../version.js";
import { compareSkillCapabilityGraphs, type SkillCapabilityGraphComparison } from "./comparison.js";
import { MAX_CAPABILITY_GRAPH_REPORT_BYTES, type SkillCapabilityGraph } from "./domain.js";
import { parseSkillCapabilityGraph } from "./read.js";

export const SKILL_REVIEW_SCHEMA_VERSION = "1.0.0" as const;
export const MAX_SKILL_REVIEW_RECEIPT_BYTES = MAX_CAPABILITY_GRAPH_REPORT_BYTES + 4_000;

export interface SkillReviewReceipt {
  readonly authentication: "unsigned-unauthenticated";
  readonly declaration: "caller-declared";
  readonly disposition: "reviewed-captured-evidence";
  readonly documentType: "uleravo.skill-review-receipt";
  readonly graph: SkillCapabilityGraph;
  readonly receipt: { readonly id: string };
  readonly schemaVersion: typeof SKILL_REVIEW_SCHEMA_VERSION;
  readonly scope: "advisory-only";
}

export interface SkillReviewCheck {
  readonly authentication: SkillReviewReceipt["authentication"];
  readonly comparison: SkillCapabilityGraphComparison;
  readonly declaration: SkillReviewReceipt["declaration"];
  readonly disposition: SkillReviewReceipt["disposition"];
  readonly documentType: "uleravo.skill-review-check";
  readonly limitations: readonly string[];
  readonly receiptId: string;
  readonly schemaVersion: typeof SKILL_REVIEW_SCHEMA_VERSION;
  readonly scope: SkillReviewReceipt["scope"];
  readonly status: "matches-evidence" | "changed-since-review" | "cannot-check";
}

/** Retain one complete supplied graph as an explicit, unauthenticated caller declaration. */
export function recordSkillReview(graph: SkillCapabilityGraph): SkillReviewReceipt {
  const normalized = parseSkillCapabilityGraph(JSON.stringify(graph), "Reviewed capability graph");
  if (!normalized.complete || normalized.correlation.state === "unknown") {
    throw new Error(
      "Cannot record unknown or incomplete evidence. Resolve the graph diagnostics and recapture before reviewing.",
    );
  }
  if (
    normalized.inputs.skill.analyzerVersion !== ARTIFACT_ANALYZER_VERSION ||
    normalized.inputs.harness.analyzerVersion !== HARNESS_ANALYZER_VERSION
  ) {
    throw new Error(
      "Cannot record evidence from unsupported analyzer versions. Recapture with supported analyzers before reviewing.",
    );
  }
  const payload = {
    authentication: "unsigned-unauthenticated" as const,
    declaration: "caller-declared" as const,
    disposition: "reviewed-captured-evidence" as const,
    documentType: "uleravo.skill-review-receipt" as const,
    graph: normalized,
    schemaVersion: SKILL_REVIEW_SCHEMA_VERSION,
    scope: "advisory-only" as const,
  };
  // The authoritative graph reader reconstructs every field in a fixed order. Hash the
  // full normalized payload, including scope and decision, rather than short graph IDs.
  const id = createHash("sha256")
    .update("uleravo:skill-review-receipt:v1\0")
    .update(JSON.stringify(payload))
    .digest("hex");
  return { ...payload, receipt: { id } };
}

export function parseSkillReviewReceipt(serialized: string): SkillReviewReceipt {
  if (Buffer.byteLength(serialized, "utf8") > MAX_SKILL_REVIEW_RECEIPT_BYTES) {
    throw new Error("Skill review receipt exceeds the report byte limit.");
  }
  validateJsonStructure(serialized, "Skill review receipt");
  const root = exactObject(JSON.parse(serialized) as unknown, [
    "authentication",
    "declaration",
    "disposition",
    "documentType",
    "graph",
    "receipt",
    "schemaVersion",
    "scope",
  ]);
  if (
    root.authentication !== "unsigned-unauthenticated" ||
    root.declaration !== "caller-declared" ||
    root.disposition !== "reviewed-captured-evidence" ||
    root.documentType !== "uleravo.skill-review-receipt" ||
    root.schemaVersion !== SKILL_REVIEW_SCHEMA_VERSION ||
    root.scope !== "advisory-only"
  ) {
    throw new Error("Skill review receipt contains unsupported metadata or disposition.");
  }
  const receipt = exactObject(root.receipt, ["id"]);
  const expected = recordSkillReview(root.graph as SkillCapabilityGraph);
  if (receipt.id !== expected.receipt.id) {
    throw new Error(
      "Skill review receipt identity does not match its complete normalized contents.",
    );
  }
  return expected;
}

/** Checking inert supplied reports never promotes evidence or changes the receipt. */
export function checkSkillReview(
  receipt: SkillReviewReceipt,
  current: SkillCapabilityGraph,
): SkillReviewCheck {
  const reviewed = parseSkillReviewReceipt(JSON.stringify(receipt));
  const comparison = compareSkillCapabilityGraphs(reviewed.graph, current);
  return {
    authentication: reviewed.authentication,
    comparison,
    declaration: reviewed.declaration,
    disposition: reviewed.disposition,
    documentType: "uleravo.skill-review-check",
    limitations: [
      "Recapture before checking. A supplied old graph can only match old evidence; it does not establish current filesystem or runtime state. Time alone does not establish freshness.",
      "The unsigned caller declaration does not prove a human reviewed the Skill or authorize execution. This check never promotes new evidence or changes the receipt.",
      "The receipt retains one reviewed graph. It does not prove restoration of an earlier state; compare the original baseline with recaptured evidence separately.",
    ],
    receiptId: reviewed.receipt.id,
    schemaVersion: SKILL_REVIEW_SCHEMA_VERSION,
    scope: reviewed.scope,
    status:
      comparison.status === "unchanged"
        ? "matches-evidence"
        : comparison.status === "changed"
          ? "changed-since-review"
          : "cannot-check",
  };
}

function exactObject(value: unknown, keys: readonly string[]): Record<string, unknown> {
  if (
    typeof value !== "object" ||
    value === null ||
    Array.isArray(value) ||
    Object.keys(value).length !== keys.length ||
    keys.some((key) => !Object.hasOwn(value, key))
  ) {
    // Do not include imported field names or values in errors.
    throw new Error("Skill review receipt has an invalid object or unexpected fields.");
  }
  return value as Record<string, unknown>;
}
