import {
  MAX_SKILL_REVIEW_RECEIPT_BYTES,
  parseSkillReviewReceipt,
  type SkillReviewCheck,
  type SkillReviewReceipt,
} from "../capability-graph/review.js";
import { formatSkillCapabilityGraphText } from "./capability-graph.js";
import { formatSkillCapabilityGraphComparisonText } from "./capability-graph-comparison.js";

export function formatSkillReviewReceiptJson(receipt: SkillReviewReceipt): string {
  const serialized = `${JSON.stringify(parseSkillReviewReceipt(JSON.stringify(receipt)), null, 2)}\n`;
  if (Buffer.byteLength(serialized, "utf8") > MAX_SKILL_REVIEW_RECEIPT_BYTES) {
    throw new Error("Skill review receipt exceeds the bounded report size.");
  }
  return serialized;
}

export function formatSkillReviewReceiptText(receipt: SkillReviewReceipt): string {
  const normalized = parseSkillReviewReceipt(JSON.stringify(receipt));
  return `${[
    "Uleravo retained Skill evidence review",
    `Receipt SHA-256: ${normalized.receipt.id}`,
    ...declarationLines(),
    "This receipt does not prove a human reviewed the Skill or authorize execution.",
    "Recapture before checking. A supplied old graph does not establish current filesystem or runtime state.",
    "Use review-record --format json to retain a machine-readable receipt.",
    formatSkillCapabilityGraphText(normalized.graph).trimEnd(),
  ].join("\n")}\n`;
}

export function formatSkillReviewCheckJson(check: SkillReviewCheck): string {
  return `${JSON.stringify(check, null, 2)}\n`;
}

export function formatSkillReviewCheckText(check: SkillReviewCheck): string {
  return `${[
    "Uleravo Skill evidence review check (reviewed -> supplied current)",
    `Review result: ${check.status}`,
    check.status === "matches-evidence"
      ? "The supplied graph matches this recorded evidence review."
      : check.status === "changed-since-review"
        ? "The supplied evidence changed. Review the differences before explicitly recording a new receipt."
        : "Unable to check complete evidence. Resolve the comparison limitations and recapture.",
    formatSkillCapabilityGraphComparisonText(check.comparison).trimEnd(),
    ...declarationLines(),
    ...check.limitations,
    `Receipt SHA-256: ${check.receiptId}`,
  ].join("\n")}\n`;
}

function declarationLines(): string[] {
  return [
    "Recorded disposition: reviewed-captured-evidence (caller-declared).",
    "Scope: advisory-only. Authentication: unsigned-unauthenticated.",
  ];
}
