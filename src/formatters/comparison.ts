import type { ReportComparison } from "../comparison.js";
import type { Finding } from "../domain.js";
import { PRODUCT_NAME } from "../version.js";

export function formatComparisonJson(comparison: ReportComparison): string {
  return `${JSON.stringify(comparison, null, 2)}\n`;
}

export function formatComparisonText(comparison: ReportComparison): string {
  const lines = [
    `${PRODUCT_NAME} report comparison`,
    `${comparison.baseline.scanId} -> ${comparison.current.scanId}`,
    "",
    `${comparison.summary.added.toString()} added · ${comparison.summary.resolved.toString()} resolved · ${comparison.summary.unchanged.toString()} unchanged`,
  ];

  appendFindings(lines, "ADDED", comparison.added);
  appendFindings(lines, "RESOLVED", comparison.resolved);
  return `${lines.join("\n")}\n`;
}

function appendFindings(lines: string[], heading: string, findings: readonly Finding[]): void {
  if (findings.length === 0) {
    return;
  }
  lines.push("", `${heading} (${findings.length.toString()})`);
  for (const finding of findings) {
    lines.push(
      `${finding.severity.toUpperCase()} ${finding.ruleId} ${finding.title}`,
      `  ${finding.file}:${finding.line.toString()}:${finding.column.toString()}`,
    );
  }
}
