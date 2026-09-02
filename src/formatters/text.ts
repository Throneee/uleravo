import type { Finding, ScanReport, Severity } from "../domain.js";

const ANSI = {
  bold: "\u001b[1m",
  critical: "\u001b[91m",
  dim: "\u001b[2m",
  high: "\u001b[31m",
  info: "\u001b[36m",
  low: "\u001b[34m",
  medium: "\u001b[33m",
  reset: "\u001b[0m",
} as const;

export function formatText(report: ScanReport, color = false): string {
  const lines = [
    style(`${report.scanner.name} ${report.scanner.version}`, "bold", color),
    `${report.scan.target} · ${report.scan.filesScanned.toString()} files · ${report.scan.durationMs.toString()} ms`,
    "",
  ];

  if (report.findings.length === 0) {
    lines.push("No findings.");
  } else {
    for (const finding of report.findings) {
      lines.push(...formatFinding(finding, color), "");
    }
  }

  for (const diagnostic of report.diagnostics) {
    lines.push(
      style(
        `${diagnostic.type.toUpperCase()}: ${diagnostic.file === undefined ? "" : `${diagnostic.file}: `}${diagnostic.message}`,
        diagnostic.type === "error" ? "high" : "medium",
        color,
      ),
    );
  }

  const counts = report.summary;
  lines.push(
    `${counts.total.toString()} findings · ${counts.critical.toString()} critical · ${counts.high.toString()} high · ${counts.medium.toString()} medium · ${counts.low.toString()} low · ${counts.info.toString()} info`,
  );
  return `${lines.join("\n").trimEnd()}\n`;
}

function formatFinding(finding: Finding, color: boolean): readonly string[] {
  const label = `${finding.severity.toUpperCase()} ${finding.ruleId}`;
  return [
    `${style(label, finding.severity, color)} ${finding.title}`,
    style(
      `  ${finding.file}:${finding.line.toString()}:${finding.column.toString()}`,
      "dim",
      color,
    ),
    `  ${finding.message}`,
    style(`  ${finding.evidence}`, "dim", color),
    `  Fix: ${finding.remediation}`,
  ];
}

function style(value: string, tone: Severity | "bold" | "dim", enabled: boolean): string {
  return enabled ? `${ANSI[tone]}${value}${ANSI.reset}` : value;
}
