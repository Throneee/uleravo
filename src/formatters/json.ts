import type { ScanReport } from "../domain.js";

export function formatJson(report: ScanReport): string {
  return `${JSON.stringify(report, null, 2)}\n`;
}
