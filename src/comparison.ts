import type { Finding, RepositoryProvenance, ScanReport } from "./domain.js";
import { compareFindings } from "./domain.js";

export interface ScanReference {
  readonly repository?: RepositoryProvenance;
  readonly scanId: string;
  readonly scanInputSha256?: string;
  readonly scannerVersion: string;
}

export interface ComparisonSummary {
  readonly added: number;
  readonly resolved: number;
  readonly unchanged: number;
}

export interface ReportComparison {
  readonly added: readonly Finding[];
  readonly baseline: ScanReference;
  readonly current: ScanReference;
  readonly resolved: readonly Finding[];
  readonly schemaVersion: "1.0.0";
  readonly summary: ComparisonSummary;
  readonly unchanged: readonly Finding[];
}

export function compareReports(baseline: ScanReport, current: ScanReport): ReportComparison {
  const baselineGroups = groupByFingerprint(baseline.findings);
  const currentGroups = groupByFingerprint(current.findings);
  const fingerprints = new Set([...baselineGroups.keys(), ...currentGroups.keys()]);
  const added: Finding[] = [];
  const resolved: Finding[] = [];
  const unchanged: Finding[] = [];

  for (const fingerprint of [...fingerprints].sort()) {
    const before = baselineGroups.get(fingerprint) ?? [];
    const after = currentGroups.get(fingerprint) ?? [];
    const sharedCount = Math.min(before.length, after.length);
    unchanged.push(...after.slice(0, sharedCount));
    resolved.push(...before.slice(sharedCount));
    added.push(...after.slice(sharedCount));
  }

  added.sort(compareFindings);
  resolved.sort(compareFindings);
  unchanged.sort(compareFindings);

  return {
    added,
    baseline: scanReference(baseline),
    current: scanReference(current),
    resolved,
    schemaVersion: "1.0.0",
    summary: {
      added: added.length,
      resolved: resolved.length,
      unchanged: unchanged.length,
    },
    unchanged,
  };
}

function groupByFingerprint(findings: readonly Finding[]): Map<string, Finding[]> {
  const groups = new Map<string, Finding[]>();
  for (const finding of findings) {
    const group = groups.get(finding.fingerprint);
    if (group === undefined) {
      groups.set(finding.fingerprint, [finding]);
    } else {
      group.push(finding);
    }
  }
  for (const group of groups.values()) {
    group.sort(compareFindings);
  }
  return groups;
}

function scanReference(report: ScanReport): ScanReference {
  return {
    ...(report.provenance?.repository === undefined
      ? {}
      : { repository: { ...report.provenance.repository } }),
    scanId: report.scan.id,
    ...(report.provenance === undefined
      ? {}
      : { scanInputSha256: report.provenance.scanInputSha256 }),
    scannerVersion: report.scanner.version,
  };
}
