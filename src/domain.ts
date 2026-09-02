import { createHash } from "node:crypto";
import { compareCodeUnits } from "./order.js";
import { redactEvidence } from "./redact.js";

export const SEVERITIES = ["info", "low", "medium", "high", "critical"] as const;
export type Severity = (typeof SEVERITIES)[number];

export const CONFIDENCE_LEVELS = ["low", "medium", "high"] as const;
export type Confidence = (typeof CONFIDENCE_LEVELS)[number];

export interface StandardsMapping {
  readonly atlas: readonly string[];
  readonly cwe: readonly string[];
  readonly owasp: readonly string[];
}

export interface RuleMetadata {
  readonly confidence: Confidence;
  readonly description: string;
  readonly id: string;
  readonly remediation: string;
  readonly severity: Severity;
  readonly standards: StandardsMapping;
  readonly title: string;
}

export interface SourceLocation {
  readonly column: number;
  readonly endColumn?: number;
  readonly endLine?: number;
  readonly file: string;
  readonly line: number;
}

export interface Finding extends SourceLocation {
  readonly confidence: Confidence;
  readonly evidence: string;
  readonly fingerprint: string;
  readonly message: string;
  readonly remediation: string;
  readonly ruleId: string;
  readonly severity: Severity;
  readonly standards: StandardsMapping;
  readonly title: string;
}

export interface Diagnostic {
  readonly file?: string;
  readonly message: string;
  readonly type: "error" | "warning";
}

export interface ScanSummary {
  readonly critical: number;
  readonly high: number;
  readonly info: number;
  readonly low: number;
  readonly medium: number;
  readonly total: number;
}

export interface LockfileProvenance {
  readonly path: string;
  readonly sha256?: string;
  readonly state: "hashed" | "size-limit";
}

export interface PackageProvenance {
  readonly name?: string;
  readonly version?: string;
}

export interface RepositoryProvenance {
  readonly commit: string;
  readonly url: string;
}

export interface ScanProvenance {
  readonly lockfiles: readonly LockfileProvenance[];
  readonly package?: PackageProvenance;
  readonly repository?: RepositoryProvenance;
  readonly scanInputSha256: string;
}

export interface ScanReport {
  readonly diagnostics: readonly Diagnostic[];
  readonly findings: readonly Finding[];
  readonly provenance?: ScanProvenance;
  readonly scan: {
    readonly durationMs: number;
    readonly filesScanned: number;
    readonly filesSkipped: number;
    readonly generatedAt: string;
    readonly id: string;
    readonly target: string;
  };
  readonly scanner: {
    readonly name: string;
    readonly version: string;
  };
  readonly schemaVersion: "1.0.0";
  readonly summary: ScanSummary;
}

export interface FindingInput extends SourceLocation {
  readonly evidence: string;
  readonly message: string;
  readonly metadata: RuleMetadata;
}

export function createFinding(input: FindingInput): Finding {
  const evidence = redactEvidence(input.evidence);
  const file = redactEvidence(input.file);
  const fingerprint = findingFingerprint(input.metadata.id, file, evidence);

  return {
    column: input.column,
    confidence: input.metadata.confidence,
    ...(input.endColumn === undefined ? {} : { endColumn: input.endColumn }),
    ...(input.endLine === undefined ? {} : { endLine: input.endLine }),
    evidence,
    file,
    fingerprint,
    line: input.line,
    message: redactEvidence(input.message),
    remediation: input.metadata.remediation,
    ruleId: input.metadata.id,
    severity: input.metadata.severity,
    standards: input.metadata.standards,
    title: input.metadata.title,
  };
}

export function findingFingerprint(ruleId: string, file: string, evidence: string): string {
  const normalizedEvidence = evidence.replaceAll(/\s+/g, "");
  return createHash("sha256")
    .update(`${ruleId}\0${file}\0${normalizedEvidence}`)
    .digest("hex")
    .slice(0, 24);
}

export function summarize(findings: readonly Finding[]): ScanSummary {
  const counts: Record<Severity, number> = {
    critical: 0,
    high: 0,
    info: 0,
    low: 0,
    medium: 0,
  };

  for (const finding of findings) {
    counts[finding.severity] += 1;
  }

  return { ...counts, total: findings.length };
}

export function severityRank(severity: Severity): number {
  return SEVERITIES.indexOf(severity);
}

export function compareFindings(left: Finding, right: Finding): number {
  return (
    severityRank(right.severity) - severityRank(left.severity) ||
    compareCodeUnits(left.file, right.file) ||
    left.line - right.line ||
    left.column - right.column ||
    compareCodeUnits(left.ruleId, right.ruleId) ||
    compareCodeUnits(left.fingerprint, right.fingerprint)
  );
}
