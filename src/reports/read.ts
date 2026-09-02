import { readFile, stat } from "node:fs/promises";
import path from "node:path";
import type {
  Confidence,
  Diagnostic,
  Finding,
  LockfileProvenance,
  PackageProvenance,
  ScanProvenance,
  ScanReport,
  Severity,
  StandardsMapping,
} from "../domain.js";
import { CONFIDENCE_LEVELS, findingFingerprint, SEVERITIES, summarize } from "../domain.js";
import { redactEvidence } from "../redact.js";
import { normalizeRepositoryIdentity } from "../scanner/provenance.js";
import { PRODUCT_NAME } from "../version.js";

const MAX_REPORT_BYTES = 10_000_000;
const utf8Decoder = new TextDecoder("utf-8", { fatal: true });

export async function readScanReport(reportPath: string): Promise<ScanReport> {
  const resolved = path.resolve(reportPath);
  const metadata = await stat(resolved);
  if (!metadata.isFile()) {
    throw new Error(`${reportPath} is not a regular report file.`);
  }
  if (metadata.size > MAX_REPORT_BYTES) {
    throw new Error(`${reportPath} exceeds the 10000000-byte report limit.`);
  }

  const bytes = await readFile(resolved);
  if (bytes.byteLength > MAX_REPORT_BYTES) {
    throw new Error(`${reportPath} exceeds the 10000000-byte report limit.`);
  }
  let serialized: string;
  try {
    serialized = utf8Decoder.decode(bytes);
  } catch {
    throw new Error(`${reportPath} is not valid UTF-8.`);
  }
  return parseScanReport(serialized, reportPath);
}

export function parseScanReport(serialized: string, label = "report"): ScanReport {
  let value: unknown;
  try {
    value = JSON.parse(serialized) as unknown;
  } catch {
    throw new Error(`${label} is not valid JSON.`);
  }
  if (!isObject(value) || value.schemaVersion !== "1.0.0") {
    throw new Error(`${label} is not a ${PRODUCT_NAME} report with schemaVersion 1.0.0.`);
  }

  const scanner = parseScanner(value.scanner);
  const scan = parseScanMetadata(value.scan);
  if (scanner === undefined || scan === undefined) {
    throw new Error(`${label} has invalid scanner or scan metadata.`);
  }

  const findings = parseFindings(value.findings);
  if (findings === undefined) {
    throw new Error(`${label} has invalid findings.`);
  }
  const diagnostics = parseDiagnostics(value.diagnostics);
  if (diagnostics === undefined) {
    throw new Error(`${label} has invalid diagnostics.`);
  }
  const summary = summarize(findings);
  if (!matchesSummary(value.summary, summary)) {
    throw new Error(`${label} has an invalid summary.`);
  }

  const provenance = value.provenance === undefined ? undefined : parseProvenance(value.provenance);
  if (value.provenance !== undefined && provenance === undefined) {
    throw new Error(`${label} has invalid provenance.`);
  }

  return {
    diagnostics,
    findings,
    ...(provenance === undefined ? {} : { provenance }),
    scan,
    scanner,
    schemaVersion: "1.0.0",
    summary,
  };
}

function parseScanner(value: unknown): ScanReport["scanner"] | undefined {
  if (!isObject(value) || !nonEmptyString(value.name) || !nonEmptyString(value.version)) {
    return undefined;
  }
  return { name: redactEvidence(value.name), version: redactEvidence(value.version) };
}

function parseScanMetadata(value: unknown): ScanReport["scan"] | undefined {
  if (
    !isObject(value) ||
    !nonNegativeInteger(value.durationMs) ||
    !nonNegativeInteger(value.filesScanned) ||
    !nonNegativeInteger(value.filesSkipped) ||
    typeof value.generatedAt !== "string" ||
    !validIsoTimestamp(value.generatedAt) ||
    typeof value.id !== "string" ||
    !/^[a-f0-9]{24}$/.test(value.id) ||
    !nonEmptyString(value.target)
  ) {
    return undefined;
  }
  return {
    durationMs: value.durationMs,
    filesScanned: value.filesScanned,
    filesSkipped: value.filesSkipped,
    generatedAt: value.generatedAt,
    id: value.id,
    target: redactEvidence(value.target),
  };
}

function parseFindings(value: unknown): Finding[] | undefined {
  if (!Array.isArray(value)) {
    return undefined;
  }
  const findings: Finding[] = [];
  for (const candidate of value) {
    const finding = parseFinding(candidate);
    if (finding === undefined) {
      return undefined;
    }
    findings.push(finding);
  }
  return findings;
}

function parseFinding(value: unknown): Finding | undefined {
  if (
    !isObject(value) ||
    !positiveInteger(value.column) ||
    (value.endColumn !== undefined && !positiveInteger(value.endColumn)) ||
    (value.endLine !== undefined && !positiveInteger(value.endLine)) ||
    !isConfidence(value.confidence) ||
    typeof value.evidence !== "string" ||
    !relativeArtifactPath(value.file) ||
    typeof value.fingerprint !== "string" ||
    !/^[a-f0-9]{24}$/.test(value.fingerprint) ||
    !positiveInteger(value.line) ||
    !nonEmptyString(value.message) ||
    !nonEmptyString(value.remediation) ||
    typeof value.ruleId !== "string" ||
    !/^MCP[0-9]{3}$/.test(value.ruleId) ||
    !isSeverity(value.severity) ||
    !nonEmptyString(value.title)
  ) {
    return undefined;
  }
  const standards = parseStandards(value.standards);
  if (standards === undefined) {
    return undefined;
  }
  if (value.fingerprint !== findingFingerprint(value.ruleId, value.file, value.evidence)) {
    return undefined;
  }
  const evidence = redactEvidence(value.evidence);
  const file = redactEvidence(value.file);

  return {
    column: value.column,
    confidence: value.confidence,
    ...(value.endColumn === undefined ? {} : { endColumn: value.endColumn }),
    ...(value.endLine === undefined ? {} : { endLine: value.endLine }),
    evidence,
    file,
    fingerprint: findingFingerprint(value.ruleId, file, evidence),
    line: value.line,
    message: redactEvidence(value.message),
    remediation: redactEvidence(value.remediation),
    ruleId: value.ruleId,
    severity: value.severity,
    standards,
    title: redactEvidence(value.title),
  };
}

function parseStandards(value: unknown): StandardsMapping | undefined {
  if (!isObject(value)) {
    return undefined;
  }
  const atlas = stringArray(value.atlas);
  const cwe = stringArray(value.cwe);
  const owasp = stringArray(value.owasp);
  if (atlas === undefined || cwe === undefined || owasp === undefined) {
    return undefined;
  }
  return { atlas, cwe, owasp };
}

function parseDiagnostics(value: unknown): Diagnostic[] | undefined {
  if (!Array.isArray(value)) {
    return undefined;
  }
  const diagnostics: Diagnostic[] = [];
  for (const candidate of value) {
    if (
      !isObject(candidate) ||
      !nonEmptyString(candidate.message) ||
      (candidate.type !== "error" && candidate.type !== "warning") ||
      (candidate.file !== undefined && !relativeArtifactPath(candidate.file))
    ) {
      return undefined;
    }
    diagnostics.push({
      ...(candidate.file === undefined ? {} : { file: redactEvidence(candidate.file) }),
      message: redactEvidence(candidate.message),
      type: candidate.type,
    });
  }
  return diagnostics;
}

function parseProvenance(value: unknown): ScanProvenance | undefined {
  if (
    !isObject(value) ||
    typeof value.scanInputSha256 !== "string" ||
    !/^[a-f0-9]{64}$/.test(value.scanInputSha256) ||
    !Array.isArray(value.lockfiles)
  ) {
    return undefined;
  }
  const lockfiles: LockfileProvenance[] = [];
  for (const candidate of value.lockfiles) {
    const lockfile = parseLockfile(candidate);
    if (lockfile === undefined) {
      return undefined;
    }
    lockfiles.push(lockfile);
  }

  const packageMetadata =
    value.package === undefined ? undefined : parsePackageProvenance(value.package);
  if (value.package !== undefined && packageMetadata === undefined) {
    return undefined;
  }

  const repository =
    value.repository === undefined ? undefined : parseRepositoryProvenance(value.repository);
  if (value.repository !== undefined && repository === undefined) {
    return undefined;
  }

  return {
    lockfiles,
    ...(packageMetadata === undefined ? {} : { package: packageMetadata }),
    ...(repository === undefined ? {} : { repository }),
    scanInputSha256: value.scanInputSha256,
  };
}

function parseRepositoryProvenance(value: unknown): ScanProvenance["repository"] {
  if (!isObject(value) || typeof value.commit !== "string" || typeof value.url !== "string") {
    return undefined;
  }
  try {
    return normalizeRepositoryIdentity({ commit: value.commit, url: value.url });
  } catch {
    return undefined;
  }
}

function parseLockfile(value: unknown): LockfileProvenance | undefined {
  if (!isObject(value) || !relativeArtifactPath(value.path)) {
    return undefined;
  }
  if (value.state === "size-limit" && value.sha256 === undefined) {
    return { path: redactEvidence(value.path), state: "size-limit" };
  }
  if (
    value.state === "hashed" &&
    typeof value.sha256 === "string" &&
    /^[a-f0-9]{64}$/.test(value.sha256)
  ) {
    return { path: redactEvidence(value.path), sha256: value.sha256, state: "hashed" };
  }
  return undefined;
}

function parsePackageProvenance(value: unknown): PackageProvenance | undefined {
  if (!isObject(value)) {
    return undefined;
  }
  const name = value.name === undefined ? undefined : nonEmptyStringValue(value.name);
  const version = value.version === undefined ? undefined : nonEmptyStringValue(value.version);
  if (
    (value.name !== undefined && name === undefined) ||
    (value.version !== undefined && version === undefined) ||
    (name === undefined && version === undefined)
  ) {
    return undefined;
  }
  return {
    ...(name === undefined ? {} : { name: redactEvidence(name) }),
    ...(version === undefined ? {} : { version: redactEvidence(version) }),
  };
}

function matchesSummary(value: unknown, expected: ScanReport["summary"]): boolean {
  if (!isObject(value)) {
    return false;
  }
  return (Object.keys(expected) as Array<keyof typeof expected>).every(
    (key) => nonNegativeInteger(value[key]) && value[key] === expected[key],
  );
}

function stringArray(value: unknown): readonly string[] | undefined {
  if (!Array.isArray(value) || !value.every(nonEmptyString)) {
    return undefined;
  }
  const sanitized = value.map((item) => redactEvidence(item));
  return new Set(sanitized).size === sanitized.length ? sanitized : undefined;
}

function relativeArtifactPath(value: unknown): value is string {
  if (!nonEmptyString(value) || path.posix.isAbsolute(value) || /^[A-Za-z]:[\\/]/.test(value)) {
    return false;
  }
  return value
    .split("/")
    .every((segment) => segment.length > 0 && segment !== "." && segment !== "..");
}

function validIsoTimestamp(value: string): boolean {
  const timestamp = Date.parse(value);
  return Number.isFinite(timestamp) && new Date(timestamp).toISOString() === value;
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function nonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.length > 0;
}

function nonEmptyStringValue(value: unknown): string | undefined {
  return nonEmptyString(value) ? value : undefined;
}

function nonNegativeInteger(value: unknown): value is number {
  return typeof value === "number" && Number.isInteger(value) && value >= 0;
}

function positiveInteger(value: unknown): value is number {
  return typeof value === "number" && Number.isInteger(value) && value >= 1;
}

function isSeverity(value: unknown): value is Severity {
  return typeof value === "string" && (SEVERITIES as readonly string[]).includes(value);
}

function isConfidence(value: unknown): value is Confidence {
  return typeof value === "string" && (CONFIDENCE_LEVELS as readonly string[]).includes(value);
}
