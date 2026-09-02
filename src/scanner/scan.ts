import { createHash } from "node:crypto";
import path from "node:path";
import { performance } from "node:perf_hooks";
import ts from "typescript";
import type { Diagnostic, Finding, FindingInput, ScanReport } from "../domain.js";
import { compareFindings, createFinding, summarize } from "../domain.js";
import { compareCodeUnits } from "../order.js";
import { redactEvidence } from "../redact.js";
import { astImportSecurityRule, astSecurityRule, toolMetadataRule } from "../rules/ast.js";
import { unpinnedPackageRule } from "../rules/packages.js";
import { pythonSecurityRule } from "../rules/python.js";
import { hardcodedSecretRule } from "../rules/secrets.js";
import type { ScannerRule } from "../rules/types.js";
import { credentialInUrlRule, insecureTransportRule } from "../rules/urls.js";
import { PRODUCT_NAME, VERSION } from "../version.js";
import { type DiscoveryOptions, discoverFiles, type ScannableFile } from "./files.js";
import { createProvenance, type RepositoryIdentity } from "./provenance.js";

const DEFAULT_RULES: readonly ScannerRule[] = [
  astSecurityRule,
  astImportSecurityRule,
  pythonSecurityRule,
  toolMetadataRule,
  hardcodedSecretRule,
  insecureTransportRule,
  credentialInUrlRule,
  unpinnedPackageRule,
];

// Thousands of findings already require bulk remediation rather than line-by-line triage. This
// leaves substantial headroom for large repositories while bounding raw, pre-deduplication state.
const MAX_RAW_FINDINGS = 5_000;
const FINDING_LIMIT_MESSAGE = `Finding limit exceeded (${MAX_RAW_FINDINGS.toString()} raw findings retained); scan evidence is incomplete.`;

export interface ScanOptions extends DiscoveryOptions {
  readonly repository?: RepositoryIdentity;
  readonly rules?: readonly ScannerRule[];
}

export async function scan(target: string, options: ScanOptions = {}): Promise<ScanReport> {
  const startedAt = new Date();
  const started = performance.now();
  const discovery = await discoverFiles(target, options);
  const rules = options.rules ?? DEFAULT_RULES;
  const diagnostics: Diagnostic[] = [...discovery.diagnostics];
  const findings: Finding[] = [];
  if (discovery.files.length === 0) {
    diagnostics.push({
      message: "No scannable UTF-8 source or configuration files were found.",
      type: "error",
    });
  }

  let findingLimitExceeded = false;
  let filesAnalyzed = 0;
  for (const file of discovery.files) {
    if (file.kind === "json") {
      validateJson(file.relativePath, file.text, diagnostics);
    }
    const hasLockfile = hasApplicableLockfile(
      file.relativePath,
      discovery.lockfiles.map((lockfile) => lockfile.path),
    );
    if (!runFileRules(file, hasLockfile, rules, findings, diagnostics)) {
      findingLimitExceeded = true;
      break;
    }
    filesAnalyzed += 1;
  }

  if (!findingLimitExceeded) {
    runRepositoryRules(discovery.files, rules, findings, diagnostics);
  }

  const uniqueFindings = deduplicateFindings(findings);
  const unanalyzedFiles = findingLimitExceeded ? discovery.files.length - filesAnalyzed : 0;
  uniqueFindings.sort(compareFindings);
  const sanitizedDiagnostics = diagnostics.map((diagnostic) => ({
    ...diagnostic,
    ...(diagnostic.file === undefined ? {} : { file: redactEvidence(diagnostic.file) }),
    message: redactEvidence(diagnostic.message),
  }));
  const scanId = createHash("sha256")
    .update(VERSION)
    .update("\0")
    .update(discovery.contentHash)
    .update("\0")
    .update(
      JSON.stringify(
        discovery.lockfiles
          .map((lockfile) => [lockfile.path, lockfile.state, lockfile.sha256 ?? null] as const)
          .sort((left, right) => compareCodeUnits(left[0], right[0])),
      ),
    )
    .update("\0")
    .update(
      JSON.stringify(
        [...sanitizedDiagnostics].sort((left, right) =>
          compareCodeUnits(
            `${left.file ?? ""}\0${left.type}\0${left.message}`,
            `${right.file ?? ""}\0${right.type}\0${right.message}`,
          ),
        ),
      ),
    )
    .update("\0")
    .update(rules.map((rule) => rule.metadata.id).join(","))
    .digest("hex")
    .slice(0, 24);

  return {
    diagnostics: sanitizedDiagnostics,
    findings: uniqueFindings,
    provenance: createProvenance(discovery, options.repository),
    scan: {
      durationMs: Math.max(0, Math.round(performance.now() - started)),
      filesScanned: discovery.files.length - unanalyzedFiles,
      filesSkipped: discovery.skipped + unanalyzedFiles,
      generatedAt: startedAt.toISOString(),
      id: scanId,
      target: redactEvidence(discovery.target),
    },
    scanner: {
      name: PRODUCT_NAME,
      version: VERSION,
    },
    schemaVersion: "1.0.0",
    summary: summarize(uniqueFindings),
  };
}

function runFileRules(
  file: ScannableFile,
  hasLockfile: boolean,
  rules: readonly ScannerRule[],
  findings: Finding[],
  diagnostics: Diagnostic[],
): boolean {
  for (const rule of rules) {
    if (!("scan" in rule)) {
      continue;
    }
    try {
      for (const input of rule.scan({ file, hasLockfile })) {
        if (!retainFinding(input, findings, diagnostics)) {
          return false;
        }
      }
    } catch (error) {
      diagnostics.push({
        file: file.relativePath,
        message: `Rule ${rule.metadata.id} failed safely: ${errorMessage(error)}`,
        type: "error",
      });
    }
  }
  return true;
}

function runRepositoryRules(
  files: readonly ScannableFile[],
  rules: readonly ScannerRule[],
  findings: Finding[],
  diagnostics: Diagnostic[],
): void {
  for (const rule of rules) {
    if (!("scanRepository" in rule)) {
      continue;
    }
    try {
      for (const input of rule.scanRepository({ files })) {
        if (!retainFinding(input, findings, diagnostics)) {
          return;
        }
      }
    } catch (error) {
      diagnostics.push({
        message: `Rule ${rule.metadata.id} failed safely: ${errorMessage(error)}`,
        type: "error",
      });
    }
  }
}

function retainFinding(
  input: FindingInput,
  findings: Finding[],
  diagnostics: Diagnostic[],
): boolean {
  if (findings.length >= MAX_RAW_FINDINGS) {
    diagnostics.push({ message: FINDING_LIMIT_MESSAGE, type: "error" });
    return false;
  }
  findings.push(createFinding(input));
  return true;
}

function deduplicateFindings(findings: readonly Finding[]): Finding[] {
  const seen = new Set<string>();
  return findings.filter((finding) => {
    const key = `${finding.ruleId}\0${finding.file}\0${finding.line.toString()}\0${finding.column.toString()}`;
    if (seen.has(key)) {
      return false;
    }
    seen.add(key);
    return true;
  });
}

function hasApplicableLockfile(relativePath: string, lockfilePaths: readonly string[]): boolean {
  const fileDirectory = path.posix.dirname(relativePath);
  return lockfilePaths.some((lockfilePath) => {
    const lockfileDirectory = path.posix.dirname(lockfilePath);
    return (
      lockfileDirectory === "." ||
      fileDirectory === lockfileDirectory ||
      fileDirectory.startsWith(`${lockfileDirectory}/`)
    );
  });
}

function validateJson(relativePath: string, text: string, diagnostics: Diagnostic[]): void {
  if (isJsonWithComments(relativePath)) {
    const parsed = ts.parseConfigFileTextToJson(relativePath, text);
    if (parsed.error !== undefined) {
      diagnostics.push({
        file: relativePath,
        message: `Invalid JSONC: ${ts.flattenDiagnosticMessageText(parsed.error.messageText, "\n")}`,
        type: "warning",
      });
    }
    return;
  }
  try {
    JSON.parse(text);
  } catch (error) {
    diagnostics.push({
      file: relativePath,
      message: `Invalid JSON: ${errorMessage(error)}`,
      type: "warning",
    });
  }
}

function isJsonWithComments(relativePath: string): boolean {
  const normalized = relativePath.toLowerCase();
  const basename = normalized.split("/").at(-1) ?? "";
  return (
    normalized.startsWith(".vscode/") ||
    normalized.includes("/.vscode/") ||
    /^(?:js|ts)config(?:\.[^.]+)*\.json$/.test(basename)
  );
}

function errorMessage(error: unknown): string {
  return redactEvidence(error instanceof Error ? error.message : String(error));
}
