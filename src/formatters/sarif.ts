import type { Confidence, Diagnostic, Finding, ScanReport, Severity } from "../domain.js";
import { redactEvidence } from "../redact.js";
import { RULE_CATALOG } from "../rules/catalog.js";
import { PRODUCT_URL } from "../version.js";

const MAX_NOTIFICATION_MESSAGE_LENGTH = 1_000;
const MAX_NOTIFICATION_PATH_LENGTH = 4_096;

export function formatSarif(report: ScanReport): string {
  const usedRules = new Set(report.findings.map((finding) => finding.ruleId));
  const sarif = {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    runs: [
      {
        invocations: [
          {
            executionSuccessful: !report.diagnostics.some(
              (diagnostic) => diagnostic.type === "error",
            ),
            toolExecutionNotifications: report.diagnostics.map(toNotification),
          },
        ],
        properties: {
          ...(report.provenance === undefined ? {} : { provenance: report.provenance }),
          scanId: report.scan.id,
        },
        results: report.findings.map(toResult),
        tool: {
          driver: {
            informationUri: PRODUCT_URL,
            name: report.scanner.name,
            rules: RULE_CATALOG.filter((rule) => usedRules.has(rule.id)).map((rule) => ({
              defaultConfiguration: { level: sarifLevel(rule.severity) },
              fullDescription: { text: rule.description },
              help: { text: rule.remediation },
              id: rule.id,
              name: rule.title,
              properties: {
                confidence: rule.confidence,
                precision: sarifPrecision(rule.confidence),
                "security-severity": securitySeverity(rule.severity),
                standards: rule.standards,
                tags: ["security"],
              },
              shortDescription: { text: rule.title },
            })),
            semanticVersion: report.scanner.version,
          },
        },
      },
    ],
    version: "2.1.0",
  };
  return `${JSON.stringify(sarif, null, 2)}\n`;
}

function toNotification(diagnostic: Diagnostic): object {
  return {
    level: diagnostic.type,
    ...(diagnostic.file === undefined
      ? {}
      : {
          locations: [
            {
              physicalLocation: {
                artifactLocation: {
                  uri: artifactUri(boundedRedacted(diagnostic.file, MAX_NOTIFICATION_PATH_LENGTH)),
                },
              },
            },
          ],
        }),
    message: {
      text: boundedRedacted(diagnostic.message, MAX_NOTIFICATION_MESSAGE_LENGTH),
    },
  };
}

function boundedRedacted(value: string, maximumLength: number): string {
  const redacted = redactEvidence(value);
  if (redacted.length <= maximumLength) {
    return redacted;
  }
  return `${redacted.slice(0, maximumLength - 3)}...`;
}

function toResult(finding: Finding): object {
  return {
    level: sarifLevel(finding.severity),
    locations: [
      {
        physicalLocation: {
          artifactLocation: { uri: artifactUri(finding.file) },
          region: {
            endColumn: finding.endColumn ?? finding.column,
            endLine: finding.endLine ?? finding.line,
            startColumn: finding.column,
            startLine: finding.line,
          },
        },
      },
    ],
    message: { text: finding.message },
    partialFingerprints: { primaryLocationLineHash: finding.fingerprint },
    properties: {
      confidence: finding.confidence,
      evidence: finding.evidence,
      remediation: finding.remediation,
      standards: finding.standards,
    },
    ruleId: finding.ruleId,
  };
}

function artifactUri(relativePath: string): string {
  return relativePath
    .split("/")
    .map((segment) => encodeURIComponent(segment.toWellFormed()))
    .join("/");
}

function sarifLevel(severity: Severity): "error" | "note" | "warning" {
  if (severity === "critical" || severity === "high") {
    return "error";
  }
  if (severity === "medium") {
    return "warning";
  }
  return "note";
}

function sarifPrecision(confidence: Confidence): "high" | "low" | "medium" {
  return confidence;
}

function securitySeverity(severity: Severity): "0.0" | "1.0" | "4.0" | "7.0" | "9.0" {
  switch (severity) {
    case "critical":
      return "9.0";
    case "high":
      return "7.0";
    case "medium":
      return "4.0";
    case "low":
      return "1.0";
    case "info":
      return "0.0";
  }
}
