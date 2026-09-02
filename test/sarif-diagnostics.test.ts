import { describe, expect, it } from "vitest";
import type { ScanReport } from "../src/domain.js";
import { formatSarif } from "../src/formatters/sarif.js";

interface SarifNotification {
  readonly level: "error" | "warning";
  readonly locations?: ReadonlyArray<{
    readonly physicalLocation: { readonly artifactLocation: { readonly uri: string } };
  }>;
  readonly message: { readonly text: string };
}

interface SarifInvocation {
  readonly executionSuccessful: boolean;
  readonly toolExecutionNotifications: readonly SarifNotification[];
}

describe("SARIF scan diagnostics", () => {
  it("preserves diagnostics as bounded, redacted execution notifications", () => {
    const credential = `ghp_${"a".repeat(32)}`;
    const report = emptyReport([
      {
        file: `api_key=${credential} ${"nested/".repeat(700)}server.ts`,
        message: `Unable to inspect api_key=${credential}: ${"x".repeat(1_200)}`,
        type: "error",
      },
      { message: "Invalid JSON", type: "warning" },
    ]);

    const invocation = invocationFrom(report);
    const error = invocation.toolExecutionNotifications[0];
    const warning = invocation.toolExecutionNotifications[1];
    const errorPath = error?.locations?.[0]?.physicalLocation.artifactLocation.uri;
    const decodedErrorPath = errorPath === undefined ? undefined : decodeURIComponent(errorPath);

    expect(invocation.executionSuccessful).toBe(false);
    expect(invocation.toolExecutionNotifications).toHaveLength(2);
    expect(error?.level).toBe("error");
    expect(error?.message.text.length).toBe(1_000);
    expect(error?.message.text.includes(credential)).toBe(false);
    expect(error?.message.text).toContain("<redacted>");
    expect(decodedErrorPath?.length).toBe(4_096);
    expect(decodedErrorPath?.includes(credential)).toBe(false);
    expect(decodedErrorPath).toContain("<redacted>");
    expect(warning).toEqual({ level: "warning", message: { text: "Invalid JSON" } });
  });

  it("marks an invocation successful when diagnostics contain no errors", () => {
    const invocation = invocationFrom(
      emptyReport([{ file: "config.json", message: "Invalid JSON", type: "warning" }]),
    );

    expect(invocation.executionSuccessful).toBe(true);
    expect(invocation.toolExecutionNotifications[0]?.locations?.[0]).toEqual({
      physicalLocation: { artifactLocation: { uri: "config.json" } },
    });
  });

  it("encodes reserved URI characters in finding and diagnostic artifact paths", () => {
    const file = "nested/name#part?query%value.ts";
    const finding = fixtureFinding(file);
    const report = {
      ...emptyReport([{ file, message: "warning", type: "warning" }]),
      findings: [finding],
      summary: { critical: 0, high: 0, info: 0, low: 1, medium: 0, total: 1 },
    } satisfies ScanReport;
    const serialized = JSON.parse(formatSarif(report)) as {
      readonly runs: ReadonlyArray<{
        readonly invocations: readonly SarifInvocation[];
        readonly results: ReadonlyArray<{
          readonly locations: ReadonlyArray<{
            readonly physicalLocation: { readonly artifactLocation: { readonly uri: string } };
          }>;
        }>;
      }>;
    };
    const run = serialized.runs[0];
    const findingUri = run?.results[0]?.locations[0]?.physicalLocation.artifactLocation.uri;
    const diagnosticUri =
      run?.invocations[0]?.toolExecutionNotifications[0]?.locations?.[0]?.physicalLocation
        .artifactLocation.uri;

    expect(findingUri).toBe("nested/name%23part%3Fquery%25value.ts");
    expect(diagnosticUri).toBe(findingUri);
  });
});

function fixtureFinding(file: string): ScanReport["findings"][number] {
  return {
    column: 1,
    confidence: "high",
    evidence: "evidence",
    file,
    fingerprint: "0".repeat(24),
    line: 1,
    message: "message",
    remediation: "remediation",
    ruleId: "MCP008",
    severity: "low",
    standards: { atlas: [], cwe: [], owasp: [] },
    title: "title",
  };
}

function invocationFrom(report: ScanReport): SarifInvocation {
  const serialized = JSON.parse(formatSarif(report)) as {
    readonly runs: ReadonlyArray<{ readonly invocations: readonly SarifInvocation[] }>;
  };
  const invocation = serialized.runs[0]?.invocations[0];
  if (invocation === undefined) {
    throw new Error("Expected one SARIF invocation.");
  }
  return invocation;
}

function emptyReport(diagnostics: ScanReport["diagnostics"]): ScanReport {
  return {
    diagnostics,
    findings: [],
    scan: {
      durationMs: 1,
      filesScanned: 0,
      filesSkipped: 0,
      generatedAt: "2026-08-31T00:00:00.000Z",
      id: "000000000000000000000000",
      target: ".",
    },
    scanner: { name: "Uleravo", version: "0.5.4" },
    schemaVersion: "1.0.0",
    summary: { critical: 0, high: 0, info: 0, low: 0, medium: 0, total: 0 },
  };
}
