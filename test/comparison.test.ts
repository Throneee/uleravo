import { describe, expect, it } from "vitest";
import { compareReports } from "../src/comparison.js";
import { createFinding, type Finding, type ScanReport } from "../src/domain.js";
import { formatComparisonJson, formatComparisonText } from "../src/formatters/comparison.js";
import { RULES } from "../src/rules/catalog.js";
import { VERSION } from "../src/version.js";

describe("report comparison", () => {
  it("classifies added, resolved, and unchanged findings deterministically", () => {
    const sharedBefore = finding("http://shared.example.com", RULES.insecureTransport, 2);
    const sharedAfter = finding("http://shared.example.com", RULES.insecureTransport, 20);
    const resolved = finding("exec(command)", RULES.commandInjection, 3);
    const added = finding("eval(code)", RULES.dynamicCode, 4);
    const baseline = report("a".repeat(24), [sharedBefore, resolved]);
    const current = report("b".repeat(24), [added, sharedAfter]);

    const comparison = compareReports(baseline, current);

    expect(comparison.summary).toEqual({ added: 1, resolved: 1, unchanged: 1 });
    expect(comparison.added.map((item) => item.fingerprint)).toEqual([added.fingerprint]);
    expect(comparison.resolved.map((item) => item.fingerprint)).toEqual([resolved.fingerprint]);
    expect(comparison.unchanged.map((item) => item.line)).toEqual([20]);
    expect(formatComparisonJson(comparison)).toBe(
      formatComparisonJson(compareReports(baseline, current)),
    );
    expect(formatComparisonText(comparison)).toContain("1 added · 1 resolved · 1 unchanged");
  });

  it("compares duplicate fingerprints as a multiset instead of dropping evidence", () => {
    const duplicate = finding("exec(command)", RULES.commandInjection, 3);
    const comparison = compareReports(
      report("a".repeat(24), [duplicate, { ...duplicate, line: 8 }]),
      report("b".repeat(24), [duplicate]),
    );

    expect(comparison.summary).toEqual({ added: 0, resolved: 1, unchanged: 1 });
    expect(comparison.resolved[0]?.line).toBe(8);
  });

  it("carries source and repository identities into comparison references", () => {
    const baseline = report("a".repeat(24), []);
    const current = {
      ...report("b".repeat(24), []),
      provenance: {
        lockfiles: [],
        repository: {
          commit: "c".repeat(40),
          url: "https://github.com/example/project",
        },
        scanInputSha256: "d".repeat(64),
      },
    } satisfies ScanReport;

    expect(compareReports(baseline, current).current).toEqual({
      repository: current.provenance.repository,
      scanId: "b".repeat(24),
      scanInputSha256: "d".repeat(64),
      scannerVersion: VERSION,
    });
  });
});

function finding(
  evidence: string,
  metadata: Parameters<typeof createFinding>[0]["metadata"],
  line: number,
): Finding {
  return createFinding({
    column: 1,
    evidence,
    file: "server.ts",
    line,
    message: "unsafe",
    metadata,
  });
}

function report(id: string, findings: readonly Finding[]): ScanReport {
  return {
    diagnostics: [],
    findings,
    scan: {
      durationMs: 1,
      filesScanned: 1,
      filesSkipped: 0,
      generatedAt: "2026-08-30T00:00:00.000Z",
      id,
      target: "fixture",
    },
    scanner: { name: "Uleravo", version: VERSION },
    schemaVersion: "1.0.0",
    summary: {
      critical: 0,
      high: 0,
      info: 0,
      low: 0,
      medium: 0,
      total: findings.length,
    },
  };
}
