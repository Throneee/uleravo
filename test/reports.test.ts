import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import { findingFingerprint } from "../src/domain.js";
import { formatJson } from "../src/formatters/json.js";
import { parseScanReport, readScanReport } from "../src/reports/read.js";
import { scan } from "../src/scanner/scan.js";
import { VERSION } from "../src/version.js";

const fixture = path.join(fileURLToPath(new URL("./fixtures/safe-server", import.meta.url)));
const vulnerableFixture = path.join(
  fileURLToPath(new URL("./fixtures/vulnerable-server", import.meta.url)),
);
const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryDirectories
      .splice(0)
      .map((directory) => rm(directory, { force: true, recursive: true })),
  );
});

describe("report input", () => {
  it("parses and reads a generated report", async () => {
    const report = await scan(fixture);
    const serialized = formatJson(report);
    const directory = await makeTemporaryDirectory();
    const reportPath = path.join(directory, "report.json");
    await writeFile(reportPath, serialized);

    expect(parseScanReport(serialized)).toEqual(report);
    expect(await readScanReport(reportPath)).toEqual(report);
  });

  it("rejects malformed JSON and report-shaped data with invalid findings", () => {
    expect(() => parseScanReport("{", "baseline")).toThrow("baseline is not valid JSON");
    expect(() => parseScanReport(JSON.stringify({ schemaVersion: "2.0.0" }))).toThrow(
      "schemaVersion 1.0.0",
    );

    const invalid = {
      diagnostics: [],
      findings: [{ fingerprint: "wrong" }],
      scan: {
        durationMs: 0,
        filesScanned: 0,
        filesSkipped: 0,
        generatedAt: "2026-08-30T00:00:00.000Z",
        id: "a".repeat(24),
        target: "fixture",
      },
      scanner: { name: "Uleravo", version: VERSION },
      schemaVersion: "1.0.0",
      summary: {},
    };
    expect(() => parseScanReport(JSON.stringify(invalid))).toThrow("invalid findings");
  });

  it("rejects a well-shaped finding whose stored fingerprint does not match", async () => {
    const report = await scan(vulnerableFixture);
    const serialized = JSON.parse(formatJson(report)) as {
      findings: Array<{ fingerprint: string }>;
    };
    const first = serialized.findings[0];
    if (first === undefined) {
      throw new Error("Expected the vulnerable fixture to produce a finding.");
    }
    first.fingerprint = first.fingerprint === "a".repeat(24) ? "b".repeat(24) : "a".repeat(24);

    expect(() => parseScanReport(JSON.stringify(serialized))).toThrow("invalid findings");
  });

  it("rejects non-UTF-8 report input", async () => {
    const directory = await makeTemporaryDirectory();
    const reportPath = path.join(directory, "report.json");
    await writeFile(reportPath, new Uint8Array([255, 254, 253]));

    await expect(readScanReport(reportPath)).rejects.toThrow("not valid UTF-8");
  });

  it("redacts untrusted finding text and strips unknown report fields", async () => {
    const report = await scan(vulnerableFixture);
    const serialized = JSON.parse(formatJson(report)) as {
      findings: Array<Record<string, unknown>>;
      unexpected?: string;
    };
    const credential = ["ghp_", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"].join("");
    const first = serialized.findings[0];
    if (first === undefined) {
      throw new Error("Expected the vulnerable fixture to produce a finding.");
    }
    first.message = `token=${credential}`;
    first.unexpected = credential;
    serialized.unexpected = credential;

    const parsed = parseScanReport(JSON.stringify(serialized));

    expect(parsed.findings[0]?.message).toContain("<redacted>");
    expect(parsed.findings[0]?.message.includes(credential)).toBe(false);
    expect(Object.hasOwn(parsed.findings[0] ?? {}, "unexpected")).toBe(false);
    expect(Object.hasOwn(parsed, "unexpected")).toBe(false);
    expect(parseScanReport(formatJson(parsed))).toEqual(parsed);
  });

  it("rejects standards entries that become duplicates after redaction", async () => {
    const report = await scan(vulnerableFixture);
    const serialized = JSON.parse(formatJson(report)) as {
      findings: Array<{ standards: { atlas: string[] } }>;
    };
    const first = serialized.findings[0];
    if (first === undefined) {
      throw new Error("Expected the vulnerable fixture to produce a finding.");
    }
    first.standards.atlas = [["ghp_", "A".repeat(36)].join(""), ["ghp_", "B".repeat(36)].join("")];

    expect(() => parseScanReport(JSON.stringify(serialized))).toThrow("invalid findings");
  });

  it("treats a leading backslash as portable report data rather than a host path", async () => {
    const report = await scan(vulnerableFixture);
    const serialized = JSON.parse(formatJson(report)) as {
      findings: Array<Record<string, unknown>>;
    };
    const first = serialized.findings[0];
    if (
      first === undefined ||
      typeof first.ruleId !== "string" ||
      typeof first.evidence !== "string"
    ) {
      throw new Error("Expected the vulnerable fixture to produce a finding.");
    }
    const literalBackslashFile = "\\server.ts";
    first.file = literalBackslashFile;
    first.fingerprint = findingFingerprint(first.ruleId, literalBackslashFile, first.evidence);

    const parsed = parseScanReport(JSON.stringify(serialized));

    expect(parsed.findings[0]?.file).toBe("\\server.ts");
  });

  it("rejects repository provenance that embeds credentials", async () => {
    const report = await scan(fixture);
    const serialized = JSON.parse(formatJson(report)) as {
      provenance: Record<string, unknown>;
    };
    serialized.provenance.repository = {
      commit: "a".repeat(40),
      url: "https://embedded@example.com/project",
    };

    expect(() => parseScanReport(JSON.stringify(serialized))).toThrow("invalid provenance");
  });
});

async function makeTemporaryDirectory(): Promise<string> {
  const directory = await mkdtemp(path.join(tmpdir(), "uleravo-report-"));
  temporaryDirectories.push(directory);
  return directory;
}
