import { access, readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { formatJson } from "../src/formatters/json.js";
import { readScanReport } from "../src/reports/read.js";
import { scan } from "../src/scanner/scan.js";
import {
  ARTIFACT_ANALYZER_VERSION,
  HARNESS_ANALYZER_VERSION,
  MCP_ANALYZER_VERSION,
  PACKAGE_VERSION,
  PRODUCT_NAME,
  PRODUCT_SLUG,
  PRODUCT_URL,
  VERSION,
} from "../src/version.js";

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

describe("release metadata", () => {
  it("aligns the private candidate package while preserving existing analyzer identities", async () => {
    const packageMetadata = JSON.parse(
      await readFile(path.join(repositoryRoot, "package.json"), "utf8"),
    ) as {
      bin?: Record<string, string>;
      bugs?: { url?: string };
      homepage?: string;
      license?: string;
      name?: string;
      private?: boolean;
      repository?: { url?: string };
      version?: string;
    };
    const [actionMetadata, actionBundle, observationWorkflow] = await Promise.all([
      readFile(path.join(repositoryRoot, "action.yml"), "utf8"),
      readFile(path.join(repositoryRoot, "action/dist/index.cjs"), "utf8"),
      readFile(path.join(repositoryRoot, "examples/github-actions/uleravo-observe.yml"), "utf8"),
    ]);

    expect(PRODUCT_NAME).toBe("Uleravo");
    expect(PRODUCT_SLUG).toBe("uleravo");
    expect(PRODUCT_URL).toBe("https://github.com/Throneee/uleravo");
    expect(VERSION).toBe("0.8.0-rc.1");
    expect(PACKAGE_VERSION).toBe(VERSION);
    expect(ARTIFACT_ANALYZER_VERSION).toBe("0.7.0");
    expect(HARNESS_ANALYZER_VERSION).toBe("0.7.0");
    expect(packageMetadata.name).toBe(PRODUCT_SLUG);
    expect(packageMetadata.version).toBe(VERSION);
    expect(packageMetadata.private).toBe(true);
    expect(packageMetadata.license).toBe("Apache-2.0");
    expect(packageMetadata.bin).toEqual({ [PRODUCT_SLUG]: "./dist/cli.js" });
    expect(packageMetadata.repository?.url).toBe(`${PRODUCT_URL}.git`);
    expect(packageMetadata.homepage).toBe(`${PRODUCT_URL}#readme`);
    expect(packageMetadata.bugs?.url).toBe(`${PRODUCT_URL}/issues`);
    expect(actionMetadata).toContain(`name: ${PRODUCT_NAME} MCP security scan`);
    expect(actionMetadata).toContain(`author: ${PRODUCT_NAME}`);
    expect(actionMetadata).toMatch(/\n {2}fail-on:\n(?: {4}.*\n)*? {4}default: none\n/);
    expect(actionMetadata).toContain(`    default: ${PRODUCT_SLUG}.json`);
    expect(actionMetadata).toContain(`    default: ${PRODUCT_SLUG}.sarif`);
    expect(actionMetadata).toMatch(
      /\n {2}has-findings:\n {4}description: Whether the report contains one or more findings;/,
    );
    expect(actionBundle).toContain("Licensed under the Apache License, Version 2.0.");
    expect(actionBundle).toContain("See LICENSE and THIRD_PARTY_NOTICES");
    expect(observationWorkflow).toMatch(
      /uses: (?:OWNER\/REPOSITORY@PUBLIC_COMMIT_A|Throneee\/uleravo@[0-9a-f]{40})/,
    );

    await Promise.all([
      access(path.join(repositoryRoot, "LICENSE")),
      access(path.join(repositoryRoot, "THIRD_PARTY_NOTICES")),
    ]);
  });

  it("ships a parseable redacted first-result example", async () => {
    const sampleTarget = path.join(repositoryRoot, "examples", "reports", "sample-target");
    const report = await readScanReport(
      path.join(repositoryRoot, "examples", "reports", "uleravo.sample.json"),
    );
    const regenerated = await scan(sampleTarget);

    expect(report.scanner).toEqual({ name: PRODUCT_NAME, version: MCP_ANALYZER_VERSION });
    expect(report.findings).toHaveLength(3);
    expect(report.summary).toMatchObject({ critical: 1, high: 2, total: 3 });
    expect(report.findings.find((finding) => finding.ruleId === "MCP007")?.evidence).toContain(
      "<redacted>",
    );
    expect(report.findings).toEqual(regenerated.findings);
    expect(report.provenance).toEqual(regenerated.provenance);
    expect(report.scan).toMatchObject({
      filesScanned: regenerated.scan.filesScanned,
      filesSkipped: regenerated.scan.filesSkipped,
      id: regenerated.scan.id,
      target: regenerated.scan.target,
    });
    expect(MCP_ANALYZER_VERSION).toBe("0.6.3");
    expect(regenerated.scanner.version).toBe(MCP_ANALYZER_VERSION);
    expect(regenerated.scan.id).toBe("0d9da546d979ba36e7931f89");
    expect(
      formatJson({
        ...regenerated,
        scan: {
          ...regenerated.scan,
          durationMs: report.scan.durationMs,
          generatedAt: report.scan.generatedAt,
        },
      }),
    ).toBe(formatJson(report));
  });
});
