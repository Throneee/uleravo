import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { formatJson } from "../src/formatters/json.js";
import { formatSarif } from "../src/formatters/sarif.js";
import { formatText } from "../src/formatters/text.js";
import { RULES } from "../src/rules/catalog.js";
import { scan } from "../src/scanner/scan.js";
import { PRODUCT_URL } from "../src/version.js";

const vulnerableFixture = path.join(
  fileURLToPath(new URL("./fixtures", import.meta.url)),
  "vulnerable-server",
);

describe("report formatters", () => {
  it("emits machine-readable JSON", async () => {
    const report = await scan(vulnerableFixture);
    const parsed = JSON.parse(formatJson(report)) as { schemaVersion: string; findings: unknown[] };

    expect(parsed.schemaVersion).toBe("1.0.0");
    expect(parsed.findings.length).toBeGreaterThan(0);
  });

  it("emits SARIF with rules, locations, and fingerprints", async () => {
    const repositoryUrl = "https://github.com/example/vulnerable-mcp-server";
    const report = await scan(vulnerableFixture, {
      repository: {
        commit: "0123456789abcdef0123456789abcdef01234567",
        url: repositoryUrl,
      },
    });
    const parsed = JSON.parse(formatSarif(report)) as {
      version: string;
      runs: Array<{
        properties: { provenance?: object; scanId: string };
        results: Array<{ partialFingerprints: object }>;
        tool: {
          driver: {
            informationUri: string;
            rules: Array<{
              defaultConfiguration: { level: string };
              fullDescription: { text: string };
              help: { text: string };
              id: string;
              name: string;
              properties: {
                confidence: string;
                precision: string;
                "security-severity": string;
                standards: object;
                tags: string[];
              };
              shortDescription: { text: string };
            }>;
          };
        };
      }>;
    };

    expect(parsed.version).toBe("2.1.0");
    expect(parsed.runs[0]?.results).toHaveLength(report.findings.length);
    expect(parsed.runs[0]?.tool.driver.rules.length).toBeGreaterThan(0);
    expect(parsed.runs[0]?.results[0]?.partialFingerprints).toBeDefined();
    expect(report.provenance?.repository?.url).toBe(repositoryUrl);
    expect(parsed.runs[0]?.tool.driver.informationUri).toBe(PRODUCT_URL);
    expect(parsed.runs[0]?.properties).toMatchObject({
      provenance: report.provenance,
      scanId: report.scan.id,
    });
    expect(parsed.runs[0]?.tool.driver.rules.find((rule) => rule.id === "MCP003")).toEqual({
      defaultConfiguration: { level: "error" },
      fullDescription: { text: RULES.pathTraversal.description },
      help: { text: RULES.pathTraversal.remediation },
      id: RULES.pathTraversal.id,
      name: RULES.pathTraversal.title,
      properties: {
        confidence: "medium",
        precision: "medium",
        "security-severity": "7.0",
        standards: RULES.pathTraversal.standards,
        tags: ["security"],
      },
      shortDescription: { text: RULES.pathTraversal.title },
    });
    expect(
      Object.fromEntries(
        parsed.runs[0]?.tool.driver.rules.map((rule) => [
          rule.id,
          {
            precision: rule.properties.precision,
            securitySeverity: rule.properties["security-severity"],
          },
        ]) ?? [],
      ),
    ).toMatchObject({
      MCP001: { precision: "high", securitySeverity: "9.0" },
      MCP003: { precision: "medium", securitySeverity: "7.0" },
      MCP008: { precision: "high", securitySeverity: "4.0" },
      MCP012: { precision: "medium", securitySeverity: "1.0" },
    });
  });

  it("renders a concise text report with and without color", async () => {
    const report = await scan(vulnerableFixture);
    const plain = formatText(report, false);
    const colored = formatText(report, true);

    expect(plain).toContain("MCP001");
    expect(plain).toContain("findings");
    expect(plain).not.toContain("\u001b[");
    expect(colored).toContain("\u001b[");
  });

  it("renders the zero-finding state", async () => {
    const safeFixture = path.join(path.dirname(vulnerableFixture), "safe-server");
    const report = await scan(safeFixture);

    expect(formatText(report)).toContain("No findings.");
  });
});
