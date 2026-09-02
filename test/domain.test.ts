import { describe, expect, it, vi } from "vitest";
import { createFinding, severityRank, summarize } from "../src/domain.js";
import { redactEvidence } from "../src/redact.js";
import { RULES } from "../src/rules/catalog.js";

describe("finding domain", () => {
  it("creates content-derived fingerprints", () => {
    const first = createFinding({
      column: 1,
      evidence: "exec(command)",
      file: "server.ts",
      line: 3,
      message: "unsafe",
      metadata: RULES.commandInjection,
    });
    const second = createFinding({
      column: 12,
      evidence: " exec( command ) ",
      file: "server.ts",
      line: 99,
      message: "different wording",
      metadata: RULES.commandInjection,
    });

    expect(first.fingerprint).toBe(second.fingerprint);
    expect(first.endLine).toBeUndefined();
  });

  it("summarizes all severity levels and orders them", () => {
    const finding = createFinding({
      column: 1,
      evidence: "eval(input)",
      file: "server.ts",
      line: 1,
      message: "unsafe",
      metadata: RULES.dynamicCode,
    });

    expect(summarize([finding])).toMatchObject({ critical: 1, total: 1 });
    expect(severityRank("critical")).toBeGreaterThan(severityRank("high"));
  });

  it("redacts a truncated quoted credential as a final defense", () => {
    const credentialPrefix = "Zz9!Yy8@Xx7#Ww6$".repeat(12);
    const marker = credentialPrefix.slice(0, 32);
    const finding = createFinding({
      column: 1,
      evidence: `const clientSecret = "${credentialPrefix}…`,
      file: "server.ts",
      line: 1,
      message: "unsafe",
      metadata: RULES.hardcodedSecret,
    });

    expect(finding.evidence.includes("<redacted>")).toBe(true);
    expect(finding.evidence.includes(marker)).toBe(false);
    expect(finding.evidence.endsWith("…")).toBe(true);

    const shortPrefixFinding = createFinding({
      column: 1,
      evidence: 'const password = "Ab…',
      file: "server.ts",
      line: 1,
      message: "unsafe",
      metadata: RULES.insecureTransport,
    });
    expect(shortPrefixFinding.evidence.includes("<redacted>")).toBe(true);
    expect(shortPrefixFinding.evidence.includes("Ab…")).toBe(false);
  });

  it("bounds duplicate credential redaction passes on untrusted text", () => {
    const replaceAll = vi.spyOn(String.prototype, "replaceAll");
    try {
      const evidence = Array.from(
        { length: 1_000 },
        (_, index) => `SECRET=Value${index.toString().padStart(8, "0")}`,
      ).join(" ");
      const redacted = redactEvidence(evidence);

      expect(replaceAll.mock.calls.length <= 22).toBe(true);
      expect(redacted.includes("Value")).toBe(false);
    } finally {
      replaceAll.mockRestore();
    }
  });
});
