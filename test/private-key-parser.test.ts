import { describe, expect, it, vi } from "vitest";
import { findPrivateKeyRanges, redactEvidence } from "../src/redact.js";
import { hardcodedSecretRule } from "../src/rules/secrets.js";
import type { ScannableFile } from "../src/scanner/files.js";

const PRIVATE_KEY_LABELS = [
  "DSA PRIVATE KEY",
  "EC PRIVATE KEY",
  "ENCRYPTED PRIVATE KEY",
  "OPENSSH PRIVATE KEY",
  "RSA PRIVATE KEY",
  "PRIVATE KEY",
  "PGP PRIVATE KEY BLOCK",
] as const;

describe("private-key parsing", () => {
  it.each(PRIVATE_KEY_LABELS)("redacts one complete %s block as one MCP007 range", (label) => {
    const bodyMarker = `SensitiveBodyFor${label.replaceAll(" ", "")}`;
    const block = `-----BEGIN ${label}-----\\n${bodyMarker}\\n-----END ${label}-----`;
    const prefix = 'const pem = "';
    const text = `${prefix}${block}";`;

    const findings = hardcodedSecretRule.scan({ file: sourceFile(text), hasLockfile: false });
    const redacted = redactEvidence(text);

    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      column: prefix.length + 1,
      endColumn: prefix.length + block.length + 1,
      endLine: 1,
      line: 1,
      metadata: { id: "MCP007" },
    });
    expect(findings[0]?.evidence).toContain("<redacted>");
    expect(findings[0]?.evidence).not.toContain(bodyMarker);
    expect(redacted).not.toContain(bodyMarker);
    expect(redacted).not.toContain("BEGIN");
    expect(redacted).not.toContain("END");
  });

  it("redacts unmatched and mismatched blocks through EOF", () => {
    const bodyMarker = "SensitiveUnterminatedBody";
    const text = [
      "prefix",
      "-----BEGIN RSA PRIVATE KEY-----",
      bodyMarker,
      "-----END EC PRIVATE KEY-----",
      "suffix",
    ].join("\n");

    const findings = hardcodedSecretRule.scan({ file: sourceFile(text), hasLockfile: false });
    const redacted = redactEvidence(text);

    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      endColumn: 7,
      endLine: 5,
      line: 2,
      metadata: { id: "MCP007" },
    });
    expect(redacted).toContain("prefix[U+000A]<redacted>");
    expect(redacted).not.toContain(bodyMarker);
    expect(redacted).not.toContain("PRIVATE KEY");
    expect(redacted).not.toContain("suffix");
  });

  it("does not classify unsupported or near-match labels as private keys", () => {
    const text =
      "-----BEGIN PUBLIC KEY-----\\nPublicMaterial\\n-----END PUBLIC KEY----- " +
      "-----BEGIN PRIVATE KEYNOTE-----\\nNoteMaterial";

    const findings = hardcodedSecretRule.scan({ file: sourceFile(text), hasLockfile: false });

    expect(findings).toHaveLength(0);
    expect(redactEvidence(text)).toBe(text);
  });

  it("scans repeated unmatched headers without restarting from each header", () => {
    const headerCount = 4_000;
    const text = Array.from(
      { length: headerCount },
      (_, index) => `-----BEGIN RSA PRIVATE KEY-----${index}|`,
    ).join("");
    const indexOf = vi.spyOn(String.prototype, "indexOf");

    try {
      expect(findPrivateKeyRanges(text)).toEqual([{ end: text.length, start: 0 }]);
      expect(indexOf.mock.calls.length).toBeLessThanOrEqual(headerCount + 1);
    } finally {
      indexOf.mockRestore();
    }
  });
});

function sourceFile(text: string): ScannableFile {
  return {
    absolutePath: "/virtual/credentials.ts",
    kind: "source",
    relativePath: "credentials.ts",
    text,
  };
}
