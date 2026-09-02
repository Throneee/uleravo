import { createHash, createPrivateKey, sign as signBytes } from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { findingFingerprint } from "../src/domain.js";
import { formatJson } from "../src/formatters/json.js";
import { scan } from "../src/scanner/scan.js";
import {
  formatSignedReportEnvelope,
  generateSigningKeyPair,
  parseSignedReportEnvelope,
  SIGNED_REPORT_MAX_ENVELOPE_BYTES,
  type SignedReportEnvelope,
  signReport,
  verifySignedReport,
} from "../src/signatures.js";

const safeFixture = path.join(fileURLToPath(new URL("./fixtures/safe-server", import.meta.url)));
const vulnerableFixture = path.join(
  fileURLToPath(new URL("./fixtures/vulnerable-server", import.meta.url)),
);

describe("signed report envelopes", () => {
  it("signs and verifies a normalized report deterministically", async () => {
    const report = await scan(safeFixture);
    const keys = generateSigningKeyPair();
    const first = signReport(report, keys.privateKeyPem);
    const second = signReport(report, keys.privateKeyPem);

    expect(first).toEqual(second);
    expect(first.algorithm).toBe("Ed25519");
    expect(first.keyId).toBe(keys.keyId);
    expect(Buffer.from(first.payload, "base64url").toString("utf8")).toBe(formatJson(report));
    expect(parseSignedReportEnvelope(formatSignedReportEnvelope(first))).toEqual(first);
    expect(verifySignedReport(first, keys.publicKeyPem)).toEqual({
      keyId: keys.keyId,
      payloadSha256: first.payloadSha256,
      report,
    });
  });

  it("detects payload tampering, signature tampering, and the wrong public key", async () => {
    const report = await scan(safeFixture);
    const keys = generateSigningKeyPair();
    const otherKeys = generateSigningKeyPair();
    const envelope = signReport(report, keys.privateKeyPem);
    const payload = JSON.parse(Buffer.from(envelope.payload, "base64url").toString("utf8")) as {
      scan: { target: string };
    };
    payload.scan.target = "tampered";

    expect(() =>
      verifySignedReport(
        { ...envelope, payload: Buffer.from(JSON.stringify(payload)).toString("base64url") },
        keys.publicKeyPem,
      ),
    ).toThrow("payload digest");
    expect(() =>
      verifySignedReport(
        { ...envelope, signature: flipFirstBase64UrlCharacter(envelope.signature) },
        keys.publicKeyPem,
      ),
    ).toThrow("signature is invalid");
    expect(() => verifySignedReport(envelope, otherKeys.publicKeyPem)).toThrow("key ID");
  });

  it("redacts recognized credentials and strips unknown fields before signing", async () => {
    const report = await scan(vulnerableFixture);
    const keys = generateSigningKeyPair();
    const credential = ["ghp_", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"].join("");
    const firstFinding = report.findings[0];
    if (firstFinding === undefined) {
      throw new Error("Expected the vulnerable fixture to produce a finding.");
    }
    const unsafe = {
      ...report,
      findings: [
        {
          ...firstFinding,
          message: `token=${credential}`,
          unexpected: credential,
        },
        ...report.findings.slice(1),
      ],
      unexpected: credential,
    };

    const envelope = signReport(unsafe, keys.privateKeyPem);
    const payload = Buffer.from(envelope.payload, "base64url").toString("utf8");
    const verified = verifySignedReport(envelope, keys.publicKeyPem);

    expect(payload).not.toContain(credential);
    expect(payload).toContain("<redacted>");
    expect(Object.hasOwn(verified.report, "unexpected")).toBe(false);
    expect(Object.hasOwn(verified.report.findings[0] ?? {}, "unexpected")).toBe(false);
  });

  it("verifies a canonical legacy payload before returning its newly sanitized report", async () => {
    const report = await scan(vulnerableFixture);
    const keys = generateSigningKeyPair();
    const firstFinding = report.findings[0];
    if (firstFinding === undefined) {
      throw new Error("Expected the vulnerable fixture to produce a finding.");
    }
    const legacyPrivateKey = [
      "-----BEGIN PRIVATE KEY-----",
      "legacy-placeholder-material",
      "-----END PRIVATE KEY-----",
    ].join("\n");
    const secondLegacyPrivateKey = [
      "-----BEGIN PRIVATE KEY-----",
      "second-legacy-placeholder-material",
      "-----END PRIVATE KEY-----",
    ].join("\n");
    const legacyPathCredential = ["ghp_", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"].join("");
    const legacyFile = `src/${legacyPathCredential}.ts`;
    const legacyFinding = {
      ...firstFinding,
      evidence: legacyPrivateKey,
      file: legacyFile,
      fingerprint: findingFingerprint(firstFinding.ruleId, legacyFile, legacyPrivateKey),
      standards: {
        ...firstFinding.standards,
        atlas: [legacyPrivateKey, secondLegacyPrivateKey],
      },
    };
    const legacyReport = {
      ...report,
      findings: [legacyFinding, ...report.findings.slice(1)],
      scanner: { ...report.scanner, version: "0.5.3" },
    };
    const serialized = formatJson(legacyReport);
    const envelope = resignPayload(
      signReport(report, keys.privateKeyPem),
      serialized,
      keys.privateKeyPem,
    );

    const verified = verifySignedReport(envelope, keys.publicKeyPem);

    const signedPayload = JSON.parse(
      Buffer.from(envelope.payload, "base64url").toString("utf8"),
    ) as { findings: Array<{ evidence: string }> };
    expect(signedPayload.findings[0]?.evidence).toBe(legacyPrivateKey);
    expect(verified.report.findings[0]?.evidence).toBe("<redacted>");
    expect(verified.report.findings[0]?.file).toBe("src/<redacted>.ts");
    expect(verified.report.findings[0]?.standards.atlas).toEqual(["<redacted>"]);
    expect(verified.report.findings[0]?.fingerprint).toBe(
      findingFingerprint(firstFinding.ruleId, "src/<redacted>.ts", "<redacted>"),
    );
    expect(formatJson(verified.report)).not.toContain(legacyPrivateKey);
    expect(formatJson(verified.report)).not.toContain(legacyPathCredential);
  });

  it("limits legacy normalization to v0.5.3 fields that were historically raw", async () => {
    const report = await scan(vulnerableFixture);
    const keys = generateSigningKeyPair();
    const template = signReport(report, keys.privateKeyPem);
    const firstFinding = report.findings[0];
    if (firstFinding === undefined) {
      throw new Error("Expected the vulnerable fixture to produce a finding.");
    }
    const privateKey = [
      "-----BEGIN PRIVATE KEY-----",
      "newer-placeholder-material",
      "-----END PRIVATE KEY-----",
    ].join("\n");
    const newerFinding = {
      ...firstFinding,
      evidence: privateKey,
      fingerprint: findingFingerprint(firstFinding.ruleId, firstFinding.file, privateKey),
    };
    const newerPayload = formatJson({
      ...report,
      findings: [newerFinding, ...report.findings.slice(1)],
      scanner: { ...report.scanner, version: "0.5.4" },
    });
    const credential = ["ghp_", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"].join("");
    const rawMessagePayload = formatJson({
      ...report,
      findings: [{ ...firstFinding, message: `token=${credential}` }, ...report.findings.slice(1)],
      scanner: { ...report.scanner, version: "0.5.3" },
    });
    const invalidLegacyFile = `src\\${credential}.ts`;
    const invalidPathPayload = formatJson({
      ...report,
      findings: [
        {
          ...firstFinding,
          file: invalidLegacyFile,
          fingerprint: findingFingerprint(
            firstFinding.ruleId,
            invalidLegacyFile,
            firstFinding.evidence,
          ),
        },
        ...report.findings.slice(1),
      ],
      scanner: { ...report.scanner, version: "0.5.3" },
    });

    for (const serialized of [newerPayload, rawMessagePayload, invalidPathPayload]) {
      const envelope = resignPayload(template, serialized, keys.privateKeyPem);
      expect(() => verifySignedReport(envelope, keys.publicKeyPem)).toThrow("normalized JSON form");
    }
  });

  it("rejects authenticated payloads with unknown, duplicate, or noncanonical fields", async () => {
    const report = await scan(vulnerableFixture);
    const keys = generateSigningKeyPair();
    const template = signReport(report, keys.privateKeyPem);
    const canonical = formatJson(report);
    const unknown = `${JSON.stringify({ ...report, unexpected: true }, null, 2)}\n`;
    const duplicate = canonical.replace(
      '  "schemaVersion": "1.0.0",',
      '  "schemaVersion": "1.0.0",\n  "schemaVersion": "1.0.0",',
    );
    const compact = JSON.stringify(report);
    const nestedUnknownReport = JSON.parse(canonical) as {
      findings: Array<{ standards: Record<string, unknown> }>;
    };
    const nestedUnknownFinding = nestedUnknownReport.findings[0];
    if (nestedUnknownFinding === undefined) {
      throw new Error("Expected the vulnerable fixture to produce a finding.");
    }
    nestedUnknownFinding.standards.unexpected = true;
    const nestedUnknown = `${JSON.stringify(nestedUnknownReport, null, 2)}\n`;
    const reorderedStandardsReport = JSON.parse(canonical) as {
      findings: Array<{ standards: Record<string, unknown> }>;
    };
    const reorderedFinding = reorderedStandardsReport.findings[0];
    if (reorderedFinding === undefined) {
      throw new Error("Expected the vulnerable fixture to produce a finding.");
    }
    reorderedFinding.standards = {
      owasp: reorderedFinding.standards.owasp,
      cwe: reorderedFinding.standards.cwe,
      atlas: reorderedFinding.standards.atlas,
    };
    const noncanonicalStandards = `${JSON.stringify(reorderedStandardsReport, null, 2)}\n`;

    for (const serialized of [unknown, duplicate, compact, nestedUnknown, noncanonicalStandards]) {
      const envelope = resignPayload(template, serialized, keys.privateKeyPem);
      expect(() => verifySignedReport(envelope, keys.publicKeyPem)).toThrow("normalized JSON form");
    }
  });

  it("rejects ambiguous, oversized, and malformed envelopes", async () => {
    const report = await scan(safeFixture);
    const keys = generateSigningKeyPair();
    const envelope = signReport(report, keys.privateKeyPem);

    expect(() => parseSignedReportEnvelope("{")).toThrow("not valid JSON");
    expect(() =>
      parseSignedReportEnvelope(JSON.stringify({ ...envelope, unexpected: true })),
    ).toThrow("ambiguous envelope shape");
    const duplicateEnvelopeKey = formatSignedReportEnvelope(envelope).replace(
      '  "algorithm": "Ed25519",',
      '  "algorithm": "Ed25519",\n  "algorithm": "Ed25519",',
    );
    expect(() => parseSignedReportEnvelope(duplicateEnvelopeKey)).toThrow(
      "ambiguous envelope shape",
    );
    expect(() =>
      parseSignedReportEnvelope(JSON.stringify({ ...envelope, payload: `${envelope.payload}=` })),
    ).toThrow("invalid base64url payload");
    expect(() =>
      parseSignedReportEnvelope(JSON.stringify({ ...envelope, signature: "YQ" })),
    ).toThrow("signature length");
    expect(() =>
      parseSignedReportEnvelope("x".repeat(SIGNED_REPORT_MAX_ENVELOPE_BYTES + 1)),
    ).toThrow("envelope limit");
  });

  it("accepts only Ed25519 PKCS#8 private and SPKI public keys", async () => {
    const report = await scan(safeFixture);
    const keys = generateSigningKeyPair();
    const envelope = signReport(report, keys.privateKeyPem);

    expect(() => signReport(report, keys.publicKeyPem)).toThrow("PKCS#8");
    expect(() => verifySignedReport(envelope, keys.privateKeyPem)).toThrow("SPKI");
    expect(() =>
      parseSignedReportEnvelope(JSON.stringify({ ...envelope, algorithm: "RSA" })),
    ).toThrow("signing metadata");
  });
});

function flipFirstBase64UrlCharacter(value: string): string {
  const first = value[0];
  if (first === undefined) {
    throw new Error("Expected a non-empty base64url value.");
  }
  return `${first === "A" ? "B" : "A"}${value.slice(1)}`;
}

function resignPayload(
  template: SignedReportEnvelope,
  serialized: string,
  privateKeyPem: string,
): SignedReportEnvelope {
  const payload = Buffer.from(serialized, "utf8");
  const signatureMessage = Buffer.concat([
    Buffer.from("mirsad:signed-report:v1\0", "utf8"),
    payload,
  ]);
  return {
    ...template,
    payload: payload.toString("base64url"),
    payloadSha256: createHash("sha256").update(payload).digest("hex"),
    signature: signBytes(null, signatureMessage, createPrivateKey(privateKeyPem)).toString(
      "base64url",
    ),
  };
}
