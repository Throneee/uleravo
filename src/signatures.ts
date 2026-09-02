import {
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  type KeyObject,
  sign as signBytes,
  verify as verifyBytes,
} from "node:crypto";
import type { ScanReport } from "./domain.js";
import { formatJson } from "./formatters/json.js";
import { redactEvidence } from "./redact.js";
import { parseScanReport } from "./reports/read.js";
import { PRODUCT_NAME } from "./version.js";

const ENVELOPE_FIELDS = [
  "algorithm",
  "keyId",
  "payload",
  "payloadSha256",
  "payloadType",
  "schemaVersion",
  "signature",
] as const;
export const SIGNED_REPORT_MAX_ENVELOPE_BYTES = 14_000_000;
export const SIGNED_REPORT_MAX_PAYLOAD_BYTES = 10_000_000;
const SIGNATURE_CONTEXT = Buffer.from("mirsad:signed-report:v1\0", "utf8");
const utf8Decoder = new TextDecoder("utf-8", { fatal: true });

export interface SignedReportEnvelope {
  readonly algorithm: "Ed25519";
  readonly keyId: string;
  readonly payload: string;
  readonly payloadSha256: string;
  readonly payloadType: "scan-report";
  readonly schemaVersion: "1.0.0";
  readonly signature: string;
}

export interface SigningKeyPair {
  readonly keyId: string;
  readonly privateKeyPem: string;
  readonly publicKeyPem: string;
}

export interface VerifiedSignedReport {
  readonly keyId: string;
  readonly payloadSha256: string;
  readonly report: ScanReport;
}

export function generateSigningKeyPair(): SigningKeyPair {
  const pair = generateKeyPairSync("ed25519", {
    privateKeyEncoding: { format: "pem", type: "pkcs8" },
    publicKeyEncoding: { format: "pem", type: "spki" },
  });
  return {
    keyId: keyId(parsePublicKey(pair.publicKey)),
    privateKeyPem: pair.privateKey,
    publicKeyPem: pair.publicKey,
  };
}

export function signReport(report: ScanReport, privateKeyPem: string): SignedReportEnvelope {
  const privateKey = parsePrivateKey(privateKeyPem);
  const payload = normalizedPayload(report);
  const signature = signBytes(null, signatureMessage(payload), privateKey);

  return {
    algorithm: "Ed25519",
    keyId: keyId(createPublicKey(privateKey)),
    payload: payload.toString("base64url"),
    payloadSha256: sha256(payload),
    payloadType: "scan-report",
    schemaVersion: "1.0.0",
    signature: signature.toString("base64url"),
  };
}

export function verifySignedReport(
  envelope: SignedReportEnvelope,
  publicKeyPem: string,
): VerifiedSignedReport {
  const validated = parseSignedReportEnvelope(JSON.stringify(envelope));
  const publicKey = parsePublicKey(publicKeyPem);
  const expectedKeyId = keyId(publicKey);
  if (validated.keyId !== expectedKeyId) {
    throw new Error("Signed report key ID does not match the supplied public key.");
  }

  const payload = decodeBase64Url(validated.payload, "payload");
  if (sha256(payload) !== validated.payloadSha256) {
    throw new Error("Signed report payload digest does not match its contents.");
  }
  const signature = decodeBase64Url(validated.signature, "signature");
  if (!verifyBytes(null, signatureMessage(payload), publicKey, signature)) {
    throw new Error("Signed report signature is invalid.");
  }

  let serialized: string;
  try {
    serialized = utf8Decoder.decode(payload);
  } catch {
    throw new Error("Signed report payload is not valid UTF-8.");
  }
  const raw = parseRawPayload(serialized);
  let report: ScanReport;
  try {
    report = parseScanReport(serialized, "signed report payload");
    if (Buffer.from(formatJson(report), "utf8").equals(payload)) {
      return {
        keyId: validated.keyId,
        payloadSha256: validated.payloadSha256,
        report,
      };
    }
  } catch (error) {
    if (!isV053Report(raw)) {
      throw error;
    }
    report = parseScanReport(JSON.stringify(migrateV053Standards(raw)), "signed report payload");
  }

  if (!isV053Report(raw) || !hasValidV053Paths(raw)) {
    throw new Error(`Signed report payload is not in ${PRODUCT_NAME}'s normalized JSON form.`);
  }
  const legacyCanonical = Buffer.from(formatJson(restoreV053CanonicalValues(report, raw)), "utf8");
  if (!legacyCanonical.equals(payload)) {
    throw new Error(`Signed report payload is not in ${PRODUCT_NAME}'s normalized JSON form.`);
  }

  return {
    keyId: validated.keyId,
    payloadSha256: validated.payloadSha256,
    report,
  };
}

function parseRawPayload(serialized: string): unknown {
  let value: unknown;
  try {
    value = JSON.parse(serialized) as unknown;
  } catch {
    throw new Error("Signed report payload is not valid JSON.");
  }
  return value;
}

function isV053Report(value: unknown): value is ScanReport {
  return isObject(value) && isObject(value.scanner) && value.scanner.version === "0.5.3";
}

function migrateV053Standards(value: unknown): unknown {
  if (!isObject(value) || !Array.isArray(value.findings)) {
    return value;
  }
  return {
    ...value,
    findings: value.findings.map((finding) => {
      if (!isObject(finding) || !isObject(finding.standards)) {
        return finding;
      }
      return {
        ...finding,
        standards: {
          ...finding.standards,
          atlas: migrateV053StringArray(finding.standards.atlas),
          cwe: migrateV053StringArray(finding.standards.cwe),
          owasp: migrateV053StringArray(finding.standards.owasp),
        },
      };
    }),
  };
}

function migrateV053StringArray(value: unknown): unknown {
  if (
    !Array.isArray(value) ||
    !value.every((item) => typeof item === "string" && item.length > 0) ||
    new Set(value).size !== value.length
  ) {
    return value;
  }
  return [...new Set(value.map((item) => redactEvidence(item)))];
}

function hasValidV053Paths(report: ScanReport): boolean {
  return (
    report.findings.every((finding) => v053ArtifactPath(finding.file)) &&
    report.diagnostics.every(
      (diagnostic) => diagnostic.file === undefined || v053ArtifactPath(diagnostic.file),
    ) &&
    (report.provenance?.lockfiles.every((lockfile) => v053ArtifactPath(lockfile.path)) ?? true)
  );
}

function v053ArtifactPath(value: string): boolean {
  if (value.length === 0 || value.startsWith("/") || /^[A-Za-z]:[\\/]/.test(value)) {
    return false;
  }
  return (
    !value.includes("\\") &&
    value.split("/").every((segment) => segment.length > 0 && segment !== "." && segment !== "..")
  );
}

function restoreV053CanonicalValues(report: ScanReport, raw: ScanReport): ScanReport {
  return {
    diagnostics: report.diagnostics.map((diagnostic, index) => {
      const rawDiagnostic = raw.diagnostics[index];
      if (rawDiagnostic === undefined) {
        return diagnostic;
      }
      return {
        ...(rawDiagnostic.file === undefined ? {} : { file: rawDiagnostic.file }),
        message: redactV053(rawDiagnostic.message),
        type: diagnostic.type,
      };
    }),
    findings: report.findings.map((finding, index) => {
      const rawFinding = raw.findings[index];
      if (rawFinding === undefined) {
        return finding;
      }
      return {
        ...finding,
        evidence: redactV053(rawFinding.evidence),
        file: rawFinding.file,
        fingerprint: rawFinding.fingerprint,
        message: redactV053(rawFinding.message),
        remediation: redactV053(rawFinding.remediation),
        standards: {
          atlas: rawFinding.standards.atlas.map(redactV053),
          cwe: rawFinding.standards.cwe.map(redactV053),
          owasp: rawFinding.standards.owasp.map(redactV053),
        },
        title: redactV053(rawFinding.title),
      };
    }),
    ...(report.provenance === undefined || raw.provenance === undefined
      ? {}
      : {
          provenance: {
            lockfiles: report.provenance.lockfiles.map((lockfile, index) => ({
              ...lockfile,
              path: raw.provenance?.lockfiles[index]?.path ?? lockfile.path,
            })),
            ...(report.provenance.package === undefined || raw.provenance.package === undefined
              ? {}
              : {
                  package: {
                    ...(raw.provenance.package.name === undefined
                      ? {}
                      : { name: redactV053(raw.provenance.package.name) }),
                    ...(raw.provenance.package.version === undefined
                      ? {}
                      : { version: redactV053(raw.provenance.package.version) }),
                  },
                }),
            ...(report.provenance.repository === undefined
              ? {}
              : { repository: report.provenance.repository }),
            scanInputSha256: report.provenance.scanInputSha256,
          },
        }),
    scan: {
      ...report.scan,
      target: redactV053(raw.scan.target),
    },
    scanner: {
      name: redactV053(raw.scanner.name),
      version: redactV053(raw.scanner.version),
    },
    schemaVersion: "1.0.0",
    summary: report.summary,
  };
}

// This is a frozen compatibility boundary, not a second current redactor.
// Broader legacy behavior must use a new explicit scanner-version gate.
const V053_KNOWN_CREDENTIALS: readonly RegExp[] = [
  /\bAKIA[0-9A-Z]{16}\b/g,
  /\bgh[pousr]_[A-Za-z0-9]{30,255}\b/g,
  /\bsk-(?:proj-)?[A-Za-z0-9_-]{20,255}\b/g,
  /\bxox[baprs]-[A-Za-z0-9-]{20,255}\b/g,
];
const V053_URL_PATTERN = /https?:\/\/[^\s"'`<>]+/g;
const V053_MAX_DUPLICATE_CREDENTIAL_VALUES = 16;
const V053_QUOTED_ASSIGNMENT_PATTERN =
  /((?:api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|password|secret)\s*["']?\s*[:=]\s*)(["'])([^"'\n]*)(\2|(?:…|\.\.\.)$)/gi;
const V053_UNQUOTED_ASSIGNMENT_PATTERN =
  /((?:api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|password|secret)\s*["']?\s*[:=]\s*)(?!["'])([^\s#"']+)/gi;
const V053_SENSITIVE_QUERY_KEYS = new Set([
  "access_token",
  "api_key",
  "apikey",
  "auth",
  "key",
  "password",
  "secret",
  "token",
]);

function redactV053(evidence: string): string {
  let redacted = evidence;
  for (const pattern of V053_KNOWN_CREDENTIALS) {
    redacted = redacted.replaceAll(pattern, "<redacted>");
  }
  for (const value of assignedCredentialValuesV053(redacted)) {
    redacted = redacted.replaceAll(value, "<redacted>");
  }
  redacted = redacted.replace(V053_QUOTED_ASSIGNMENT_PATTERN, "$1$2<redacted>$4");
  redacted = redacted.replace(V053_UNQUOTED_ASSIGNMENT_PATTERN, "$1<redacted>");
  return redacted.replaceAll(V053_URL_PATTERN, (raw) => redactUrlV053(raw));
}

function assignedCredentialValuesV053(evidence: string): readonly string[] {
  const values = new Set<string>();
  for (const match of evidence.matchAll(V053_QUOTED_ASSIGNMENT_PATTERN)) {
    if (match[4] === match[2] && addCredentialValueV053(values, match[3])) {
      return sortByLengthV053(values);
    }
  }
  for (const match of evidence.matchAll(V053_UNQUOTED_ASSIGNMENT_PATTERN)) {
    if (addCredentialValueV053(values, match[2])) {
      break;
    }
  }
  return sortByLengthV053(values);
}

function addCredentialValueV053(values: Set<string>, value: string | undefined): boolean {
  if (value === undefined || value.length < 8) {
    return false;
  }
  values.add(value);
  return values.size === V053_MAX_DUPLICATE_CREDENTIAL_VALUES;
}

function sortByLengthV053(values: ReadonlySet<string>): readonly string[] {
  return [...values].sort((left, right) => right.length - left.length);
}

function redactUrlV053(raw: string): string {
  const trailing = raw.match(/[),.;\]}]+$/)?.[0] ?? "";
  const candidate = trailing.length === 0 ? raw : raw.slice(0, -trailing.length);
  try {
    const url = new URL(candidate);
    if (url.username.length > 0) {
      url.username = "redacted";
    }
    if (url.password.length > 0) {
      url.password = "redacted";
    }
    for (const key of [...url.searchParams.keys()]) {
      if (V053_SENSITIVE_QUERY_KEYS.has(key.toLowerCase())) {
        url.searchParams.set(key, "redacted");
      }
    }
    return `${url.toString()}${trailing}`;
  } catch {
    return raw;
  }
}

export function parseSignedReportEnvelope(
  serialized: string,
  label = "signed report",
): SignedReportEnvelope {
  if (Buffer.byteLength(serialized, "utf8") > SIGNED_REPORT_MAX_ENVELOPE_BYTES) {
    throw new Error(
      `${label} exceeds the ${SIGNED_REPORT_MAX_ENVELOPE_BYTES.toString()}-byte envelope limit.`,
    );
  }
  if (hasDuplicateTopLevelObjectKeys(serialized)) {
    throw new Error(`${label} has an invalid or ambiguous envelope shape.`);
  }

  let value: unknown;
  try {
    value = JSON.parse(serialized) as unknown;
  } catch {
    throw new Error(`${label} is not valid JSON.`);
  }
  if (!isObject(value) || !hasExactFields(value, ENVELOPE_FIELDS)) {
    throw new Error(`${label} has an invalid or ambiguous envelope shape.`);
  }
  if (
    value.algorithm !== "Ed25519" ||
    value.payloadType !== "scan-report" ||
    value.schemaVersion !== "1.0.0" ||
    typeof value.keyId !== "string" ||
    !/^[a-f0-9]{64}$/.test(value.keyId) ||
    typeof value.payloadSha256 !== "string" ||
    !/^[a-f0-9]{64}$/.test(value.payloadSha256) ||
    typeof value.payload !== "string" ||
    typeof value.signature !== "string"
  ) {
    throw new Error(`${label} has invalid signing metadata.`);
  }

  const payload = decodeBase64Url(value.payload, "payload", label);
  if (payload.byteLength > SIGNED_REPORT_MAX_PAYLOAD_BYTES) {
    throw new Error(
      `${label} payload exceeds the ${SIGNED_REPORT_MAX_PAYLOAD_BYTES.toString()}-byte limit.`,
    );
  }
  const signature = decodeBase64Url(value.signature, "signature", label);
  if (signature.byteLength !== 64) {
    throw new Error(`${label} has an invalid Ed25519 signature length.`);
  }

  return {
    algorithm: "Ed25519",
    keyId: value.keyId,
    payload: value.payload,
    payloadSha256: value.payloadSha256,
    payloadType: "scan-report",
    schemaVersion: "1.0.0",
    signature: value.signature,
  };
}

export function formatSignedReportEnvelope(envelope: SignedReportEnvelope): string {
  return `${JSON.stringify(envelope, null, 2)}\n`;
}

function normalizedPayload(report: ScanReport): Buffer {
  const normalized = parseScanReport(JSON.stringify(report), "report to sign");
  const payload = Buffer.from(formatJson(normalized), "utf8");
  if (payload.byteLength > SIGNED_REPORT_MAX_PAYLOAD_BYTES) {
    throw new Error(
      `Report to sign exceeds the ${SIGNED_REPORT_MAX_PAYLOAD_BYTES.toString()}-byte limit.`,
    );
  }
  return payload;
}

function parsePrivateKey(pem: string): KeyObject {
  try {
    const key = createPrivateKey(pem);
    if (key.asymmetricKeyType !== "ed25519") {
      throw new Error("wrong key type");
    }
    return key;
  } catch {
    throw new Error("Private key must be an Ed25519 PKCS#8 PEM key.");
  }
}

function parsePublicKey(pem: string): KeyObject {
  if (canParsePrivateKey(pem)) {
    throw new Error("Public key must be an Ed25519 SPKI PEM key.");
  }
  try {
    const key = createPublicKey(pem);
    if (key.asymmetricKeyType !== "ed25519") {
      throw new Error("wrong key type");
    }
    return key;
  } catch {
    throw new Error("Public key must be an Ed25519 SPKI PEM key.");
  }
}

function canParsePrivateKey(pem: string): boolean {
  try {
    createPrivateKey(pem);
    return true;
  } catch {
    return false;
  }
}

function keyId(publicKey: KeyObject): string {
  const der = publicKey.export({ format: "der", type: "spki" });
  return sha256(der);
}

function signatureMessage(payload: Buffer): Buffer {
  return Buffer.concat([SIGNATURE_CONTEXT, payload]);
}

function sha256(value: NodeJS.ArrayBufferView): string {
  return createHash("sha256").update(value).digest("hex");
}

function decodeBase64Url(value: string, field: string, label = "signed report"): Buffer {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) {
    throw new Error(`${label} has invalid base64url ${field}.`);
  }
  const decoded = Buffer.from(value, "base64url");
  if (decoded.toString("base64url") !== value) {
    throw new Error(`${label} has non-canonical base64url ${field}.`);
  }
  return decoded;
}

function hasExactFields(value: Record<string, unknown>, expected: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  return (
    actual.length === expected.length && actual.every((field, index) => field === expected[index])
  );
}

function hasDuplicateTopLevelObjectKeys(serialized: string): boolean {
  const state: ObjectKeyScanState = {
    depth: 0,
    escaped: false,
    keys: new Set<string>(),
    stringStart: -1,
  };
  for (let index = 0; index < serialized.length; index += 1) {
    if (scanObjectKeyCharacter(serialized, index, state)) {
      return true;
    }
  }
  return false;
}

interface ObjectKeyScanState {
  depth: number;
  escaped: boolean;
  readonly keys: Set<string>;
  stringStart: number;
}

function scanObjectKeyCharacter(
  serialized: string,
  index: number,
  state: ObjectKeyScanState,
): boolean {
  const character = serialized[index];
  if (state.stringStart >= 0) {
    return scanQuotedCharacter(serialized, index, character, state);
  }
  if (character === '"') {
    state.stringStart = index;
  } else if (character === "{" || character === "[") {
    state.depth += 1;
  } else if (character === "}" || character === "]") {
    state.depth -= 1;
  }
  return false;
}

function scanQuotedCharacter(
  serialized: string,
  index: number,
  character: string | undefined,
  state: ObjectKeyScanState,
): boolean {
  if (state.escaped) {
    state.escaped = false;
    return false;
  }
  if (character === "\\") {
    state.escaped = true;
    return false;
  }
  if (character !== '"') {
    return false;
  }
  const duplicate = registerTopLevelKey(serialized, index, state);
  state.stringStart = -1;
  return duplicate;
}

function registerTopLevelKey(
  serialized: string,
  stringEnd: number,
  state: ObjectKeyScanState,
): boolean {
  let cursor = stringEnd + 1;
  while (/\s/.test(serialized[cursor] ?? "")) {
    cursor += 1;
  }
  if (state.depth !== 1 || serialized[cursor] !== ":") {
    return false;
  }
  let key: unknown;
  try {
    key = JSON.parse(serialized.slice(state.stringStart, stringEnd + 1)) as unknown;
  } catch {
    return false;
  }
  if (typeof key !== "string") {
    return false;
  }
  if (state.keys.has(key)) {
    return true;
  }
  state.keys.add(key);
  return false;
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
