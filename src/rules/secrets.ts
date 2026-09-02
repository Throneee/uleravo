import type { FindingInput } from "../domain.js";
import { findPrivateKeyRanges } from "../redact.js";
import type { ScannableFile } from "../scanner/files.js";
import { findingAtRedactedOffset } from "../scanner/source.js";
import { RULES } from "./catalog.js";
import {
  isSyntheticFixtureCredential,
  isUnmistakableProviderFixtureCredential,
} from "./file-context.js";
import type { Rule } from "./types.js";

interface SecretPattern {
  readonly label: string;
  readonly pattern: RegExp;
}

const KNOWN_SECRET_PATTERNS: readonly SecretPattern[] = [
  { label: "AWS access key", pattern: /\bAKIA[0-9A-Z]{16}\b/g },
  { label: "GitHub token", pattern: /\bgh[pousr]_[A-Za-z0-9]{30,255}\b/g },
  { label: "OpenAI-compatible API key", pattern: /\bsk-(?:proj-)?[A-Za-z0-9_-]{20,255}\b/g },
  { label: "Slack token", pattern: /\bxox[baprs]-[A-Za-z0-9-]{20,255}\b/g },
];

const QUOTED_ASSIGNMENT =
  /(?:api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|password|secret)[^\S\r\n]*["']?[^\S\r\n]*[:=][^\S\r\n]*(["'])([^"'\n]{8,})\1/gi;
const UNQUOTED_ENV_ASSIGNMENT =
  /^[^\S\r\n]*[A-Z0-9_-]*(?:API[_-]?KEY|ACCESS[_-]?TOKEN|AUTH[_-]?TOKEN|CLIENT[_-]?SECRET|PASSWORD|SECRET|TOKEN)[^\S\r\n]*=[^\S\r\n]*([^\s#"']{8,})/gim;
const UNQUOTED_STRUCTURED_ASSIGNMENT =
  /^[^\S\r\n]*["']?[A-Z0-9_-]*(?:API[_-]?KEY|ACCESS[_-]?TOKEN|AUTH[_-]?TOKEN|CLIENT[_-]?SECRET|PASSWORD|SECRET|TOKEN)["']?[^\S\r\n]*[:=][^\S\r\n]*([^\s#"'.,()[\]{};]{8,})/gim;

export const hardcodedSecretRule: Rule = {
  metadata: RULES.hardcodedSecret,
  scan({ file }): readonly FindingInput[] {
    const occupiedRanges: Array<{ end: number; start: number }> = [];
    const findings = findKnownSecrets(file, occupiedRanges);
    findings.push(...findGenericSecrets(file, occupiedRanges));
    return findings;
  },
};

function findKnownSecrets(
  file: ScannableFile,
  occupiedRanges: Array<{ end: number; start: number }>,
): FindingInput[] {
  const findings: FindingInput[] = [];
  for (const range of findPrivateKeyRanges(file.text)) {
    occupiedRanges.push(range);
    findings.push(
      findingAtRedactedOffset(
        file,
        range.start,
        range.end - range.start,
        RULES.hardcodedSecret,
        "A private key is embedded in this file.",
      ),
    );
  }
  for (const definition of KNOWN_SECRET_PATTERNS) {
    for (const match of file.text.matchAll(definition.pattern)) {
      const offset = match.index;
      const value = match[0];
      if (
        offset === undefined ||
        value === undefined ||
        isUnmistakableProviderFixtureCredential(file.relativePath, value) ||
        overlaps(occupiedRanges, offset, offset + value.length)
      ) {
        continue;
      }
      occupiedRanges.push({ end: offset + value.length, start: offset });
      findings.push(
        findingAtRedactedOffset(
          file,
          offset,
          value.length,
          RULES.hardcodedSecret,
          `A ${definition.label} is embedded in this file.`,
        ),
      );
    }
  }
  return findings;
}

function findGenericSecrets(
  file: ScannableFile,
  occupiedRanges: readonly { readonly end: number; readonly start: number }[],
): FindingInput[] {
  const findings: FindingInput[] = [];
  const patterns: readonly { readonly pattern: RegExp; readonly valueGroup: number }[] = [
    { pattern: QUOTED_ASSIGNMENT, valueGroup: 2 },
    ...unquotedCredentialPatterns(file.relativePath),
  ];
  for (const { pattern, valueGroup } of patterns) {
    for (const match of file.text.matchAll(pattern)) {
      const fullMatch = match[0];
      const value = match[valueGroup];
      const matchOffset = match.index;
      if (fullMatch === undefined || value === undefined || matchOffset === undefined) {
        continue;
      }
      const valueOffset = matchOffset + fullMatch.lastIndexOf(value);
      if (
        isPlaceholder(value) ||
        isPublicIngestKey(value) ||
        isSyntheticFixtureCredential(file.relativePath, value) ||
        shannonEntropy(value) < 3 ||
        overlaps(occupiedRanges, valueOffset, valueOffset + value.length)
      ) {
        continue;
      }
      findings.push(
        findingAtRedactedOffset(
          file,
          valueOffset,
          value.length,
          RULES.hardcodedSecret,
          "A credential-like value is assigned directly instead of being loaded from a secret binding.",
        ),
      );
    }
  }
  return findings;
}

function unquotedCredentialPatterns(
  relativePath: string,
): readonly { readonly pattern: RegExp; readonly valueGroup: number }[] {
  const normalized = relativePath.toLowerCase();
  if (/(?:^|\/)\.env(?:\.|$)/.test(normalized)) {
    return [{ pattern: UNQUOTED_ENV_ASSIGNMENT, valueGroup: 1 }];
  }
  if ([".toml", ".yaml", ".yml"].some((extension) => normalized.endsWith(extension))) {
    return [{ pattern: UNQUOTED_STRUCTURED_ASSIGNMENT, valueGroup: 1 }];
  }
  return [];
}

function isPublicIngestKey(value: string): boolean {
  // PostHog project tokens are public, write-only event-ingest identifiers.
  // Personal API keys use a different shape and remain reportable.
  return /^phc_[A-Za-z0-9_-]{20,}$/.test(value);
}

function isPlaceholder(value: string): boolean {
  const normalized = value.toLowerCase();
  return (
    normalized.includes("${") ||
    normalized.includes("<") ||
    normalized.includes("changeme") ||
    normalized.includes("dummy") ||
    normalized.includes("example") ||
    normalized.includes("fake") ||
    normalized.includes("placeholder") ||
    normalized.includes("process.env") ||
    normalized.includes("redacted") ||
    normalized.includes("replace") ||
    normalized.includes("test") ||
    normalized.includes("your_") ||
    normalized.startsWith("your-") ||
    normalized.startsWith("$") ||
    /[\\[\]{}()]/.test(value)
  );
}

function shannonEntropy(value: string): number {
  const frequencies = new Map<string, number>();
  for (const character of value) {
    frequencies.set(character, (frequencies.get(character) ?? 0) + 1);
  }
  let entropy = 0;
  for (const count of frequencies.values()) {
    const probability = count / value.length;
    entropy -= probability * Math.log2(probability);
  }
  return entropy;
}

function overlaps(
  ranges: readonly { readonly end: number; readonly start: number }[],
  start: number,
  end: number,
): boolean {
  return ranges.some((range) => start < range.end && end > range.start);
}
