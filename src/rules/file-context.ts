const SYNTHETIC_CREDENTIAL_WORDS = new Set([
  "admin",
  "client",
  "credential",
  "key",
  "password",
  "redirect",
  "secret",
  "token",
  "user",
  "username",
  "value",
]);
const DOCUMENTED_AWS_EXAMPLE = ["AKIA", "IOSFODNN7EXAMPLE"].join("");

export function isTestFile(relativePath: string): boolean {
  const normalized = relativePath.toLowerCase();
  const segments = normalized.split("/");
  const basename = segments.at(-1) ?? "";

  return (
    segments.some(
      (segment) => segment === "__tests__" || /(?:^|[-_])tests?(?:$|[-_])/.test(segment),
    ) ||
    /\.(?:spec|test)\.[^.]+$/.test(basename) ||
    /^(?:test[-_].+|.+[-_]test)\.[^.]+$/.test(basename)
  );
}

export function isExampleFile(relativePath: string): boolean {
  const normalized = relativePath.toLowerCase();
  const segments = normalized.split("/");
  const basename = segments.at(-1) ?? "";

  return (
    segments.some((segment) => ["example", "examples", "sample", "samples"].includes(segment)) ||
    /(?:^|\.)(?:example|sample|template)(?:\.|$)/.test(basename)
  );
}

export function isSyntheticFixtureCredential(relativePath: string, value: string): boolean {
  if (!isTestFile(relativePath) && !isExampleFile(relativePath)) {
    return false;
  }
  const normalized = value.toLowerCase();
  return (
    SYNTHETIC_CREDENTIAL_WORDS.has(normalized) ||
    /^[a-z0-9]+(?:[-_][a-z0-9]+)+$/.test(normalized) ||
    credentialCharacterClassCount(value) < 3
  );
}

export function isUnmistakableProviderFixtureCredential(
  relativePath: string,
  value: string,
): boolean {
  if (!isTestFile(relativePath) && !isExampleFile(relativePath)) {
    return false;
  }
  if (value === DOCUMENTED_AWS_EXAMPLE) {
    return true;
  }
  const body = value
    .replace(/^AKIA/u, "")
    .replace(/^gh[pousr]_/u, "")
    .replace(/^sk-(?:proj-)?/u, "")
    .replace(/^xox[baprs]-/u, "");
  const segments = body.split(/[-_]/u).filter(Boolean);
  return segments.length > 0 && segments.every(isUnmistakableFillerSegment);
}

function isUnmistakableFillerSegment(value: string): boolean {
  const normalized = value.toLowerCase();
  const marker = /^(?:changeme|dummy|example|fake|placeholder|redacted|test)/u.exec(normalized);
  const remainder = marker === null ? normalized : normalized.slice(marker[0].length);
  return (
    /^(?:changeme|dummy|example|fake|placeholder|redacted|test|token|key|secret|value)+$/u.test(
      normalized,
    ) ||
    isRepeatedCharacter(remainder) ||
    followsRepeatedSequence(remainder, "abcdefghijklmnopqrstuvwxyz") ||
    followsRepeatedSequence(remainder, "0123456789")
  );
}

function isRepeatedCharacter(value: string): boolean {
  return value.length >= 8 && [...value].every((character) => character === value[0]);
}

function followsRepeatedSequence(value: string, sequence: string): boolean {
  return (
    value.length >= 8 &&
    [...value].every((character, index) => character === sequence[index % sequence.length])
  );
}

function credentialCharacterClassCount(value: string): number {
  return [/[a-z]/, /[A-Z]/, /[0-9]/, /[^A-Za-z0-9]/].filter((pattern) => pattern.test(value))
    .length;
}
