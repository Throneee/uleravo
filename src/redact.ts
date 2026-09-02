const KNOWN_CREDENTIALS: readonly RegExp[] = [
  /\bAKIA[0-9A-Z]{16}\b/g,
  /\bgh[pousr]_[A-Za-z0-9]{30,255}\b/g,
  /\bsk-(?:proj-)?[A-Za-z0-9_-]{20,255}\b/g,
  /\bxox[baprs]-[A-Za-z0-9-]{20,255}\b/g,
];
const PRIVATE_KEY_LABELS = [
  "DSA PRIVATE KEY",
  "EC PRIVATE KEY",
  "ENCRYPTED PRIVATE KEY",
  "OPENSSH PRIVATE KEY",
  "RSA PRIVATE KEY",
  "PRIVATE KEY",
  "PGP PRIVATE KEY BLOCK",
] as const;
const PRIVATE_KEY_DELIMITER = "-----";
const PRIVATE_KEY_TOKENS = PRIVATE_KEY_LABELS.map((label) => ({
  begin: `-----BEGIN ${label}-----`,
  end: `-----END ${label}-----`,
  label,
}));
const URL_PATTERN = /https?:\/\/[^\s"'`<>]+/g;
const UNSAFE_DISPLAY_PATTERN =
  // biome-ignore lint/complexity/useRegexLiterals: the constructor avoids treating the intentionally matched control ranges as literal controls.
  new RegExp(
    "[\\u0000-\\u001f\\u007f-\\u009f\\u061c\\u200e\\u200f\\u2028\\u2029\\u202a-\\u202e\\u2066-\\u2069]",
    "g",
  );
const MAX_DUPLICATE_CREDENTIAL_VALUES = 16;
const QUOTED_ASSIGNMENT_PATTERN =
  /((?:api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|password|secret)\s*["']?\s*[:=]\s*)(["'])([^"'\n]*)(\2|(?:…|\.\.\.)$)/gi;
const UNQUOTED_ASSIGNMENT_PATTERN =
  /((?:api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|password|secret)\s*["']?\s*[:=]\s*)(?!["'])([^\s#"']+)/gi;
const SENSITIVE_QUERY_KEYS = new Set([
  "access_token",
  "api_key",
  "apikey",
  "auth",
  "key",
  "password",
  "secret",
  "token",
]);

export function redactEvidence(evidence: string): string {
  let redacted = redactPrivateKeys(evidence);
  for (const pattern of KNOWN_CREDENTIALS) {
    redacted = redacted.replaceAll(pattern, "<redacted>");
  }
  for (const value of assignedCredentialValues(redacted)) {
    redacted = redacted.replaceAll(value, "<redacted>");
  }
  redacted = redacted.replace(QUOTED_ASSIGNMENT_PATTERN, "$1$2<redacted>$4");
  redacted = redacted.replace(UNQUOTED_ASSIGNMENT_PATTERN, "$1<redacted>");
  redacted = redacted.replaceAll(URL_PATTERN, (raw) => redactUrl(raw));
  return escapeUnsafeDisplayCharacters(redacted);
}

export interface PrivateKeyRange {
  readonly end: number;
  readonly start: number;
}

export function findPrivateKeyRanges(value: string): readonly PrivateKeyRange[] {
  const ranges: PrivateKeyRange[] = [];
  let cursor = 0;
  let open: { readonly label: string; readonly start: number } | undefined;

  while (cursor < value.length) {
    const marker = value.indexOf(PRIVATE_KEY_DELIMITER, cursor);
    if (marker === -1) {
      break;
    }
    const token = privateKeyTokenAt(value, marker);
    cursor = token?.end ?? marker + PRIVATE_KEY_DELIMITER.length;
    if (token?.kind === "begin") {
      open ??= { label: token.label, start: marker };
    } else if (token?.kind === "end" && open?.label === token.label) {
      ranges.push({ end: token.end, start: open.start });
      open = undefined;
    }
  }

  if (open !== undefined) {
    ranges.push({ end: value.length, start: open.start });
  }
  return ranges;
}

function privateKeyTokenAt(
  value: string,
  offset: number,
): { readonly end: number; readonly kind: "begin" | "end"; readonly label: string } | undefined {
  for (const token of PRIVATE_KEY_TOKENS) {
    if (value.startsWith(token.begin, offset)) {
      return { end: offset + token.begin.length, kind: "begin", label: token.label };
    }
    if (value.startsWith(token.end, offset)) {
      return { end: offset + token.end.length, kind: "end", label: token.label };
    }
  }
  return undefined;
}

function redactPrivateKeys(value: string): string {
  const ranges = findPrivateKeyRanges(value);
  if (ranges.length === 0) {
    return value;
  }
  const parts: string[] = [];
  let copiedUntil = 0;
  for (const range of ranges) {
    parts.push(value.slice(copiedUntil, range.start), "<redacted>");
    copiedUntil = range.end;
  }
  parts.push(value.slice(copiedUntil));
  return parts.join("");
}

function escapeUnsafeDisplayCharacters(value: string): string {
  return value.replace(
    UNSAFE_DISPLAY_PATTERN,
    (character) =>
      `[U+${(character.codePointAt(0) ?? 0).toString(16).toUpperCase().padStart(4, "0")}]`,
  );
}

function assignedCredentialValues(evidence: string): readonly string[] {
  const values = new Set<string>();
  for (const match of evidence.matchAll(QUOTED_ASSIGNMENT_PATTERN)) {
    if (match[4] === match[2] && addCredentialValue(values, match[3])) {
      return sortByLength(values);
    }
  }
  for (const match of evidence.matchAll(UNQUOTED_ASSIGNMENT_PATTERN)) {
    if (addCredentialValue(values, match[2])) {
      break;
    }
  }
  return sortByLength(values);
}

function addCredentialValue(values: Set<string>, value: string | undefined): boolean {
  if (value === undefined || value.length < 8) {
    return false;
  }
  values.add(value);
  return values.size === MAX_DUPLICATE_CREDENTIAL_VALUES;
}

function sortByLength(values: ReadonlySet<string>): readonly string[] {
  return [...values].sort((left, right) => right.length - left.length);
}

function redactUrl(raw: string): string {
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
      if (SENSITIVE_QUERY_KEYS.has(key.toLowerCase())) {
        url.searchParams.set(key, "redacted");
      }
    }
    return `${url.toString()}${trailing}`;
  } catch {
    return raw;
  }
}
