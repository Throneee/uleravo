import type { FindingInput } from "../domain.js";
import { findingAtOffset } from "../scanner/source.js";
import { RULES } from "./catalog.js";
import { isExampleFile, isSyntheticFixtureCredential, isTestFile } from "./file-context.js";
import type { Rule } from "./types.js";

const URL_PATTERN = /https?:\/\/[^\s"'`<>]+/g;
const LOCAL_HOSTS = new Set(["0.0.0.0", "127.0.0.1", "::1", "localhost"]);
const DOCUMENTATION_HOSTS = new Set(["example.com", "example.net", "example.org"]);
const DOCUMENTATION_TLDS = [".example", ".invalid", ".test"] as const;
const NON_TRANSPORT_IDENTIFIERS = new Set([
  "http://json-schema.org/draft-04/schema#",
  "http://json-schema.org/draft-07/schema#",
  "http://www.w3.org/1998/Math/MathML",
]);
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

export const insecureTransportRule: Rule = {
  metadata: RULES.insecureTransport,
  scan({ file }): readonly FindingInput[] {
    if (isTestFile(file.relativePath)) {
      return [];
    }
    const findings: FindingInput[] = [];
    for (const candidate of findUrls(file.text)) {
      if (
        candidate.url.protocol !== "http:" ||
        isLocal(candidate.url.hostname) ||
        isNonTransportIdentifier(candidate)
      ) {
        continue;
      }
      findings.push(
        findingAtOffset(
          file,
          candidate.offset,
          candidate.raw.length,
          RULES.insecureTransport,
          `Remote endpoint ${candidate.url.hostname} uses cleartext HTTP.`,
        ),
      );
    }
    return findings;
  },
};

export const credentialInUrlRule: Rule = {
  metadata: RULES.credentialInUrl,
  scan({ file }): readonly FindingInput[] {
    const findings: FindingInput[] = [];
    for (const candidate of findUrls(file.text)) {
      const sensitiveParameters = [...candidate.url.searchParams.keys()].filter((key) =>
        SENSITIVE_QUERY_KEYS.has(key.toLowerCase()),
      );
      if (
        candidate.url.username.length === 0 &&
        candidate.url.password.length === 0 &&
        sensitiveParameters.length === 0
      ) {
        continue;
      }
      if (
        credentialValues(candidate.url, sensitiveParameters).every((value) =>
          isSyntheticFixtureCredential(file.relativePath, value),
        ) &&
        (isTestFile(file.relativePath) ||
          (isExampleFile(file.relativePath) && isDocumentationHost(candidate.url.hostname)))
      ) {
        continue;
      }
      const finding = findingAtOffset(
        file,
        candidate.offset,
        candidate.raw.length,
        RULES.credentialInUrl,
        "This URL carries a credential in userinfo or a sensitive query parameter.",
      );
      findings.push({ ...finding, evidence: redactUrl(finding.evidence, candidate.url) });
    }
    return findings;
  },
};

interface UrlCandidate {
  readonly offset: number;
  readonly raw: string;
  readonly url: URL;
}

function credentialValues(url: URL, sensitiveParameters: readonly string[]): readonly string[] {
  return [
    url.username,
    url.password,
    ...sensitiveParameters.flatMap((key) => url.searchParams.getAll(key)),
  ].filter((value) => value.length > 0);
}

function redactUrl(evidence: string, url: URL): string {
  let sanitized = evidence;
  if (url.username.length > 0) {
    sanitized = sanitized.replaceAll(url.username, "<redacted>");
  }
  if (url.password.length > 0) {
    sanitized = sanitized.replaceAll(url.password, "<redacted>");
  }
  for (const [key, value] of url.searchParams) {
    if (SENSITIVE_QUERY_KEYS.has(key.toLowerCase()) && value.length > 0) {
      sanitized = sanitized.replaceAll(value, "<redacted>");
    }
  }
  return sanitized;
}

function findUrls(text: string): readonly UrlCandidate[] {
  const candidates: UrlCandidate[] = [];
  for (const match of text.matchAll(URL_PATTERN)) {
    const offset = match.index;
    const matched = match[0];
    if (offset === undefined || matched === undefined) {
      continue;
    }
    const raw = matched.replace(/[),.;\]}]+$/, "");
    try {
      const url = new URL(raw);
      if (/[{}]/.test(url.hostname)) {
        // A formatted authority does not establish a literal remote destination.
        // Handler data-flow rules cover tool-controlled hosts where visible.
        continue;
      }
      candidates.push({ offset, raw, url });
    } catch {
      // Ignore incomplete strings; the scanner only reports URLs it can parse confidently.
    }
  }
  return candidates;
}

function isLocal(hostname: string): boolean {
  const normalized = hostname.replace(/^\[|\]$/g, "").toLowerCase();
  return LOCAL_HOSTS.has(normalized) || normalized.endsWith(".localhost");
}

function isDocumentationHost(hostname: string): boolean {
  const normalized = hostname.toLowerCase();
  return (
    [...DOCUMENTATION_HOSTS].some(
      (host) => normalized === host || normalized.endsWith(`.${host}`),
    ) || DOCUMENTATION_TLDS.some((suffix) => normalized.endsWith(suffix))
  );
}

function isNonTransportIdentifier(candidate: UrlCandidate): boolean {
  const { raw, url } = candidate;
  const unescapedRaw = raw.endsWith("\\") ? raw.slice(0, -1) : raw;
  if (NON_TRANSPORT_IDENTIFIERS.has(unescapedRaw)) {
    return true;
  }
  const hostname = url.hostname.toLowerCase();
  return (
    hostname === "proxy" ||
    (hostname === "www.apache.org" && url.pathname.startsWith("/licenses/")) ||
    (hostname === "www.w3.org" &&
      ["/1999/", "/2000/", "/2001/", "/XML/"].some((prefix) => url.pathname.startsWith(prefix)))
  );
}
