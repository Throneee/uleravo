import type { PackageProvenance, RepositoryProvenance, ScanProvenance } from "../domain.js";
import { redactEvidence } from "../redact.js";
import type { DiscoveryResult } from "./files.js";

type JsonObject = Record<string, unknown>;

export interface RepositoryIdentity {
  readonly commit: string;
  readonly url: string;
}

export function createProvenance(
  discovery: DiscoveryResult,
  repository?: RepositoryIdentity,
): ScanProvenance {
  const packageMetadata = packageProvenance(discovery);
  const repositoryMetadata =
    repository === undefined ? undefined : normalizeRepositoryIdentity(repository);

  return {
    lockfiles: discovery.lockfiles.map((lockfile) => ({
      ...lockfile,
      path: redactEvidence(lockfile.path),
    })),
    ...(packageMetadata === undefined ? {} : { package: packageMetadata }),
    ...(repositoryMetadata === undefined ? {} : { repository: repositoryMetadata }),
    scanInputSha256: discovery.contentHash,
  };
}

function packageProvenance(discovery: DiscoveryResult): PackageProvenance | undefined {
  const manifest = discovery.files.find((file) => file.relativePath === "package.json");
  if (manifest === undefined) {
    return undefined;
  }

  let document: unknown;
  try {
    document = JSON.parse(manifest.text) as unknown;
  } catch {
    return undefined;
  }
  if (!isObject(document)) {
    return undefined;
  }

  const name = redactedNonEmptyString(document.name);
  const version = redactedNonEmptyString(document.version);
  if (name === undefined && version === undefined) {
    return undefined;
  }
  return {
    ...(name === undefined ? {} : { name }),
    ...(version === undefined ? {} : { version }),
  };
}

export function normalizeRepositoryIdentity(repository: RepositoryIdentity): RepositoryProvenance {
  if (!/^(?:[a-f0-9]{40}|[a-f0-9]{64})$/i.test(repository.commit)) {
    throw new Error("Repository commit must be a complete 40- or 64-character Git hash.");
  }

  let parsed: URL;
  try {
    parsed = new URL(repository.url);
  } catch {
    throw new Error("Repository URL must be a valid HTTPS URL.");
  }
  if (parsed.protocol !== "https:") {
    throw new Error("Repository URL must use HTTPS.");
  }
  if (parsed.username.length > 0 || parsed.password.length > 0) {
    throw new Error("Repository URL must not contain credentials.");
  }
  if (parsed.search.length > 0 || parsed.hash.length > 0) {
    throw new Error("Repository URL must not contain a query string or fragment.");
  }

  return {
    commit: repository.commit.toLowerCase(),
    url: parsed.href.replace(/\/$/, ""),
  };
}

function isObject(value: unknown): value is JsonObject {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function nonEmptyString(value: unknown): string | undefined {
  return typeof value === "string" && value.trim().length > 0 ? value : undefined;
}

function redactedNonEmptyString(value: unknown): string | undefined {
  const text = nonEmptyString(value);
  return text === undefined ? undefined : redactEvidence(text);
}
