import { Buffer } from "node:buffer";
import { createHash } from "node:crypto";
import type { Stats } from "node:fs";
import { lstat, open } from "node:fs/promises";
import path from "node:path";
import { compareCodeUnits } from "../order.js";
import { boundedRedactedEvidence, redactEvidence } from "../redact.js";
import type {
  ArtifactAbsentClaim,
  ArtifactClaim,
  ArtifactClosureFile,
  ArtifactCoverage,
  ArtifactDiagnostic,
  ArtifactDiagnosticCode,
  ArtifactEvidenceReference,
  ArtifactEvidenceSource,
  ArtifactRepositoryClaims,
  ArtifactSnapshot,
  ArtifactValueClaim,
  SkillManifestClaims,
} from "./domain.js";
import {
  ARTIFACT_DIAGNOSTIC_CODES,
  MAX_ARTIFACT_CLAIM_CHARACTERS,
  MAX_ARTIFACT_DIAGNOSTICS,
  MAX_ARTIFACT_REPORT_BYTES,
  MAX_ARTIFACT_TARGET_CHARACTERS,
} from "./domain.js";
import {
  containsUnsafeArtifactText,
  isSafeArtifactReportPath,
  isWellFormedUnicode,
} from "./path.js";

const MAX_JSON_DEPTH = 128;
const MAX_JSON_VALUES = 1_000_000;
const MAX_FILES = 10_000;
const MAX_EVIDENCE = 10_000;
const MAX_FILE_BYTES = 100_000_000;
const MAX_TOTAL_BYTES = 250_000_000;
const MAX_PATH_CHARACTERS = 4_000;
const MAX_REASON_CHARACTERS = 4_000;
const MAX_DIAGNOSTIC_CHARACTERS = 4_000;
const MAX_ANALYZER_CHARACTERS = 200;
const MAX_READER_ERROR_CHARACTERS = 1_000;
const DIGEST_PATTERN = /^[a-f0-9]{64}$/;
const SNAPSHOT_ID_PATTERN = /^[a-f0-9]{24}$/;
const CONTENT_DOMAIN = Buffer.from("uleravo-artifact-content-v1\0", "utf8");
const OBSERVATION_DOMAIN = Buffer.from("uleravo-artifact-observation-v1\0", "utf8");
const SNAPSHOT_DOMAIN = Buffer.from("uleravo-artifact-snapshot-v1\0", "utf8");
const utf8Decoder = new TextDecoder("utf-8", { fatal: true });
const COVERAGE_AREAS = [
  "artifact-closure",
  "manifest-metadata",
  "capability-normalization",
  "harness-permissions",
] as const;
const EVIDENCE_SOURCES = new Set<ArtifactEvidenceSource>([
  "declared",
  "inferred",
  "observed",
  "user-supplied",
]);
const DIAGNOSTIC_CODES = new Set<ArtifactDiagnosticCode>(ARTIFACT_DIAGNOSTIC_CODES);

type JsonObject = Record<string, unknown>;
type CoverageArea = (typeof COVERAGE_AREAS)[number];

interface DigestibleClosureFile {
  readonly bytes: number;
  readonly path: string;
  readonly sha256: string;
}

interface CrossFieldInput {
  readonly artifact: ArtifactSnapshot["artifact"];
  readonly closure: ArtifactSnapshot["closure"];
  readonly complete: boolean;
  readonly coverage: readonly ArtifactCoverage[];
  readonly diagnostics: readonly ArtifactDiagnostic[];
  readonly label: string;
  readonly snapshot: ArtifactSnapshot["snapshot"];
}

interface RequiredCoverageClaims {
  readonly capability: ArtifactClaim<string>;
  readonly closure: ArtifactClaim<string>;
  readonly harness: ArtifactClaim<string>;
  readonly manifest: ArtifactClaim<string>;
}

export async function readArtifactSnapshot(reportPath: string): Promise<ArtifactSnapshot> {
  const label = boundedRedactedEvidence(reportPath, MAX_READER_ERROR_CHARACTERS);
  let bytes: Buffer;
  try {
    bytes = await readBoundedStableRegularFile(path.resolve(reportPath), label);
  } catch (error) {
    throw new Error(
      boundedRedactedEvidence(
        error instanceof Error ? error.message : String(error),
        MAX_READER_ERROR_CHARACTERS,
      ),
    );
  }
  let serialized: string;
  try {
    serialized = utf8Decoder.decode(bytes);
  } catch {
    throw new Error(`${label} is not valid UTF-8.`);
  }
  return parseArtifactSnapshot(serialized, label);
}

export function parseArtifactSnapshot(
  serialized: string,
  label = "artifact snapshot",
): ArtifactSnapshot {
  label = boundedRedactedEvidence(label, MAX_READER_ERROR_CHARACTERS);
  if (
    serialized.length > MAX_ARTIFACT_REPORT_BYTES ||
    Buffer.byteLength(serialized, "utf8") > MAX_ARTIFACT_REPORT_BYTES
  ) {
    throw new Error(
      `${label} exceeds the ${MAX_ARTIFACT_REPORT_BYTES.toString()}-byte report limit.`,
    );
  }
  validateJsonStructure(serialized, label);

  let parsed: unknown;
  try {
    parsed = JSON.parse(serialized) as unknown;
  } catch {
    throw new Error(`${label} is not valid JSON.`);
  }

  const root = exactObject(parsed, label, [
    "artifact",
    "closure",
    "complete",
    "coverage",
    "diagnostics",
    "documentType",
    "schemaVersion",
    "snapshot",
  ]);
  expectLiteral(root.documentType, "uleravo.artifact-snapshot", `${label}.documentType`);
  expectLiteral(root.schemaVersion, "1.0.0", `${label}.schemaVersion`);
  if (typeof root.complete !== "boolean") {
    invalid(`${label}.complete`, "must be a boolean");
  }

  const artifact = parseArtifact(root.artifact, `${label}.artifact`);
  const closure = parseClosure(root.closure, `${label}.closure`);
  const diagnostics = parseDiagnostics(root.diagnostics, `${label}.diagnostics`);
  const coverage = parseCoverage(root.coverage, `${label}.coverage`);
  const snapshot = parseSnapshotMetadata(root.snapshot, `${label}.snapshot`);
  validateCrossFieldInvariants({
    artifact,
    closure,
    complete: root.complete,
    coverage,
    diagnostics,
    label,
    snapshot,
  });

  return {
    artifact,
    closure,
    complete: root.complete,
    coverage,
    diagnostics,
    documentType: "uleravo.artifact-snapshot",
    schemaVersion: "1.0.0",
    snapshot,
  };
}

async function readBoundedStableRegularFile(resolved: string, label: string): Promise<Buffer> {
  const pathBefore = await lstat(resolved);
  assertRegularUnlinkedFile(pathBefore, label);
  assertFileSize(pathBefore.size, label);

  const handle = await open(resolved, "r");
  try {
    const openedBefore = await handle.stat();
    assertRegularUnlinkedFile(openedBefore, label);
    assertFileSize(openedBefore.size, label);
    if (!samePathAndOpenedFileSnapshot(pathBefore, openedBefore)) {
      throw new Error(`${label} changed before it could be read safely.`);
    }

    const allocation = Buffer.allocUnsafe(openedBefore.size + 1);
    let used = 0;
    while (used < allocation.byteLength) {
      const { bytesRead } = await handle.read(allocation, used, allocation.byteLength - used, used);
      if (bytesRead === 0) {
        break;
      }
      used += bytesRead;
    }
    if (used > MAX_ARTIFACT_REPORT_BYTES) {
      throw new Error(
        `${label} exceeds the ${MAX_ARTIFACT_REPORT_BYTES.toString()}-byte report limit.`,
      );
    }

    const openedAfter = await handle.stat();
    const pathAfter = await lstat(resolved);
    assertRegularUnlinkedFile(openedAfter, label);
    assertRegularUnlinkedFile(pathAfter, label);
    if (
      openedAfter.size !== used ||
      !sameOpenedFileSnapshot(openedBefore, openedAfter) ||
      !samePathAndOpenedFileSnapshot(pathAfter, openedAfter)
    ) {
      throw new Error(`${label} changed while it was being read.`);
    }
    return Buffer.from(allocation.subarray(0, used));
  } finally {
    await handle.close();
  }
}

function assertRegularUnlinkedFile(metadata: Stats, label: string): void {
  if (!metadata.isFile() || metadata.isSymbolicLink()) {
    throw new Error(`${label} is not a regular report file.`);
  }
}

function assertFileSize(size: number, label: string): void {
  if (!Number.isSafeInteger(size) || size < 0 || size > MAX_ARTIFACT_REPORT_BYTES) {
    throw new Error(
      `${label} exceeds the ${MAX_ARTIFACT_REPORT_BYTES.toString()}-byte report limit.`,
    );
  }
}

function sameOpenedFileSnapshot(left: Stats, right: Stats): boolean {
  return left.dev === right.dev && left.ino === right.ino && sameFileMetadata(left, right);
}

function samePathAndOpenedFileSnapshot(pathSnapshot: Stats, openedSnapshot: Stats): boolean {
  const sameDevice =
    pathSnapshot.dev === openedSnapshot.dev ||
    (process.platform === "win32" &&
      pathSnapshot.dev === 0 &&
      openedSnapshot.dev !== 0 &&
      pathSnapshot.ino !== 0);
  return (
    sameDevice &&
    pathSnapshot.ino === openedSnapshot.ino &&
    sameFileMetadata(pathSnapshot, openedSnapshot)
  );
}

function sameFileMetadata(left: Stats, right: Stats): boolean {
  return (
    left.size === right.size && left.mtimeMs === right.mtimeMs && left.ctimeMs === right.ctimeMs
  );
}

function parseArtifact(value: unknown, location: string): ArtifactSnapshot["artifact"] {
  const object = exactObject(
    value,
    location,
    ["adapter", "identity", "kind", "manifest"],
    ["repository"],
  );
  expectLiteral(object.kind, "skill", `${location}.kind`);

  const adapter = exactObject(object.adapter, `${location}.adapter`, ["name", "version"]);
  expectLiteral(adapter.name, "openai-skill", `${location}.adapter.name`);
  expectLiteral(adapter.version, "1.0.0", `${location}.adapter.version`);

  const identity = exactObject(object.identity, `${location}.identity`, [
    "contentSha256",
    "mutable",
  ]);
  const contentSha256 = parseClaim(identity.contentSha256, `${location}.identity.contentSha256`, {
    kind: "digest",
  });
  const mutable = parseValueClaim(identity.mutable, `${location}.identity.mutable`, parseTrue);
  assertValueClaimShape(mutable, `${location}.identity.mutable`, {
    evidence: [],
    source: "inferred",
    state: "mutable",
  });
  if (mutable.value !== true || mutable.redacted !== undefined) {
    invalid(`${location}.identity.mutable`, "must be the inferred mutable value true");
  }

  const manifest = parseManifest(object.manifest, `${location}.manifest`);
  const repository =
    object.repository === undefined
      ? undefined
      : parseRepository(object.repository, `${location}.repository`);
  return {
    adapter: { name: "openai-skill", version: "1.0.0" },
    identity: { contentSha256, mutable },
    kind: "skill",
    manifest,
    ...(repository === undefined ? {} : { repository }),
  };
}

function parseManifest(value: unknown, location: string): SkillManifestClaims {
  const object = exactObject(value, location, ["description", "name", "path", "version"]);
  const description = parseClaim(object.description, `${location}.description`, {
    kind: "string",
    maximum: MAX_ARTIFACT_CLAIM_CHARACTERS,
  });
  const name = parseClaim(object.name, `${location}.name`, {
    kind: "string",
    maximum: MAX_ARTIFACT_CLAIM_CHARACTERS,
  });
  validateManifestTextClaim(description, `${location}.description`);
  validateManifestTextClaim(name, `${location}.name`);
  if (isValueClaim(description) !== isValueClaim(name)) {
    invalid(location, "name and description claims must resolve together");
  }

  const manifestPath = parseValueClaim(object.path, `${location}.path`, parseManifestPath);
  assertValueClaimShape(manifestPath, `${location}.path`, {
    evidence: manifestPath.state === "resolved" ? ["SKILL.md"] : [],
    source: "observed",
    state: manifestPath.state,
  });
  if (
    (manifestPath.state !== "resolved" && manifestPath.state !== "unresolved") ||
    manifestPath.redacted !== undefined
  ) {
    invalid(`${location}.path`, "must be an observed resolved or unresolved path claim");
  }

  const version = parseAbsentClaim(object.version, `${location}.version`);
  assertAbsentClaimShape(version, `${location}.version`, {
    evidence: [],
    source: "inferred",
    state: "unavailable",
  });
  return { description, name, path: manifestPath, version };
}

function validateManifestTextClaim(claim: ArtifactClaim<string>, location: string): void {
  if (isValueClaim(claim)) {
    assertValueClaimShape(claim, location, {
      evidence: ["SKILL.md"],
      source: "declared",
      state: "resolved",
    });
    if (claim.value.length === 0 || claim.value.trim() !== claim.value) {
      invalid(location, "must contain a non-empty trimmed string");
    }
    return;
  }
  assertAbsentClaimShape(claim, location, {
    evidence: [],
    source: "observed",
    state: "unavailable",
  });
}

function parseRepository(value: unknown, location: string): ArtifactRepositoryClaims {
  const object = exactObject(value, location, ["commit", "url"]);
  const commit = parseValueClaim(object.commit, `${location}.commit`, (candidate, nested) =>
    boundedString(candidate, nested, 40, 64),
  );
  const url = parseValueClaim(object.url, `${location}.url`, (candidate, nested) =>
    boundedString(candidate, nested, 1, MAX_ARTIFACT_CLAIM_CHARACTERS),
  );
  for (const [name, claim] of [
    ["commit", commit],
    ["url", url],
  ] as const) {
    assertValueClaimShape(claim, `${location}.${name}`, {
      evidence: [],
      source: "user-supplied",
      state: "endpoint-unverified",
    });
    if (claim.redacted !== undefined) {
      invalid(`${location}.${name}`, "must not be marked redacted");
    }
  }
  const normalized = normalizeRepository(commit.value, url.value, location);
  if (normalized.commit !== commit.value || normalized.url !== url.value) {
    invalid(location, "must contain a canonical repository identity");
  }
  return { commit, url };
}

function parseClosure(value: unknown, location: string): ArtifactSnapshot["closure"] {
  const object = exactObject(value, location, ["files", "observedSha256", "totalBytes"]);
  const files = parseClosureFiles(object.files, `${location}.files`);
  const observedSha256 = parseValueClaim(
    object.observedSha256,
    `${location}.observedSha256`,
    parseDigest,
  );
  const totalBytes = parseValueClaim(
    object.totalBytes,
    `${location}.totalBytes`,
    (candidate, nested) => safeInteger(candidate, nested, 0, MAX_TOTAL_BYTES),
  );
  return { files, observedSha256, totalBytes };
}

function parseClosureFiles(value: unknown, location: string): ArtifactClosureFile[] {
  const candidates = boundedArray(value, location, MAX_FILES);
  const files: ArtifactClosureFile[] = [];
  let previousPath: string | undefined;
  for (let index = 0; index < candidates.length; index += 1) {
    const nested = `${location}[${index.toString()}]`;
    const object = exactObject(candidates[index], nested, ["bytes", "path", "sha256"]);
    const bytes = parseValueClaim(object.bytes, `${nested}.bytes`, (candidate, claimLocation) =>
      safeInteger(candidate, claimLocation, 0, MAX_FILE_BYTES),
    );
    const filePath = parseValueClaim(object.path, `${nested}.path`, parseArtifactPath);
    const sha256 = parseValueClaim(object.sha256, `${nested}.sha256`, parseDigest);
    for (const [name, claim] of [
      ["bytes", bytes],
      ["path", filePath],
      ["sha256", sha256],
    ] as const) {
      assertValueClaimShape(claim, `${nested}.${name}`, {
        evidence: [filePath.value],
        source: "observed",
        state: "resolved",
      });
      if (claim.redacted !== undefined) {
        invalid(`${nested}.${name}`, "must not be marked redacted");
      }
    }
    if (previousPath !== undefined && compareCodeUnits(previousPath, filePath.value) >= 0) {
      invalid(location, "must be strictly sorted by unique path using code-unit order");
    }
    previousPath = filePath.value;
    files.push({ bytes, path: filePath, sha256 });
  }
  return files;
}

function parseCoverage(value: unknown, location: string): ArtifactCoverage[] {
  const candidates = boundedArray(value, location, COVERAGE_AREAS.length, COVERAGE_AREAS.length);
  const coverage: ArtifactCoverage[] = [];
  const seen = new Set<CoverageArea>();
  for (let index = 0; index < candidates.length; index += 1) {
    const nested = `${location}[${index.toString()}]`;
    const object = exactObject(candidates[index], nested, ["area", "claim"]);
    if (!isCoverageArea(object.area) || seen.has(object.area)) {
      invalid(`${nested}.area`, "must identify an exactly-once coverage area");
    }
    seen.add(object.area);
    const claim = parseClaim(object.claim, `${nested}.claim`, {
      kind: "string",
      maximum: MAX_ARTIFACT_CLAIM_CHARACTERS,
    });
    if (isValueClaim(claim) && claim.value.length === 0) {
      invalid(`${nested}.claim.value`, "must not be empty");
    }
    coverage.push({
      area: object.area,
      claim,
    });
  }
  if (!COVERAGE_AREAS.every((area) => seen.has(area))) {
    invalid(location, "must contain every required coverage area exactly once");
  }
  return coverage;
}

function parseDiagnostics(value: unknown, location: string): ArtifactDiagnostic[] {
  const candidates = boundedArray(value, location, MAX_ARTIFACT_DIAGNOSTICS);
  const diagnostics: ArtifactDiagnostic[] = [];
  let previous: ArtifactDiagnostic | undefined;
  for (let index = 0; index < candidates.length; index += 1) {
    const nested = `${location}[${index.toString()}]`;
    const object = exactObject(candidates[index], nested, ["code", "message", "type"], ["file"]);
    const code = parseDiagnosticCode(object.code, `${nested}.code`);
    const message = boundedString(
      object.message,
      `${nested}.message`,
      1,
      MAX_DIAGNOSTIC_CHARACTERS,
    );
    if (object.type !== "error" && object.type !== "warning") {
      invalid(`${nested}.type`, "must be error or warning");
    }
    const file =
      object.file === undefined ? undefined : parseArtifactPath(object.file, `${nested}.file`);
    const diagnostic: ArtifactDiagnostic = {
      code,
      ...(file === undefined ? {} : { file }),
      message,
      type: object.type,
    };
    if (previous !== undefined && compareDiagnostics(previous, diagnostic) >= 0) {
      invalid(location, "must be strictly sorted and contain no duplicate diagnostics");
    }
    previous = diagnostic;
    diagnostics.push(diagnostic);
  }
  return diagnostics;
}

function parseSnapshotMetadata(value: unknown, location: string): ArtifactSnapshot["snapshot"] {
  const object = exactObject(value, location, [
    "analyzer",
    "consistency",
    "durationMs",
    "generatedAt",
    "id",
    "target",
  ]);
  const analyzerObject = exactObject(object.analyzer, `${location}.analyzer`, ["name", "version"]);
  const analyzer = {
    name: boundedString(
      analyzerObject.name,
      `${location}.analyzer.name`,
      1,
      MAX_ANALYZER_CHARACTERS,
    ),
    version: boundedString(
      analyzerObject.version,
      `${location}.analyzer.version`,
      1,
      MAX_ANALYZER_CHARACTERS,
    ),
  };
  expectLiteral(object.consistency, "best-effort", `${location}.consistency`);
  const durationMs = safeInteger(object.durationMs, `${location}.durationMs`, 0);
  const generatedAt = boundedString(object.generatedAt, `${location}.generatedAt`, 1, 100);
  if (!validIsoTimestamp(generatedAt)) {
    invalid(`${location}.generatedAt`, "must be a canonical ISO-8601 timestamp");
  }
  const id = boundedString(object.id, `${location}.id`, 24, 24);
  if (!SNAPSHOT_ID_PATTERN.test(id)) {
    invalid(`${location}.id`, "must be a lower-case 24-character hexadecimal identifier");
  }
  const target = boundedString(
    object.target,
    `${location}.target`,
    1,
    MAX_ARTIFACT_TARGET_CHARACTERS,
  );
  return {
    analyzer,
    consistency: "best-effort",
    durationMs,
    generatedAt,
    id,
    target,
  };
}

function validateCrossFieldInvariants(input: CrossFieldInput): void {
  const fileMetadata: DigestibleClosureFile[] = input.closure.files.map((file) => ({
    bytes: file.bytes.value,
    path: file.path.value,
    sha256: file.sha256.value,
  }));
  const filePaths = fileMetadata.map((file) => file.path);
  validateTotalBytes(input, fileMetadata);
  const observedDigest = validateObservation(input, fileMetadata, filePaths);
  const coverage = requiredCoverageClaims(input.coverage, input.label);
  const closureComplete = validateClosureState(input, coverage.closure, filePaths);
  validateContentIdentity(input, fileMetadata, filePaths, closureComplete);
  const manifestComplete = validateManifestState(input, coverage.manifest);
  validateDeferredCoverage(input.label, coverage);
  validateCompleteness(input, closureComplete, manifestComplete);
  validateSnapshotIdentity(input, observedDigest);
}

function validateTotalBytes(
  input: CrossFieldInput,
  fileMetadata: readonly DigestibleClosureFile[],
): void {
  const totalBytes = fileMetadata.reduce((total, file) => {
    const next = total + file.bytes;
    if (!Number.isSafeInteger(next) || next > MAX_TOTAL_BYTES) {
      invalid(`${input.label}.closure.totalBytes`, "exceeds the aggregate byte limit");
    }
    return next;
  }, 0);
  if (input.closure.totalBytes.value !== totalBytes) {
    invalid(`${input.label}.closure.totalBytes.value`, "does not match the closure file total");
  }
}

function validateObservation(
  input: CrossFieldInput,
  fileMetadata: readonly DigestibleClosureFile[],
  filePaths: readonly string[],
): string {
  const observedDigest = artifactDigest(OBSERVATION_DOMAIN, fileMetadata);
  if (input.closure.observedSha256.value !== observedDigest) {
    invalid(
      `${input.label}.closure.observedSha256.value`,
      "does not match the closure observation",
    );
  }
  assertValueClaimShape(input.closure.observedSha256, `${input.label}.closure.observedSha256`, {
    evidence: filePaths,
    source: "observed",
    state: "resolved",
  });
  if (input.closure.observedSha256.redacted !== undefined) {
    invalid(`${input.label}.closure.observedSha256`, "must not be marked redacted");
  }
  return observedDigest;
}

function requiredCoverageClaims(
  coverage: readonly ArtifactCoverage[],
  label: string,
): RequiredCoverageClaims {
  const byArea = new Map(coverage.map((entry) => [entry.area, entry.claim]));
  return {
    capability: requireCoverageClaim(byArea, "capability-normalization", label),
    closure: requireCoverageClaim(byArea, "artifact-closure", label),
    harness: requireCoverageClaim(byArea, "harness-permissions", label),
    manifest: requireCoverageClaim(byArea, "manifest-metadata", label),
  };
}

function requireCoverageClaim(
  coverage: ReadonlyMap<CoverageArea, ArtifactClaim<string>>,
  area: CoverageArea,
  label: string,
): ArtifactClaim<string> {
  const claim = coverage.get(area);
  if (claim === undefined) {
    invalid(`${label}.coverage`, "is missing a required area");
  }
  return claim;
}

function validateClosureState(
  input: CrossFieldInput,
  closureCoverage: ArtifactClaim<string>,
  filePaths: readonly string[],
): boolean {
  if (!isValueClaim(closureCoverage)) {
    invalid(`${input.label}.coverage`, "artifact-closure must be a value claim");
  }
  const closureComplete = closureCoverage.state === "resolved";
  if (!closureComplete && closureCoverage.state !== "unresolved") {
    invalid(`${input.label}.coverage`, "artifact-closure must be resolved or unresolved");
  }
  const hasClosureError = input.diagnostics.some(
    (diagnostic) => diagnostic.type === "error" && diagnostic.code.startsWith("ARTIFACT_"),
  );
  if (closureComplete === hasClosureError) {
    invalid(`${input.label}.coverage.artifact-closure`, "does not match artifact diagnostic state");
  }
  assertValueClaimShape(closureCoverage, `${input.label}.coverage.artifact-closure`, {
    evidence: filePaths,
    source: "observed",
    state: closureComplete ? "resolved" : "unresolved",
  });
  assertValueClaimShape(input.closure.totalBytes, `${input.label}.closure.totalBytes`, {
    evidence: filePaths,
    source: "observed",
    state: closureComplete ? "resolved" : "unresolved",
  });
  if (input.closure.totalBytes.redacted !== undefined) {
    invalid(`${input.label}.closure.totalBytes`, "must not be marked redacted");
  }
  return closureComplete;
}

function validateContentIdentity(
  input: CrossFieldInput,
  fileMetadata: readonly DigestibleClosureFile[],
  filePaths: readonly string[],
  closureComplete: boolean,
): void {
  const contentDigest = artifactDigest(CONTENT_DOMAIN, fileMetadata);
  const contentClaim = input.artifact.identity.contentSha256;
  if (closureComplete) {
    if (!isValueClaim(contentClaim) || contentClaim.value !== contentDigest) {
      invalid(
        `${input.label}.artifact.identity.contentSha256`,
        "must resolve to the recomputed complete-closure digest",
      );
    }
    assertValueClaimShape(contentClaim, `${input.label}.artifact.identity.contentSha256`, {
      evidence: filePaths,
      source: "observed",
      state: "resolved",
    });
    if (contentClaim.redacted !== undefined) {
      invalid(`${input.label}.artifact.identity.contentSha256`, "must not be marked redacted");
    }
  } else {
    if (isValueClaim(contentClaim)) {
      invalid(
        `${input.label}.artifact.identity.contentSha256`,
        "must be unavailable while the closure is unresolved",
      );
    }
    assertAbsentClaimShape(contentClaim, `${input.label}.artifact.identity.contentSha256`, {
      evidence: [],
      source: "observed",
      state: "unavailable",
    });
  }
}

function validateManifestState(
  input: CrossFieldInput,
  manifestCoverage: ArtifactClaim<string>,
): boolean {
  const manifestObserved = input.closure.files.some((file) => file.path.value === "SKILL.md");
  if ((input.artifact.manifest.path.state === "resolved") !== manifestObserved) {
    invalid(`${input.label}.artifact.manifest.path`, "does not match the observed closure");
  }
  const manifestComplete = isValueClaim(manifestCoverage) && manifestCoverage.state === "resolved";
  if (manifestComplete) {
    assertValueClaimShape(manifestCoverage, `${input.label}.coverage.manifest-metadata`, {
      evidence: ["SKILL.md"],
      source: "declared",
      state: "resolved",
    });
    if (
      !isValueClaim(input.artifact.manifest.name) ||
      !isValueClaim(input.artifact.manifest.description) ||
      input.artifact.manifest.path.state !== "resolved"
    ) {
      invalid(`${input.label}.artifact.manifest`, "does not match resolved manifest coverage");
    }
  } else {
    if (isValueClaim(manifestCoverage)) {
      invalid(`${input.label}.coverage.manifest-metadata`, "must be resolved or unavailable");
    }
    assertAbsentClaimShape(manifestCoverage, `${input.label}.coverage.manifest-metadata`, {
      evidence: [],
      source: "observed",
      state: "unavailable",
    });
    if (
      isValueClaim(input.artifact.manifest.name) ||
      isValueClaim(input.artifact.manifest.description)
    ) {
      invalid(`${input.label}.artifact.manifest`, "does not match unavailable manifest coverage");
    }
  }
  validateManifestDiagnosticState(input, manifestComplete);
  return manifestComplete;
}

function validateManifestDiagnosticState(input: CrossFieldInput, manifestComplete: boolean): void {
  const manifestErrors = input.diagnostics.filter(
    (diagnostic) => diagnostic.type === "error" && diagnostic.code.startsWith("SKILL_"),
  );
  if ((manifestErrors.length === 0) !== manifestComplete || manifestErrors.length > 1) {
    invalid(`${input.label}.coverage.manifest-metadata`, "does not match skill diagnostic state");
  }
  const diagnostic = manifestErrors[0];
  if (
    (diagnostic?.code === "SKILL_MANIFEST_MISSING" &&
      input.artifact.manifest.path.state !== "unresolved") ||
    (diagnostic?.code === "SKILL_MANIFEST_INVALID" &&
      input.artifact.manifest.path.state !== "resolved")
  ) {
    invalid(`${input.label}.artifact.manifest.path`, "does not match its skill diagnostic code");
  }
}

function validateDeferredCoverage(inputLabel: string, coverage: RequiredCoverageClaims): void {
  assertAbsentClaimShape(coverage.capability, `${inputLabel}.coverage.capability-normalization`, {
    evidence: [],
    source: "inferred",
    state: "unsupported",
  });
  assertAbsentClaimShape(coverage.harness, `${inputLabel}.coverage.harness-permissions`, {
    evidence: [],
    source: "inferred",
    state: "unavailable",
  });
}

function validateCompleteness(
  input: CrossFieldInput,
  closureComplete: boolean,
  manifestComplete: boolean,
): void {
  const hasErrors = input.diagnostics.some((diagnostic) => diagnostic.type === "error");
  const expectedComplete = closureComplete && manifestComplete && !hasErrors;
  if (input.complete !== expectedComplete) {
    invalid(`${input.label}.complete`, "does not match closure, manifest, and diagnostic state");
  }
}

function validateSnapshotIdentity(input: CrossFieldInput, observedDigest: string): void {
  const context =
    input.artifact.repository === undefined
      ? ""
      : `${input.artifact.repository.url.value}\0${input.artifact.repository.commit.value}`;
  const expectedId = snapshotId({
    adapterVersion: input.artifact.adapter.version,
    analyzerVersion: input.snapshot.analyzer.version,
    context,
    diagnostics: input.diagnostics,
    observationSha256: observedDigest,
  });
  if (input.snapshot.id !== expectedId) {
    invalid(`${input.label}.snapshot.id`, "does not match the recomputed snapshot identity");
  }
}

function parseClaim(
  value: unknown,
  location: string,
  options: { readonly kind: "digest" } | { readonly kind: "string"; readonly maximum: number },
): ArtifactClaim<string> {
  if (isObject(value) && (value.state === "unavailable" || value.state === "unsupported")) {
    return parseAbsentClaim(value, location);
  }
  return parseValueClaim(value, location, (candidate, nested) =>
    options.kind === "digest"
      ? parseDigest(candidate, nested)
      : boundedString(candidate, nested, 0, options.maximum),
  );
}

function parseAbsentClaim(value: unknown, location: string): ArtifactAbsentClaim {
  const object = exactObject(value, location, ["evidence", "reason", "source", "state"]);
  const evidence = parseEvidence(object.evidence, `${location}.evidence`);
  const reason = boundedString(object.reason, `${location}.reason`, 1, MAX_REASON_CHARACTERS);
  const source = parseEvidenceSource(object.source, `${location}.source`);
  if (object.state !== "unavailable" && object.state !== "unsupported") {
    invalid(`${location}.state`, "must be unavailable or unsupported for an absent claim");
  }
  return { evidence, reason, source, state: object.state };
}

function parseValueClaim<T>(
  value: unknown,
  location: string,
  parseValue: (candidate: unknown, location: string) => T,
): ArtifactValueClaim<T> {
  const object = exactObject(
    value,
    location,
    ["evidence", "source", "state", "value"],
    ["redacted"],
  );
  const evidence = parseEvidence(object.evidence, `${location}.evidence`);
  const source = parseEvidenceSource(object.source, `${location}.source`);
  if (
    object.state !== "endpoint-unverified" &&
    object.state !== "mutable" &&
    object.state !== "resolved" &&
    object.state !== "unresolved"
  ) {
    invalid(`${location}.state`, "is not a supported value-claim state");
  }
  if (object.redacted !== undefined && object.redacted !== true) {
    invalid(`${location}.redacted`, "must be true when present");
  }
  return {
    evidence,
    ...(object.redacted === true ? { redacted: true as const } : {}),
    source,
    state: object.state,
    value: parseValue(object.value, `${location}.value`),
  };
}

function parseEvidence(value: unknown, location: string): ArtifactEvidenceReference[] {
  const candidates = boundedArray(value, location, MAX_EVIDENCE);
  const evidence: ArtifactEvidenceReference[] = [];
  let previousPath: string | undefined;
  for (let index = 0; index < candidates.length; index += 1) {
    const nested = `${location}[${index.toString()}]`;
    const object = exactObject(candidates[index], nested, ["path"]);
    const evidencePath = parseArtifactPath(object.path, `${nested}.path`);
    if (previousPath !== undefined && compareCodeUnits(previousPath, evidencePath) >= 0) {
      invalid(location, "must be strictly sorted and contain no duplicate paths");
    }
    previousPath = evidencePath;
    evidence.push({ path: evidencePath });
  }
  return evidence;
}

function assertValueClaimShape(
  claim: ArtifactValueClaim<unknown>,
  location: string,
  expected: {
    readonly evidence: readonly string[];
    readonly source: ArtifactEvidenceSource;
    readonly state: ArtifactValueClaim<unknown>["state"];
  },
): void {
  if (
    claim.source !== expected.source ||
    claim.state !== expected.state ||
    !sameEvidence(claim.evidence, expected.evidence)
  ) {
    invalid(location, "has evidence, source, or state inconsistent with its field");
  }
}

function assertAbsentClaimShape(
  claim: ArtifactClaim<unknown>,
  location: string,
  expected: {
    readonly evidence: readonly string[];
    readonly source: ArtifactEvidenceSource;
    readonly state: ArtifactAbsentClaim["state"];
  },
): asserts claim is ArtifactAbsentClaim {
  if (
    isValueClaim(claim) ||
    claim.source !== expected.source ||
    claim.state !== expected.state ||
    !sameEvidence(claim.evidence, expected.evidence)
  ) {
    invalid(location, "has evidence, source, or state inconsistent with its field");
  }
}

function sameEvidence(
  evidence: readonly ArtifactEvidenceReference[],
  expected: readonly string[],
): boolean {
  return (
    evidence.length === expected.length &&
    evidence.every((reference, index) => reference.path === expected[index])
  );
}

function isValueClaim<T>(claim: ArtifactClaim<T>): claim is ArtifactValueClaim<T> {
  return "value" in claim;
}

function parseEvidenceSource(value: unknown, location: string): ArtifactEvidenceSource {
  if (typeof value !== "string" || !EVIDENCE_SOURCES.has(value as ArtifactEvidenceSource)) {
    invalid(location, "is not a supported evidence source");
  }
  return value as ArtifactEvidenceSource;
}

function parseTrue(value: unknown, location: string): true {
  if (value !== true) {
    invalid(location, "must be true");
  }
  return true;
}

function parseManifestPath(value: unknown, location: string): "SKILL.md" {
  const parsed = parseArtifactPath(value, location);
  if (parsed !== "SKILL.md") {
    invalid(location, "must be SKILL.md");
  }
  return "SKILL.md";
}

function parseDiagnosticCode(value: unknown, location: string): ArtifactDiagnosticCode {
  if (typeof value !== "string" || !DIAGNOSTIC_CODES.has(value as ArtifactDiagnosticCode)) {
    invalid(location, "is not a recognized artifact diagnostic code");
  }
  return value as ArtifactDiagnosticCode;
}

function parseDigest(value: unknown, location: string): string {
  const digest = boundedString(value, location, 64, 64);
  if (!DIGEST_PATTERN.test(digest)) {
    invalid(location, "must be a lower-case SHA-256 digest");
  }
  return digest;
}

function parseArtifactPath(value: unknown, location: string): string {
  if (
    typeof value !== "string" ||
    value.length > MAX_PATH_CHARACTERS ||
    !isSafeArtifactReportPath(value)
  ) {
    invalid(location, "must be a normalized portable relative artifact path");
  }
  return value;
}

function boundedString(value: unknown, location: string, minimum: number, maximum: number): string {
  if (
    typeof value !== "string" ||
    value.length < minimum ||
    value.length > maximum ||
    !isWellFormedUnicode(value) ||
    containsUnsafeArtifactText(value) ||
    redactEvidence(value) !== value
  ) {
    invalid(
      location,
      `must be a safe redacted string between ${minimum.toString()} and ${maximum.toString()} characters`,
    );
  }
  return value;
}

function safeInteger(
  value: unknown,
  location: string,
  minimum: number,
  maximum = Number.MAX_SAFE_INTEGER,
): number {
  if (!Number.isSafeInteger(value) || (value as number) < minimum || (value as number) > maximum) {
    invalid(
      location,
      `must be a safe integer between ${minimum.toString()} and ${maximum.toString()}`,
    );
  }
  return value as number;
}

function boundedArray(value: unknown, location: string, maximum: number, minimum = 0): unknown[] {
  if (!Array.isArray(value) || value.length < minimum || value.length > maximum) {
    invalid(
      location,
      `must be an array with ${minimum.toString()} to ${maximum.toString()} entries`,
    );
  }
  return value;
}

function exactObject(
  value: unknown,
  location: string,
  required: readonly string[],
  optional: readonly string[] = [],
): JsonObject {
  if (!isObject(value)) {
    invalid(location, "must be an object");
  }
  const allowed = new Set([...required, ...optional]);
  for (const key of Object.keys(value)) {
    if (!allowed.has(key)) {
      invalid(location, "contains an unknown field");
    }
  }
  for (const key of required) {
    if (!Object.hasOwn(value, key)) {
      invalid(location, `is missing required field ${JSON.stringify(key)}`);
    }
  }
  return value;
}

function isObject(value: unknown): value is JsonObject {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function expectLiteral<T extends string>(value: unknown, expected: T, location: string): T {
  if (value !== expected) {
    invalid(location, `must be ${JSON.stringify(expected)}`);
  }
  return expected;
}

function isCoverageArea(value: unknown): value is CoverageArea {
  return typeof value === "string" && (COVERAGE_AREAS as readonly string[]).includes(value);
}

function validIsoTimestamp(value: string): boolean {
  const timestamp = Date.parse(value);
  return Number.isFinite(timestamp) && new Date(timestamp).toISOString() === value;
}

function normalizeRepository(
  commit: string,
  rawUrl: string,
  location: string,
): { readonly commit: string; readonly url: string } {
  if (!/^(?:[a-f0-9]{40}|[a-f0-9]{64})$/.test(commit)) {
    invalid(`${location}.commit.value`, "must be a complete lower-case Git commit hash");
  }
  let url: URL;
  try {
    url = new URL(rawUrl);
  } catch {
    invalid(`${location}.url.value`, "must be a valid HTTPS URL");
  }
  if (
    url.protocol !== "https:" ||
    url.username.length > 0 ||
    url.password.length > 0 ||
    url.search.length > 0 ||
    url.hash.length > 0
  ) {
    invalid(
      `${location}.url.value`,
      "must be a credential-free HTTPS URL without query or fragment",
    );
  }
  return { commit, url: url.href.replace(/\/$/, "") };
}

function artifactDigest(domain: Buffer, files: readonly DigestibleClosureFile[]): string {
  const hash = createHash("sha256").update(domain);
  updateLengthPrefixed(hash, "skill");
  for (const file of files) {
    updateLengthPrefixed(hash, file.path);
    updateUnsignedLength(hash, file.bytes);
    hash.update(Buffer.from(file.sha256, "hex"));
  }
  return hash.digest("hex");
}

function snapshotId(input: {
  readonly adapterVersion: string;
  readonly analyzerVersion: string;
  readonly context: string;
  readonly diagnostics: readonly ArtifactDiagnostic[];
  readonly observationSha256: string;
}): string {
  const hash = createHash("sha256").update(SNAPSHOT_DOMAIN);
  updateLengthPrefixed(hash, input.adapterVersion);
  updateLengthPrefixed(hash, input.analyzerVersion);
  updateLengthPrefixed(hash, input.context);
  updateLengthPrefixed(hash, input.observationSha256);
  updateLengthPrefixed(
    hash,
    JSON.stringify(
      input.diagnostics.map((diagnostic) => ({
        code: diagnostic.code,
        ...(diagnostic.file === undefined ? {} : { file: diagnostic.file }),
        type: diagnostic.type,
      })),
    ),
  );
  return hash.digest("hex").slice(0, 24);
}

function updateLengthPrefixed(hash: ReturnType<typeof createHash>, value: string): void {
  const bytes = Buffer.from(value, "utf8");
  updateUnsignedLength(hash, bytes.byteLength);
  hash.update(bytes);
}

function updateUnsignedLength(hash: ReturnType<typeof createHash>, value: number): void {
  const length = Buffer.alloc(8);
  length.writeBigUInt64BE(BigInt(value));
  hash.update(length);
}

function compareDiagnostics(left: ArtifactDiagnostic, right: ArtifactDiagnostic): number {
  return (
    compareCodeUnits(left.file ?? "", right.file ?? "") ||
    compareCodeUnits(left.code, right.code) ||
    compareCodeUnits(left.type, right.type) ||
    compareCodeUnits(left.message, right.message)
  );
}

function invalid(location: string, reason: string): never {
  throw new Error(`${location} ${reason}.`);
}

function validateJsonStructure(serialized: string, label: string): void {
  try {
    new JsonStructureValidator(serialized).validate();
  } catch (error) {
    if (error instanceof JsonStructureError && error.kind === "duplicate") {
      throw new Error(`${label} contains a duplicate JSON object key.`);
    }
    if (error instanceof JsonStructureError && error.kind === "depth") {
      throw new Error(
        `${label} exceeds the ${MAX_JSON_DEPTH.toString()}-level JSON nesting limit.`,
      );
    }
    if (error instanceof JsonStructureError && error.kind === "values") {
      throw new Error(`${label} exceeds the ${MAX_JSON_VALUES.toString()}-value JSON limit.`);
    }
    throw new Error(`${label} is not valid JSON.`);
  }
}

class JsonStructureError extends Error {
  constructor(readonly kind: "depth" | "duplicate" | "syntax" | "values") {
    super(kind);
  }
}

class JsonStructureValidator {
  private index = 0;
  private values = 0;

  constructor(private readonly source: string) {}

  validate(): void {
    this.skipWhitespace();
    this.parseValue(0);
    this.skipWhitespace();
    if (this.index !== this.source.length) {
      throw new JsonStructureError("syntax");
    }
  }

  private parseValue(depth: number): void {
    if (depth > MAX_JSON_DEPTH) {
      throw new JsonStructureError("depth");
    }
    this.values += 1;
    if (this.values > MAX_JSON_VALUES) {
      throw new JsonStructureError("values");
    }
    const character = this.source[this.index];
    if (character === "{") {
      this.parseObject(depth);
    } else if (character === "[") {
      this.parseArray(depth);
    } else if (character === '"') {
      this.parseString();
    } else if (character === "t") {
      this.consumeLiteral("true");
    } else if (character === "f") {
      this.consumeLiteral("false");
    } else if (character === "n") {
      this.consumeLiteral("null");
    } else {
      this.parseNumber();
    }
  }

  private parseObject(depth: number): void {
    this.index += 1;
    this.skipWhitespace();
    if (this.source[this.index] === "}") {
      this.index += 1;
      return;
    }
    const keys = new Set<string>();
    while (this.index < this.source.length) {
      if (this.source[this.index] !== '"') {
        throw new JsonStructureError("syntax");
      }
      const key = this.parseString();
      if (keys.has(key)) {
        throw new JsonStructureError("duplicate");
      }
      keys.add(key);
      this.skipWhitespace();
      if (this.source[this.index] !== ":") {
        throw new JsonStructureError("syntax");
      }
      this.index += 1;
      this.skipWhitespace();
      this.parseValue(depth + 1);
      this.skipWhitespace();
      const delimiter = this.source[this.index];
      this.index += 1;
      if (delimiter === "}") {
        return;
      }
      if (delimiter !== ",") {
        throw new JsonStructureError("syntax");
      }
      this.skipWhitespace();
    }
    throw new JsonStructureError("syntax");
  }

  private parseArray(depth: number): void {
    this.index += 1;
    this.skipWhitespace();
    if (this.source[this.index] === "]") {
      this.index += 1;
      return;
    }
    while (this.index < this.source.length) {
      this.parseValue(depth + 1);
      this.skipWhitespace();
      const delimiter = this.source[this.index];
      this.index += 1;
      if (delimiter === "]") {
        return;
      }
      if (delimiter !== ",") {
        throw new JsonStructureError("syntax");
      }
      this.skipWhitespace();
    }
    throw new JsonStructureError("syntax");
  }

  private parseString(): string {
    const start = this.index;
    this.index += 1;
    while (this.index < this.source.length) {
      const character = this.source[this.index];
      if (character === '"') {
        return this.decodeString(start);
      }
      if (character === "\\") {
        this.consumeStringEscape();
        continue;
      }
      if (character === undefined || character.charCodeAt(0) <= 0x1f) {
        throw new JsonStructureError("syntax");
      }
      this.index += 1;
    }
    throw new JsonStructureError("syntax");
  }

  private decodeString(start: number): string {
    this.index += 1;
    try {
      const decoded = JSON.parse(this.source.slice(start, this.index)) as unknown;
      if (typeof decoded !== "string") {
        throw new JsonStructureError("syntax");
      }
      return decoded;
    } catch (error) {
      if (error instanceof JsonStructureError) {
        throw error;
      }
      throw new JsonStructureError("syntax");
    }
  }

  private consumeStringEscape(): void {
    this.index += 1;
    const escapeCode = this.source[this.index];
    if (escapeCode === "u") {
      const hexadecimal = this.source.slice(this.index + 1, this.index + 5);
      if (!/^[a-fA-F0-9]{4}$/.test(hexadecimal)) {
        throw new JsonStructureError("syntax");
      }
      this.index += 5;
      return;
    }
    if (escapeCode === undefined || !'"\\/bfnrt'.includes(escapeCode)) {
      throw new JsonStructureError("syntax");
    }
    this.index += 1;
  }

  private parseNumber(): void {
    if (this.source[this.index] === "-") {
      this.index += 1;
    }
    if (this.source[this.index] === "0") {
      this.index += 1;
    } else if (this.isDigitFromOneToNine(this.source[this.index])) {
      this.consumeDigits();
    } else {
      throw new JsonStructureError("syntax");
    }
    if (this.source[this.index] === ".") {
      this.index += 1;
      this.requireDigit();
      this.consumeDigits();
    }
    if (this.source[this.index] === "e" || this.source[this.index] === "E") {
      this.index += 1;
      if (this.source[this.index] === "+" || this.source[this.index] === "-") {
        this.index += 1;
      }
      this.requireDigit();
      this.consumeDigits();
    }
  }

  private consumeDigits(): void {
    while (this.isDigit(this.source[this.index])) {
      this.index += 1;
    }
  }

  private requireDigit(): void {
    if (!this.isDigit(this.source[this.index])) {
      throw new JsonStructureError("syntax");
    }
  }

  private isDigit(character: string | undefined): boolean {
    return character !== undefined && character >= "0" && character <= "9";
  }

  private isDigitFromOneToNine(character: string | undefined): boolean {
    return character !== undefined && character >= "1" && character <= "9";
  }

  private consumeLiteral(literal: string): void {
    if (!this.source.startsWith(literal, this.index)) {
      throw new JsonStructureError("syntax");
    }
    this.index += literal.length;
  }

  private skipWhitespace(): void {
    while (
      this.source[this.index] === " " ||
      this.source[this.index] === "\t" ||
      this.source[this.index] === "\r" ||
      this.source[this.index] === "\n"
    ) {
      this.index += 1;
    }
  }
}
