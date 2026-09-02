import { Buffer } from "node:buffer";
import { createHash } from "node:crypto";
import type { Dirent, Stats } from "node:fs";
import { lstat, open, opendir, realpath } from "node:fs/promises";
import path from "node:path";
import { compareCodeUnits } from "../order.js";
import { boundedRedactedEvidence, redactEvidence } from "../redact.js";
import { sameOpenedFileSnapshot, samePathAndOpenedFileSnapshot } from "../scanner/files.js";
import { artifactContentSha256, artifactObservationSha256 } from "./digest.js";
import type {
  ArtifactDiagnostic,
  ArtifactDiagnosticCode,
  ArtifactSnapshotOptions,
} from "./domain.js";
import { MAX_ARTIFACT_DIAGNOSTICS, MAX_ARTIFACT_TARGET_CHARACTERS } from "./domain.js";
import { isPortableArtifactPath, isSafeArtifactReportPath } from "./path.js";

const CONTROL_DIRECTORIES = new Set([".git", ".hg", ".svn"]);
const GIT_LFS_POINTER_VERSION = "version https://git-lfs.github.com/spec/v1";
const MAX_GIT_LFS_POINTER_BYTES = 8_192;
const DEFAULT_MAX_FILE_BYTES = 10_000_000;
const DEFAULT_MAX_FILES = 1_000;
const DEFAULT_MAX_TOTAL_BYTES = 50_000_000;
const MAX_DIRECTORIES = 2_000;
const MAX_DEPTH = 64;
const MAX_CONFIGURED_FILE_BYTES = 100_000_000;
const MAX_CONFIGURED_FILES = 10_000;
const MAX_CONFIGURED_TOTAL_BYTES = 250_000_000;

export interface DiscoveredArtifactFile {
  readonly bytes: Buffer;
  readonly relativePath: string;
  readonly sha256: string;
}

export interface ArtifactDiscoveryResult {
  readonly complete: boolean;
  readonly contentSha256?: string;
  readonly diagnostics: readonly ArtifactDiagnostic[];
  readonly files: readonly DiscoveredArtifactFile[];
  readonly observedSha256: string;
  readonly root: string;
  readonly target: string;
  readonly totalBytes: number;
}

interface DiscoveryLimits {
  readonly maxEntries: number;
  readonly maxFileBytes: number;
  readonly maxFiles: number;
  readonly maxTotalBytes: number;
}

interface MutableDiscoveryState {
  complete: boolean;
  directoriesSeen: number;
  readonly diagnostics: ArtifactDiagnostic[];
  entriesSeen: number;
  readonly files: DiscoveredArtifactFile[];
  filesSeen: number;
  readonly limits: DiscoveryLimits;
  readonly root: string;
  stop: boolean;
  totalBytes: number;
}

interface StableReadResult {
  readonly bytes: Buffer;
  readonly exceeded: boolean;
}

interface DirectorySnapshot {
  readonly canonicalPath: string;
  readonly metadata: Stats;
}

interface DirectoryEnumeration {
  readonly entries: readonly Dirent[];
  readonly snapshot: DirectorySnapshot;
}

export async function discoverSkillArtifact(
  requestedTarget: string,
  options: ArtifactSnapshotOptions = {},
): Promise<ArtifactDiscoveryResult> {
  const root = await resolveSkillRoot(requestedTarget);
  const rootSnapshot = await captureDirectorySnapshot(root, root);
  if (rootSnapshot === undefined) {
    throw new Error("Skill root must resolve to a stable regular directory.");
  }

  const state: MutableDiscoveryState = {
    complete: true,
    directoriesSeen: 1,
    diagnostics: [],
    entriesSeen: 0,
    files: [],
    filesSeen: 0,
    limits: normalizeLimits(options),
    root,
    stop: false,
    totalBytes: 0,
  };
  await walkDirectory(root, state, rootSnapshot);
  state.files.sort((left, right) => compareCodeUnits(left.relativePath, right.relativePath));

  const observedSha256 = artifactObservationSha256("skill", state.files);
  return {
    complete: state.complete,
    ...(state.complete ? { contentSha256: artifactContentSha256("skill", state.files) } : {}),
    diagnostics: state.diagnostics,
    files: state.files,
    observedSha256,
    root,
    target: artifactDisplayTarget(root),
    totalBytes: state.totalBytes,
  };
}

export function artifactDisplayTarget(root: string): string {
  return boundedRedactedEvidence(
    path.basename(root) || path.parse(root).root,
    MAX_ARTIFACT_TARGET_CHARACTERS,
    "",
  );
}

export async function resolveSkillRoot(requestedTarget: string): Promise<string> {
  const requested = path.resolve(requestedTarget);
  const requestedMetadata = await lstat(requested);
  if (requestedMetadata.isSymbolicLink()) {
    throw new Error("Skill target must not be a symbolic link or junction.");
  }

  let root: string;
  if (requestedMetadata.isDirectory()) {
    root = await realpath(requested);
  } else if (requestedMetadata.isFile() && path.basename(requested) === "SKILL.md") {
    root = await realpath(path.dirname(requested));
  } else {
    throw new Error("Skill target must be a directory or a file named SKILL.md.");
  }

  const canonicalRootMetadata = await lstat(root);
  if (!canonicalRootMetadata.isDirectory() || canonicalRootMetadata.isSymbolicLink()) {
    throw new Error("Skill root must resolve to a regular directory.");
  }
  return root;
}

function normalizeLimits(options: ArtifactSnapshotOptions): DiscoveryLimits {
  const maxFiles = boundedPositiveInteger(
    options.maxFiles ?? DEFAULT_MAX_FILES,
    "maxFiles",
    MAX_CONFIGURED_FILES,
  );
  return {
    maxEntries: maxFiles + MAX_DIRECTORIES,
    maxFileBytes: boundedPositiveInteger(
      options.maxFileBytes ?? DEFAULT_MAX_FILE_BYTES,
      "maxFileBytes",
      MAX_CONFIGURED_FILE_BYTES,
    ),
    maxFiles,
    maxTotalBytes: boundedPositiveInteger(
      options.maxTotalBytes ?? DEFAULT_MAX_TOTAL_BYTES,
      "maxTotalBytes",
      MAX_CONFIGURED_TOTAL_BYTES,
    ),
  };
}

function boundedPositiveInteger(value: number, label: string, maximum: number): number {
  if (!Number.isSafeInteger(value) || value < 1 || value > maximum) {
    throw new Error(
      `${label} must be a positive safe integer no greater than ${maximum.toString()}.`,
    );
  }
  return value;
}

async function walkDirectory(
  directory: string,
  state: MutableDiscoveryState,
  expectedSnapshot: DirectorySnapshot,
): Promise<void> {
  const enumeration = await enumerateDirectory(directory, state, expectedSnapshot);
  if (enumeration === undefined) {
    return;
  }
  for (const entry of enumeration.entries) {
    if (state.stop) {
      return;
    }
    if (!(await directoryMatchesSnapshot(directory, state.root, enumeration.snapshot))) {
      state.stop = true;
      recordError(
        state,
        diagnosticPath(state.root, directory),
        "ARTIFACT_DIRECTORY_CHANGED",
        "Artifact directory changed while its entries were being processed.",
      );
      return;
    }
    await visitEntry(directory, entry, state, enumeration.snapshot);
  }
  if (!(await directoryMatchesSnapshot(directory, state.root, enumeration.snapshot))) {
    state.stop = true;
    recordError(
      state,
      diagnosticPath(state.root, directory),
      "ARTIFACT_DIRECTORY_CHANGED",
      "Artifact directory changed while its descendants were being processed.",
    );
  }
}

async function enumerateDirectory(
  directory: string,
  state: MutableDiscoveryState,
  expectedSnapshot: DirectorySnapshot,
): Promise<DirectoryEnumeration | undefined> {
  const before = await captureDirectorySnapshot(directory, state.root);
  if (before === undefined || !sameDirectorySnapshot(before, expectedSnapshot)) {
    recordError(
      state,
      diagnosticPath(state.root, directory),
      "ARTIFACT_DIRECTORY_CHANGED",
      "Artifact directory changed before it could be safely enumerated.",
    );
    return undefined;
  }

  try {
    const handle = await opendir(directory, { bufferSize: 32 });
    const remainingEntries = state.limits.maxEntries - state.entriesSeen;
    const collected = await collectBoundedEntries(handle, remainingEntries);
    if (collected.overflow) {
      state.stop = true;
      recordError(
        state,
        diagnosticPath(state.root, directory),
        "ARTIFACT_ENTRY_LIMIT",
        `Artifact entry limit exceeded (${state.limits.maxEntries.toString()} encountered entries).`,
      );
      return undefined;
    }

    const after = await captureDirectorySnapshot(directory, state.root);
    if (after === undefined || !sameDirectorySnapshot(before, after)) {
      state.stop = true;
      recordError(
        state,
        diagnosticPath(state.root, directory),
        "ARTIFACT_DIRECTORY_CHANGED",
        "Artifact directory changed while it was being enumerated.",
      );
      return undefined;
    }
    state.entriesSeen += collected.entries.length;
    collected.entries.sort((left, right) => compareCodeUnits(left.name, right.name));
    return { entries: collected.entries, snapshot: after };
  } catch {
    recordError(
      state,
      diagnosticPath(state.root, directory),
      "ARTIFACT_DIRECTORY_ENUMERATION_FAILED",
      "Could not safely enumerate an artifact directory.",
    );
    return undefined;
  }
}

export async function collectBoundedEntries<T>(
  source: AsyncIterable<T>,
  limit: number,
): Promise<{ readonly entries: T[]; readonly overflow: boolean }> {
  if (!Number.isSafeInteger(limit) || limit < 0) {
    throw new Error("Directory entry limit must be a non-negative safe integer.");
  }
  const entries: T[] = [];
  for await (const entry of source) {
    if (entries.length >= limit) {
      return { entries: [], overflow: true };
    }
    entries.push(entry);
  }
  return { entries, overflow: false };
}

async function visitEntry(
  directory: string,
  entry: Dirent,
  state: MutableDiscoveryState,
  parentSnapshot: DirectorySnapshot,
): Promise<void> {
  const absolutePath = path.join(directory, entry.name);
  const relativePath = normalizeRelativePath(path.relative(state.root, absolutePath));
  const pathError = artifactPathError(relativePath);
  if (pathError !== undefined) {
    recordError(state, undefined, pathError.code, pathError.message);
    return;
  }
  let metadata: Stats;
  try {
    metadata = await lstat(absolutePath);
  } catch {
    recordError(
      state,
      relativePath,
      "ARTIFACT_FILE_READ_FAILED",
      "Could not inspect an artifact entry after directory enumeration.",
    );
    return;
  }
  if (metadata.isSymbolicLink()) {
    recordError(
      state,
      relativePath,
      "ARTIFACT_SYMLINK_UNSUPPORTED",
      "Skipped symbolic link or junction; artifact closure is unresolved.",
    );
    return;
  }
  if (metadata.isDirectory()) {
    if (CONTROL_DIRECTORIES.has(entry.name)) {
      return;
    }
    const depth = relativePath.split("/").length;
    if (depth > MAX_DEPTH) {
      recordError(
        state,
        relativePath,
        "ARTIFACT_DIRECTORY_DEPTH_LIMIT",
        `Artifact directory depth exceeds the ${MAX_DEPTH.toString()}-level limit.`,
      );
      return;
    }
    if (state.directoriesSeen >= MAX_DIRECTORIES) {
      state.stop = true;
      recordError(
        state,
        relativePath,
        "ARTIFACT_DIRECTORY_LIMIT",
        `Artifact directory limit exceeded (${MAX_DIRECTORIES.toString()} directories).`,
      );
      return;
    }
    const childSnapshot = await captureDirectorySnapshot(absolutePath, state.root);
    if (childSnapshot === undefined) {
      recordError(
        state,
        relativePath,
        "ARTIFACT_DIRECTORY_CHANGED",
        "Artifact directory changed before descent or resolved outside the artifact root.",
      );
      return;
    }
    state.directoriesSeen += 1;
    await walkDirectory(childSnapshot.canonicalPath, state, childSnapshot);
    return;
  }
  if (!metadata.isFile()) {
    recordError(
      state,
      relativePath,
      "ARTIFACT_NON_REGULAR_ENTRY",
      "Skipped non-regular filesystem entry.",
    );
    return;
  }
  if (!reserveFileCandidate(relativePath, state)) {
    return;
  }
  try {
    await collectFile(absolutePath, relativePath, metadata, parentSnapshot, state);
  } catch {
    recordError(
      state,
      relativePath,
      "ARTIFACT_FILE_READ_FAILED",
      "Could not safely read a stable artifact file within the artifact root.",
    );
  }
}

async function collectFile(
  absolutePath: string,
  relativePath: string,
  expectedPathMetadata: Stats,
  parentSnapshot: DirectorySnapshot,
  state: MutableDiscoveryState,
): Promise<void> {
  const pathMetadata = await lstat(absolutePath);
  if (
    !pathMetadata.isFile() ||
    pathMetadata.isSymbolicLink() ||
    !sameOpenedFileSnapshot(expectedPathMetadata, pathMetadata)
  ) {
    throw new Error("Artifact entry changed before it could be read.");
  }
  const canonicalBefore = await realpath(absolutePath);
  if (!isWithinRoot(state.root, canonicalBefore)) {
    throw new Error("Artifact file resolved outside the artifact root.");
  }
  if (pathMetadata.size > state.limits.maxFileBytes) {
    recordError(
      state,
      relativePath,
      "ARTIFACT_FILE_SIZE_LIMIT",
      `Artifact file exceeds the ${state.limits.maxFileBytes.toString()}-byte per-file limit.`,
    );
    return;
  }
  if (state.totalBytes + pathMetadata.size > state.limits.maxTotalBytes) {
    state.stop = true;
    recordError(
      state,
      relativePath,
      "ARTIFACT_TOTAL_SIZE_LIMIT",
      `Artifact exceeds the ${state.limits.maxTotalBytes.toString()}-byte aggregate limit.`,
    );
    return;
  }

  const remaining = state.limits.maxTotalBytes - state.totalBytes;
  const readLimit = Math.min(state.limits.maxFileBytes, remaining);
  const read = await readStableRegularFile(absolutePath, pathMetadata, readLimit);
  if (read.exceeded) {
    const aggregateExceeded = remaining < state.limits.maxFileBytes;
    state.stop = aggregateExceeded;
    recordError(
      state,
      relativePath,
      aggregateExceeded ? "ARTIFACT_TOTAL_SIZE_LIMIT" : "ARTIFACT_FILE_SIZE_LIMIT",
      aggregateExceeded
        ? `Artifact exceeds the ${state.limits.maxTotalBytes.toString()}-byte aggregate limit.`
        : `Artifact file exceeds the ${state.limits.maxFileBytes.toString()}-byte per-file limit.`,
    );
    return;
  }
  if (isGitLfsPointer(read.bytes)) {
    recordError(
      state,
      relativePath,
      "ARTIFACT_LFS_POINTER_UNRESOLVED",
      "Skipped unresolved Git LFS pointer; materialize the artifact file before snapshotting.",
    );
    return;
  }
  const canonicalAfter = await realpath(absolutePath);
  if (
    normalizedAbsolutePath(canonicalAfter) !== normalizedAbsolutePath(canonicalBefore) ||
    !(await directoryMatchesSnapshot(path.dirname(absolutePath), state.root, parentSnapshot))
  ) {
    throw new Error("Artifact path changed while its file was being read.");
  }
  state.totalBytes += read.bytes.byteLength;
  state.files.push({
    bytes: read.bytes,
    relativePath,
    sha256: createHash("sha256").update(read.bytes).digest("hex"),
  });
}

function isGitLfsPointer(bytes: Buffer): boolean {
  if (bytes.byteLength > MAX_GIT_LFS_POINTER_BYTES) {
    return false;
  }
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    return false;
  }
  const lines = text
    .split(/\r?\n/)
    .filter((line, index, values) => line.length > 0 || index !== values.length - 1);
  if (lines[0] !== GIT_LFS_POINTER_VERSION) {
    return false;
  }
  let hasObjectId = false;
  let hasSize = false;
  for (const line of lines.slice(1)) {
    if (/^oid sha256:[a-f0-9]{64}$/.test(line)) {
      hasObjectId = true;
    } else if (/^size [0-9]+$/.test(line)) {
      hasSize = true;
    } else if (!/^ext-[0-9]+-[A-Za-z0-9.-]+ .+$/.test(line)) {
      return false;
    }
  }
  return hasObjectId && hasSize;
}

function reserveFileCandidate(relativePath: string, state: MutableDiscoveryState): boolean {
  if (state.filesSeen >= state.limits.maxFiles) {
    state.stop = true;
    recordError(
      state,
      relativePath,
      "ARTIFACT_ENTRY_LIMIT",
      `Artifact file limit exceeded (${state.limits.maxFiles.toString()} files).`,
    );
    return false;
  }
  state.filesSeen += 1;
  return true;
}

async function captureDirectorySnapshot(
  directory: string,
  root: string,
): Promise<DirectorySnapshot | undefined> {
  try {
    const before = await lstat(directory);
    if (!before.isDirectory() || before.isSymbolicLink()) {
      return undefined;
    }
    const canonicalPath = await realpath(directory);
    if (!isWithinRoot(root, canonicalPath)) {
      return undefined;
    }
    const after = await lstat(directory);
    if (!after.isDirectory() || after.isSymbolicLink() || !sameOpenedFileSnapshot(before, after)) {
      return undefined;
    }
    return { canonicalPath, metadata: after };
  } catch {
    return undefined;
  }
}

async function directoryMatchesSnapshot(
  directory: string,
  root: string,
  expected: DirectorySnapshot,
): Promise<boolean> {
  const current = await captureDirectorySnapshot(directory, root);
  return current !== undefined && sameDirectorySnapshot(current, expected);
}

function sameDirectorySnapshot(left: DirectorySnapshot, right: DirectorySnapshot): boolean {
  return (
    normalizedAbsolutePath(left.canonicalPath) === normalizedAbsolutePath(right.canonicalPath) &&
    sameOpenedFileSnapshot(left.metadata, right.metadata)
  );
}

function isWithinRoot(root: string, candidate: string): boolean {
  const normalizedRoot = normalizedAbsolutePath(root);
  const normalizedCandidate = normalizedAbsolutePath(candidate);
  const relative = path.relative(normalizedRoot, normalizedCandidate);
  return (
    relative.length === 0 ||
    (relative !== ".." && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative))
  );
}

function normalizedAbsolutePath(value: string): string {
  const resolved = path.resolve(value);
  return process.platform === "win32" ? resolved.toLocaleLowerCase("en-US") : resolved;
}

function diagnosticPath(root: string, candidate: string): string | undefined {
  const relative = normalizeRelativePath(path.relative(root, candidate));
  return isPortableArtifactPath(relative) ? relative : undefined;
}

async function readStableRegularFile(
  absolutePath: string,
  expected: Stats,
  maximumBytes: number,
): Promise<StableReadResult> {
  const handle = await open(absolutePath, "r");
  try {
    const opened = await handle.stat();
    if (!opened.isFile() || !samePathAndOpenedFileSnapshot(expected, opened)) {
      throw new Error("An artifact file changed while it was being opened.");
    }
    const chunks: Buffer[] = [];
    let total = 0;
    while (total <= maximumBytes) {
      const chunk = Buffer.allocUnsafe(Math.min(64 * 1024, maximumBytes + 1 - total));
      const { bytesRead } = await handle.read(chunk, 0, chunk.length, total);
      if (bytesRead === 0) {
        break;
      }
      chunks.push(chunk.subarray(0, bytesRead));
      total += bytesRead;
    }
    const afterRead = await handle.stat();
    const pathAfterRead = await lstat(absolutePath);
    if (
      !afterRead.isFile() ||
      !pathAfterRead.isFile() ||
      !sameOpenedFileSnapshot(opened, afterRead) ||
      !samePathAndOpenedFileSnapshot(pathAfterRead, opened)
    ) {
      throw new Error("An artifact file changed while it was being read.");
    }
    return { bytes: Buffer.concat(chunks, total), exceeded: total > maximumBytes };
  } finally {
    await handle.close();
  }
}

function recordError(
  state: MutableDiscoveryState,
  relativePath: string | undefined,
  code: ArtifactDiagnosticCode,
  message: string,
): void {
  state.complete = false;
  if (state.diagnostics.length >= MAX_ARTIFACT_DIAGNOSTICS) {
    return;
  }
  if (state.diagnostics.length === MAX_ARTIFACT_DIAGNOSTICS - 1) {
    state.diagnostics.push({
      code: "ARTIFACT_DIAGNOSTIC_LIMIT",
      message: `Artifact diagnostics were truncated at ${MAX_ARTIFACT_DIAGNOSTICS.toString()} entries.`,
      type: "error",
    });
    return;
  }
  state.diagnostics.push({
    code,
    ...(relativePath === undefined ? {} : { file: redactEvidence(relativePath) }),
    message,
    type: "error",
  });
}

function normalizeRelativePath(value: string): string {
  return path.sep === "\\" ? value.replaceAll("\\", "/") : value;
}

function artifactPathError(
  value: string,
): { readonly code: ArtifactDiagnosticCode; readonly message: string } | undefined {
  if (!isPortableArtifactPath(value)) {
    return {
      code: "ARTIFACT_NON_PORTABLE_PATH",
      message: "Skipped an entry with a non-portable artifact path.",
    };
  }
  return isSafeArtifactReportPath(value)
    ? undefined
    : {
        code: "ARTIFACT_SENSITIVE_PATH",
        message: "Skipped an entry whose path may contain sensitive data.",
      };
}
