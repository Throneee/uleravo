import { Buffer } from "node:buffer";
import { createHash } from "node:crypto";
import type { Dirent, Stats } from "node:fs";
import { lstat, open, readdir, realpath } from "node:fs/promises";
import path from "node:path";
import type { Diagnostic } from "../domain.js";
import { compareCodeUnits } from "../order.js";

const SOURCE_EXTENSIONS = new Set([".cjs", ".cts", ".js", ".jsx", ".mjs", ".mts", ".ts", ".tsx"]);
const TEXT_EXTENSIONS = new Set([".json", ".py", ".toml", ".yaml", ".yml"]);
const TEXT_FILENAMES = new Set([".gitmodules", "bun.lock", "yarn.lock"]);
const LOCKFILE_FILENAMES = new Set([
  "bun.lock",
  "bun.lockb",
  "npm-shrinkwrap.json",
  "package-lock.json",
  "pnpm-lock.yaml",
  "yarn.lock",
]);
const IGNORED_DIRECTORIES = new Set([
  ".git",
  ".hg",
  ".svn",
  ".turbo",
  ".wrangler",
  "build",
  "coverage",
  "dist",
  "node_modules",
  "out",
  "target",
  "vendor",
]);

const utf8Decoder = new TextDecoder("utf-8", { fatal: true });
const SCAN_INPUT_HASH_DOMAIN = Buffer.from("mirsad-scan-input-v1\0", "utf8");
const GIT_LFS_POINTER_VERSION = "version https://git-lfs.github.com/spec/v1";
const MAX_GIT_LFS_POINTER_BYTES = 8_192;

export type FileKind = "json" | "source" | "text";

export interface ScannableFile {
  readonly absolutePath: string;
  readonly kind: FileKind;
  readonly relativePath: string;
  readonly text: string;
}

export interface DiscoveryOptions {
  readonly excludePrefixes?: readonly string[];
  readonly maxFileBytes?: number;
  readonly maxFiles?: number;
  readonly maxTotalBytes?: number;
}

export interface DiscoveryResult {
  readonly contentHash: string;
  readonly diagnostics: readonly Diagnostic[];
  readonly files: readonly ScannableFile[];
  readonly lockfiles: readonly DiscoveredLockfile[];
  readonly root: string;
  readonly skipped: number;
  readonly target: string;
}

export interface DiscoveredLockfile {
  readonly path: string;
  readonly sha256?: string;
  readonly state: "hashed" | "size-limit";
}

interface MutableDiscoveryState {
  bytesCollected: number;
  candidatesSeen: number;
  readonly diagnostics: Diagnostic[];
  readonly files: ScannableFile[];
  readonly hash: ReturnType<typeof createHash>;
  readonly lockfiles: DiscoveredLockfile[];
  readonly options: Required<DiscoveryOptions>;
  readonly root: string;
  limitReached: boolean;
  skipped: number;
}

interface BoundedReadResult {
  readonly bytes: Buffer;
  readonly exceeded: boolean;
}

interface DeclaredSubmodulePaths {
  readonly exceeded: boolean;
  readonly invalid: boolean;
  readonly paths: readonly string[];
}

interface SubmoduleManifestState {
  inSubmoduleSection: boolean;
  readonly paths: Set<string>;
  sectionHasPath: boolean;
}

const DEFAULT_OPTIONS: Required<DiscoveryOptions> = {
  excludePrefixes: [],
  maxFileBytes: 1_000_000,
  maxFiles: 10_000,
  maxTotalBytes: 100_000_000,
};
const MAX_CONFIGURED_FILE_BYTES = 100_000_000;

export async function discoverFiles(
  requestedTarget: string,
  options: DiscoveryOptions = {},
): Promise<DiscoveryResult> {
  const target = await realpath(path.resolve(requestedTarget));
  const targetStat = await lstat(target);
  const root = targetStat.isDirectory() ? target : path.dirname(target);
  const state: MutableDiscoveryState = {
    bytesCollected: 0,
    candidatesSeen: 0,
    diagnostics: [],
    files: [],
    hash: createHash("sha256"),
    lockfiles: [],
    limitReached: false,
    options: normalizeOptions(options),
    root,
    skipped: 0,
  };

  if (targetStat.isDirectory()) {
    await walkDirectory(target, state);
  } else if (targetStat.isFile()) {
    await collectFile(target, state);
  } else {
    throw new Error("Target must be a regular file or directory.");
  }
  await validateMaterializedSubmodules(state);

  state.files.sort((left, right) => compareCodeUnits(left.relativePath, right.relativePath));
  state.hash.update(SCAN_INPUT_HASH_DOMAIN);
  for (const file of state.files) {
    updateLengthPrefixed(state.hash, file.relativePath);
    updateLengthPrefixed(state.hash, file.text);
  }

  return {
    contentHash: state.hash.digest("hex"),
    diagnostics: state.diagnostics,
    files: state.files,
    lockfiles: state.lockfiles,
    root,
    skipped: state.skipped,
    target: targetDisplayName(target),
  };
}

function updateLengthPrefixed(hash: ReturnType<typeof createHash>, value: string): void {
  const bytes = Buffer.from(value, "utf8");
  const length = Buffer.alloc(8);
  length.writeBigUInt64BE(BigInt(bytes.length));
  hash.update(length).update(bytes);
}

function normalizeOptions(options: DiscoveryOptions): Required<DiscoveryOptions> {
  return {
    excludePrefixes: (options.excludePrefixes ?? []).map((value) =>
      normalizeRelativePath(value).replace(/\/$/, ""),
    ),
    maxFileBytes: boundedPositiveInteger(
      options.maxFileBytes ?? DEFAULT_OPTIONS.maxFileBytes,
      "maxFileBytes",
      MAX_CONFIGURED_FILE_BYTES,
    ),
    maxFiles: boundedPositiveInteger(
      options.maxFiles ?? DEFAULT_OPTIONS.maxFiles,
      "maxFiles",
      DEFAULT_OPTIONS.maxFiles,
    ),
    maxTotalBytes: boundedPositiveInteger(
      options.maxTotalBytes ?? DEFAULT_OPTIONS.maxTotalBytes,
      "maxTotalBytes",
      DEFAULT_OPTIONS.maxTotalBytes,
    ),
  };
}

function boundedPositiveInteger(value: number, name: string, maximum: number): number {
  if (!Number.isSafeInteger(value) || value < 1 || value > maximum) {
    throw new Error(
      `${name} must be a positive safe integer no greater than ${maximum.toString()}.`,
    );
  }
  return value;
}

export function targetDisplayName(target: string): string {
  return path.basename(target) || path.parse(target).root;
}

async function walkDirectory(directory: string, state: MutableDiscoveryState): Promise<void> {
  const entries = await readdir(directory, { withFileTypes: true });
  entries.sort((left, right) => compareCodeUnits(left.name, right.name));

  for (const entry of entries) {
    if (state.limitReached) {
      return;
    }
    await visitEntry(directory, entry, state);
  }
}

async function visitEntry(
  directory: string,
  entry: Dirent,
  state: MutableDiscoveryState,
): Promise<void> {
  const absolutePath = path.join(directory, entry.name);
  const relativePath = toRelativePath(state.root, absolutePath);
  if (isExcluded(relativePath, state.options.excludePrefixes)) {
    state.skipped += 1;
    return;
  }
  if (entry.isSymbolicLink()) {
    if (!reserveCandidate(relativePath, state)) {
      return;
    }
    state.skipped += 1;
    state.diagnostics.push({
      file: relativePath,
      message:
        "Skipped symbolic link; scans never follow links outside the target boundary, so scan evidence is incomplete.",
      type: "error",
    });
    return;
  }
  if (entry.isDirectory()) {
    if (IGNORED_DIRECTORIES.has(entry.name)) {
      state.skipped += 1;
      return;
    }
    await walkDirectory(absolutePath, state);
    return;
  }
  if (entry.isFile()) {
    await collectFile(absolutePath, state);
  }
}

async function collectFile(absolutePath: string, state: MutableDiscoveryState): Promise<void> {
  const relativePath = toRelativePath(state.root, absolutePath);
  if (!reserveCandidate(relativePath, state)) {
    return;
  }
  const kind = classifyFile(absolutePath);
  const isLockfile = LOCKFILE_FILENAMES.has(path.basename(absolutePath));
  if (kind === undefined && !isLockfile) {
    state.skipped += 1;
    return;
  }

  const fileStat = await lstat(absolutePath);
  if (fileStat.size > state.options.maxFileBytes) {
    if (isLockfile) {
      state.lockfiles.push({ path: relativePath, state: "size-limit" });
    }
    state.skipped += 1;
    state.diagnostics.push({
      file: relativePath,
      message: `Skipped scannable file larger than ${state.options.maxFileBytes.toString()} bytes; scan evidence is incomplete.`,
      type: "error",
    });
    return;
  }

  if (state.bytesCollected + fileStat.size > state.options.maxTotalBytes) {
    state.skipped += 1;
    state.limitReached = true;
    state.diagnostics.push({
      file: relativePath,
      message: `Aggregate scan input limit exceeded (${state.options.maxTotalBytes.toString()} bytes); scan evidence is incomplete.`,
      type: "error",
    });
    return;
  }

  const remainingBytes = state.options.maxTotalBytes - state.bytesCollected;
  const readLimit = Math.min(state.options.maxFileBytes, remainingBytes);
  const { bytes, exceeded } = await readBoundedRegularFile(absolutePath, fileStat, readLimit);
  if (exceeded) {
    recordReadLimitExceeded(relativePath, isLockfile, remainingBytes, state);
    return;
  }
  state.bytesCollected += bytes.byteLength;
  recordCollectedFile(absolutePath, relativePath, kind, isLockfile, bytes, state);
}

function recordCollectedFile(
  absolutePath: string,
  relativePath: string,
  kind: FileKind | undefined,
  isLockfile: boolean,
  bytes: Buffer,
  state: MutableDiscoveryState,
): void {
  let text: string | undefined;
  if (kind !== undefined || (isLockfile && bytes.byteLength <= MAX_GIT_LFS_POINTER_BYTES)) {
    try {
      text = utf8Decoder.decode(bytes);
    } catch {
      // Binary lockfiles remain valid provenance inputs; scannable text fails closed below.
    }
  }
  if (text !== undefined && isGitLfsPointer(text, bytes.byteLength)) {
    state.skipped += 1;
    state.diagnostics.push({
      file: relativePath,
      message:
        "Skipped unresolved Git LFS pointer; materialize the referenced file before scanning, because scan evidence is incomplete.",
      type: "error",
    });
    return;
  }
  if (isLockfile) {
    state.lockfiles.push({
      path: relativePath,
      sha256: createHash("sha256").update(bytes).digest("hex"),
      state: "hashed",
    });
  }
  if (kind === undefined) {
    state.skipped += 1;
    return;
  }
  if (text === undefined) {
    state.skipped += 1;
    state.diagnostics.push({
      file: relativePath,
      message: "Skipped non-UTF-8 scannable file; scan evidence is incomplete.",
      type: "error",
    });
    return;
  }
  state.files.push({ absolutePath, kind, relativePath, text });
}

async function validateMaterializedSubmodules(state: MutableDiscoveryState): Promise<void> {
  const manifests = state.files.filter(
    (file) => path.basename(file.absolutePath) === ".gitmodules",
  );
  let declarationsSeen = 0;
  for (const manifest of manifests) {
    const declared = declaredSubmodulePaths(
      manifest.text,
      state.options.maxFiles - declarationsSeen,
    );
    if (rejectInvalidSubmoduleManifest(state, manifest, declared)) {
      return;
    }
    declarationsSeen += declared.paths.length;
    for (const declaredPath of declared.paths) {
      await validateDeclaredSubmodulePath(state, manifest, declaredPath);
    }
  }
}

function rejectInvalidSubmoduleManifest(
  state: MutableDiscoveryState,
  manifest: ScannableFile,
  declared: DeclaredSubmodulePaths,
): boolean {
  if (declared.invalid) {
    recordSubmoduleError(
      state,
      manifest.relativePath,
      "Declared Git submodule path uses unsupported or invalid syntax; scan evidence is incomplete.",
    );
    return true;
  }
  if (declared.exceeded) {
    recordSubmoduleError(
      state,
      manifest.relativePath,
      `Declared submodule limit exceeded (${state.options.maxFiles.toString()} paths); scan evidence is incomplete.`,
    );
    return true;
  }
  return false;
}

async function validateDeclaredSubmodulePath(
  state: MutableDiscoveryState,
  manifest: ScannableFile,
  declaredPath: string,
): Promise<void> {
  if (!isSafeSubmodulePath(declaredPath)) {
    recordSubmoduleError(
      state,
      manifest.relativePath,
      "Declared Git submodule path is invalid or leaves the scan root; scan evidence is incomplete.",
    );
    return;
  }
  const manifestDirectory = path.posix.dirname(manifest.relativePath);
  const relativePath = normalizeRelativePath(path.posix.join(manifestDirectory, declaredPath));
  if (isExcluded(relativePath, state.options.excludePrefixes)) {
    return;
  }
  const absolutePath = path.resolve(state.root, ...relativePath.split("/"));
  if (!isWithinDirectory(state.root, absolutePath)) {
    recordSubmoduleError(
      state,
      manifest.relativePath,
      "Declared Git submodule path resolves outside the scan root; scan evidence is incomplete.",
    );
    return;
  }
  if (!(await isMaterializedSubmodule(absolutePath))) {
    recordSubmoduleError(
      state,
      relativePath,
      "Declared Git submodule is absent or unmaterialized; check it out before scanning, because scan evidence is incomplete.",
    );
  }
}

function recordSubmoduleError(state: MutableDiscoveryState, file: string, message: string): void {
  state.skipped += 1;
  state.diagnostics.push({ file, message, type: "error" });
}

function declaredSubmodulePaths(manifest: string, maximum: number): DeclaredSubmodulePaths {
  const state: SubmoduleManifestState = {
    inSubmoduleSection: false,
    paths: new Set(),
    sectionHasPath: false,
  };
  for (const line of manifest.split(/\r?\n/)) {
    const result = processSubmoduleManifestLine(line, state, maximum);
    if (result !== "continue") {
      return {
        exceeded: result === "exceeded",
        invalid: result === "invalid",
        paths: [...state.paths],
      };
    }
  }
  if (state.inSubmoduleSection && !state.sectionHasPath) {
    return { exceeded: false, invalid: true, paths: [...state.paths] };
  }
  return { exceeded: false, invalid: false, paths: [...state.paths] };
}

function processSubmoduleManifestLine(
  line: string,
  state: SubmoduleManifestState,
  maximum: number,
): "continue" | "exceeded" | "invalid" {
  const section = parseSubmoduleSection(line);
  if (section !== undefined) {
    if (section === "invalid" || (state.inSubmoduleSection && !state.sectionHasPath)) {
      return "invalid";
    }
    state.inSubmoduleSection = section === "submodule";
    state.sectionHasPath = false;
    return "continue";
  }
  if (!state.inSubmoduleSection) {
    return "continue";
  }
  const parsedPath = parseSubmodulePathLine(line);
  if (parsedPath === "other") {
    return "continue";
  }
  if (parsedPath === "invalid" || state.sectionHasPath || state.paths.has(parsedPath)) {
    return "invalid";
  }
  state.sectionHasPath = true;
  return retainDeclaredSubmodulePath(state.paths, parsedPath, maximum) ? "continue" : "exceeded";
}

function retainDeclaredSubmodulePath(paths: Set<string>, value: string, maximum: number): boolean {
  if (paths.has(value)) {
    return true;
  }
  if (paths.size >= maximum) {
    return false;
  }
  paths.add(value);
  return true;
}

function parseSubmoduleSection(line: string): "invalid" | "other" | "submodule" | undefined {
  const trimmed = line.trim();
  if (!trimmed.startsWith("[")) {
    return undefined;
  }
  if (/^\[submodule\s+"(?:[^"\\]|\\.)*"\]\s*(?:[;#].*)?$/i.test(trimmed)) {
    return "submodule";
  }
  return /^\[submodule\b/i.test(trimmed) ? "invalid" : "other";
}

function parseSubmodulePathLine(line: string): "invalid" | "other" | string {
  const match = line.match(/^\s*path\s*=\s*(.*?)\s*$/i);
  if (match?.[1] !== undefined) {
    const value = parseGitConfigValue(match[1]);
    return value === undefined || value.length === 0 ? "invalid" : value;
  }
  return /^\s*path(?:\s|=|$)/i.test(line) ? "invalid" : "other";
}

function parseGitConfigValue(raw: string): string | undefined {
  const value = raw.trim();
  if (!value.startsWith('"')) {
    return decodeGitConfigEscapes(value.replace(/\s[;#].*$/, "").trim());
  }
  let decoded = "";
  for (let index = 1; index < value.length; index += 1) {
    const character = value[index];
    if (character === '"') {
      return /^\s*(?:[;#].*)?$/.test(value.slice(index + 1)) ? decoded : undefined;
    }
    if (character !== "\\") {
      decoded += character;
      continue;
    }
    const escaped = value[index + 1];
    const replacement = escaped === undefined ? undefined : gitConfigEscape(escaped);
    if (replacement === undefined) {
      return undefined;
    }
    decoded += replacement;
    index += 1;
  }
  return undefined;
}

function decodeGitConfigEscapes(value: string): string | undefined {
  let decoded = "";
  for (let index = 0; index < value.length; index += 1) {
    const character = value[index];
    if (character !== "\\") {
      decoded += character;
      continue;
    }
    const escaped = value[index + 1];
    const replacement = escaped === undefined ? undefined : gitConfigEscape(escaped);
    if (replacement === undefined) {
      return undefined;
    }
    decoded += replacement;
    index += 1;
  }
  return decoded;
}

function gitConfigEscape(character: string): string | undefined {
  switch (character) {
    case "\\":
    case '"':
      return character;
    case "b":
      return "\b";
    case "n":
      return "\n";
    case "t":
      return "\t";
    default:
      return undefined;
  }
}

function isSafeSubmodulePath(value: string): boolean {
  return (
    value.length > 0 &&
    value === value.normalize("NFC") &&
    !value.includes("\\") &&
    !value.includes(":") &&
    !hasAsciiControl(value) &&
    !path.posix.isAbsolute(value) &&
    !path.win32.isAbsolute(value) &&
    !value.split("/").some((segment) => segment.length === 0 || segment === "." || segment === "..")
  );
}

function hasAsciiControl(value: string): boolean {
  return [...value].some((character) => {
    const codePoint = character.codePointAt(0) ?? 0;
    return codePoint <= 0x1f || codePoint === 0x7f;
  });
}

function isWithinDirectory(root: string, candidate: string): boolean {
  const relative = path.relative(root, candidate);
  return (
    relative !== "" &&
    relative !== ".." &&
    !relative.startsWith(`..${path.sep}`) &&
    !path.isAbsolute(relative)
  );
}

async function isMaterializedSubmodule(absolutePath: string): Promise<boolean> {
  try {
    const metadata = await lstat(absolutePath);
    if (!metadata.isDirectory()) {
      return false;
    }
    return (await readdir(absolutePath)).length > 0;
  } catch (error) {
    if (hasErrorCode(error, "ENOENT")) {
      return false;
    }
    throw error;
  }
}

function isGitLfsPointer(text: string, byteLength: number): boolean {
  if (byteLength > MAX_GIT_LFS_POINTER_BYTES) {
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

function hasErrorCode(error: unknown, code: string): boolean {
  return error instanceof Error && "code" in error && error.code === code;
}

function recordReadLimitExceeded(
  relativePath: string,
  isLockfile: boolean,
  remainingBytes: number,
  state: MutableDiscoveryState,
): void {
  const aggregateLimitReached = remainingBytes < state.options.maxFileBytes;
  if (isLockfile && !aggregateLimitReached) {
    state.lockfiles.push({ path: relativePath, state: "size-limit" });
  }
  state.skipped += 1;
  state.limitReached = aggregateLimitReached;
  state.diagnostics.push({
    file: relativePath,
    message: aggregateLimitReached
      ? `Aggregate scan input limit exceeded (${state.options.maxTotalBytes.toString()} bytes); scan evidence is incomplete.`
      : `Skipped scannable file larger than ${state.options.maxFileBytes.toString()} bytes; scan evidence is incomplete.`,
    type: "error",
  });
}

async function readBoundedRegularFile(
  absolutePath: string,
  expected: Stats,
  maximumBytes: number,
): Promise<BoundedReadResult> {
  const handle = await open(absolutePath, "r");
  try {
    const opened = await handle.stat();
    if (!opened.isFile() || !samePathAndOpenedFileSnapshot(expected, opened)) {
      throw new Error("A candidate file changed while it was being opened for scanning.");
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
      throw new Error("A candidate file changed while it was being scanned.");
    }
    return {
      bytes: Buffer.concat(chunks, total),
      exceeded: total > maximumBytes,
    };
  } finally {
    await handle.close();
  }
}

interface FileSnapshot {
  readonly ctimeMs: number;
  readonly dev: number;
  readonly ino: number;
  readonly mtimeMs: number;
  readonly size: number;
}

export function sameOpenedFileSnapshot(left: FileSnapshot, right: FileSnapshot): boolean {
  return left.dev === right.dev && left.ino === right.ino && sameFileMetadata(left, right);
}

export function samePathAndOpenedFileSnapshot(
  pathSnapshot: FileSnapshot,
  openedSnapshot: FileSnapshot,
  platform = process.platform,
): boolean {
  const sameDevice =
    pathSnapshot.dev === openedSnapshot.dev ||
    (platform === "win32" &&
      pathSnapshot.dev === 0 &&
      openedSnapshot.dev !== 0 &&
      pathSnapshot.ino !== 0);
  return (
    sameDevice &&
    pathSnapshot.ino === openedSnapshot.ino &&
    sameFileMetadata(pathSnapshot, openedSnapshot)
  );
}

function sameFileMetadata(left: FileSnapshot, right: FileSnapshot): boolean {
  return (
    left.size === right.size && left.mtimeMs === right.mtimeMs && left.ctimeMs === right.ctimeMs
  );
}

function reserveCandidate(relativePath: string, state: MutableDiscoveryState): boolean {
  if (state.candidatesSeen >= state.options.maxFiles) {
    state.skipped += 1;
    state.limitReached = true;
    state.diagnostics.push({
      file: relativePath,
      message: `Candidate file limit exceeded (${state.options.maxFiles.toString()} files); scan evidence is incomplete.`,
      type: "error",
    });
    return false;
  }
  state.candidatesSeen += 1;
  return true;
}

function classifyFile(filePath: string): FileKind | undefined {
  const basename = path.basename(filePath);
  const extension = path.extname(basename).toLowerCase();
  if (SOURCE_EXTENSIONS.has(extension)) {
    return "source";
  }
  if (extension === ".json") {
    return "json";
  }
  if (
    TEXT_EXTENSIONS.has(extension) ||
    TEXT_FILENAMES.has(basename) ||
    basename === ".env" ||
    basename.startsWith(".env.")
  ) {
    return "text";
  }
  return undefined;
}

function isExcluded(relativePath: string, prefixes: readonly string[]): boolean {
  return prefixes.some(
    (prefix) => relativePath === prefix || relativePath.startsWith(`${prefix}/`),
  );
}

function normalizeRelativePath(value: string): string {
  const platformPath = path.sep === "\\" ? value.replaceAll("\\", "/") : value;
  return platformPath.replace(/^\.\//, "");
}

function toRelativePath(root: string, absolutePath: string): string {
  return normalizeRelativePath(path.relative(root, absolutePath));
}
