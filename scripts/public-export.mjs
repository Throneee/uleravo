import { createHash } from "node:crypto";
import { constants } from "node:fs";
import { lstat, mkdir, open, readdir, realpath } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

const scriptPath = fileURLToPath(import.meta.url);
const defaultRepositoryRoot = path.resolve(path.dirname(scriptPath), "..");
const MANIFEST_RELATIVE_PATH = "release/public-export.json";
const MAX_MANIFEST_BYTES = 1_000_000;
const MAX_PUBLIC_FILE_BYTES = 10_000_000;
const MAX_PUBLIC_FILES = 500;
const MAX_PUBLIC_TOTAL_BYTES = 100_000_000;
const MAX_BRANDING_POLICIES = 1_000;
const utf8Decoder = new TextDecoder("utf-8", { fatal: true });
const legacyBrand = ["mir", "sad"].join("");
const rejectedDraftBrands = [["lim", "intra"].join(""), ["jepo", "rano"].join("")];
const blockedBrandPattern = new RegExp([legacyBrand, ...rejectedDraftBrands].join("|"), "iu");
const approvedBrandingCompatibility = new Map([
  ["action/dist/index.cjs", new Set([`${legacyBrand}-scan-input-v1`])],
  [
    "schemas/comparison.schema.json",
    new Set([
      `https://${legacyBrand}.local/schemas/comparison-1.0.0.json`,
      `https://${legacyBrand}.local/schemas/report-1.0.0.json`,
    ]),
  ],
  [
    "schemas/report.schema.json",
    new Set([`https://${legacyBrand}.local/schemas/report-1.0.0.json`]),
  ],
  [
    "schemas/signed-report.schema.json",
    new Set([`https://${legacyBrand}.local/schemas/signed-report-envelope-1.0.0.json`]),
  ],
  ["src/scanner/files.ts", new Set([`${legacyBrand}-scan-input-v1`])],
  ["src/signatures.ts", new Set([`${legacyBrand}:signed-report:v1`])],
  ["test/signatures.test.ts", new Set([`${legacyBrand}:signed-report:v1`])],
]);

const privatePublicationPaths = new Set(
  [
    ".github/corpus-expectations.json",
    ".github/corpus-review.json",
    ".github/workflows/corpus-validation.yml",
    "AGENTS.md",
    "docs/corpus-methodology.md",
    "docs/product-direction.md",
    "docs/responsible-disclosure.md",
    "docs/roadmap.md",
    "scripts/check-corpus-report.mjs",
  ].map(aliasKey),
);
const privatePublicationPrefixes = [
  ".github/corpus-",
  ".github/workflows/corpus-",
  "disclosure/",
  "embargoed/",
  "private/",
  "research/",
  "scripts/check-corpus-",
].map(aliasKey);
const windowsDeviceNames = new Set([
  "AUX",
  "CON",
  "NUL",
  "PRN",
  ...Array.from({ length: 9 }, (_, index) => `COM${(index + 1).toString()}`),
  ...Array.from({ length: 9 }, (_, index) => `LPT${(index + 1).toString()}`),
]);

export async function checkPublicSurface(repositoryRoot = defaultRepositoryRoot) {
  const root = await canonicalDirectory(repositoryRoot, "repository root");
  const manifestEntry = await readRegularEntry(root, MANIFEST_RELATIVE_PATH, MAX_MANIFEST_BYTES);
  const manifest = parseManifest(utf8(manifestEntry.content, MANIFEST_RELATIVE_PATH));
  const entries = new Map();
  let totalBytes = 0;

  for (const relativePath of manifest.files) {
    const entry =
      relativePath === MANIFEST_RELATIVE_PATH
        ? manifestEntry
        : await readRegularEntry(root, relativePath, MAX_PUBLIC_FILE_BYTES);
    totalBytes += entry.content.length;
    if (totalBytes > MAX_PUBLIC_TOTAL_BYTES) {
      throw new Error("Public export exceeds its aggregate byte limit.");
    }
    entries.set(relativePath, entry);
    if (relativePath !== MANIFEST_RELATIVE_PATH) {
      const expectedDigest = manifest.reviewedSha256[relativePath];
      if (expectedDigest === undefined || sha256(entry.content) !== expectedDigest) {
        throw new Error(`${relativePath} does not match its release-reviewed SHA-256 digest.`);
      }
      checkBranding(
        relativePath,
        entry.content,
        manifest.brandingCompatibility[relativePath] ?? [],
      );
    }
  }

  return { entries, manifest, root };
}

export async function exportPublicSurface(destination, repositoryRoot = defaultRepositoryRoot) {
  const checked = await checkPublicSurface(repositoryRoot);
  const preparedDestination = await prepareDestination(checked.root, destination);

  for (const relativePath of checked.manifest.files) {
    await assertStableDirectory(
      preparedDestination.root,
      preparedDestination.identity,
      "Public export destination changed during export.",
    );
    const entry = checked.entries.get(relativePath);
    if (entry === undefined) {
      throw new Error(`Public export entry ${relativePath} disappeared after validation.`);
    }
    const parent = await materializeDestinationParent(preparedDestination, relativePath);
    await assertStableDirectory(
      parent.root,
      parent.identity,
      `Public export parent changed before writing ${relativePath}.`,
    );
    const destinationPath = path.join(parent.root, path.posix.basename(relativePath));
    const noFollow = constants.O_NOFOLLOW ?? 0;
    const handle = await open(
      destinationPath,
      constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | noFollow,
      entry.mode,
    );
    try {
      await handle.writeFile(entry.content);
      await handle.chmod(entry.mode);
    } finally {
      await handle.close();
    }
    await assertStableDirectory(
      parent.root,
      parent.identity,
      `Public export parent changed while writing ${relativePath}.`,
    );
    await assertStableDirectory(
      preparedDestination.root,
      preparedDestination.identity,
      "Public export destination changed during export.",
    );
  }

  await verifyExport(preparedDestination, checked.manifest);
  return { destination: preparedDestination.root, files: checked.manifest.files.length };
}

async function verifyExport(destination, manifest) {
  await assertStableDirectory(
    destination.root,
    destination.identity,
    "Public export destination changed before final verification.",
  );
  const exportedFiles = await collectRegularFiles(destination.root);
  if (!sameStringArray(exportedFiles, manifest.files)) {
    const missing = manifest.files.filter((entry) => !exportedFiles.includes(entry));
    const extra = exportedFiles.filter((entry) => !manifest.files.includes(entry));
    throw new Error(
      `Public export does not match the exact allowlist (missing: ${formatPaths(missing)}; extra: ${formatPaths(extra)}).`,
    );
  }
  await checkPublicSurface(destination.root);
  await assertStableDirectory(
    destination.root,
    destination.identity,
    "Public export destination changed during final verification.",
  );
}

function parseManifest(serialized) {
  let value;
  try {
    value = JSON.parse(serialized);
  } catch {
    throw new Error(`${MANIFEST_RELATIVE_PATH} is not valid JSON.`);
  }
  assertObject(value, MANIFEST_RELATIVE_PATH);
  if (serialized !== `${JSON.stringify(value, null, 2)}\n`) {
    throw new Error(
      `${MANIFEST_RELATIVE_PATH} must use canonical two-space JSON with no duplicate keys.`,
    );
  }
  assertExactKeys(
    value,
    ["brandingCompatibility", "files", "reviewedSha256", "schemaVersion"],
    MANIFEST_RELATIVE_PATH,
  );
  if (value.schemaVersion !== 1) {
    throw new Error(`${MANIFEST_RELATIVE_PATH} must use schemaVersion 1.`);
  }
  const files = parsePublicFiles(value.files);
  const reviewedSha256 = parseReviewedDigests(value.reviewedSha256, files);
  const brandingCompatibility = parseBrandingCompatibility(value.brandingCompatibility, files);

  return { brandingCompatibility, files, reviewedSha256, schemaVersion: 1 };
}

function parsePublicFiles(value) {
  if (!Array.isArray(value) || value.length === 0) {
    throw new Error(`${MANIFEST_RELATIVE_PATH} files must be a non-empty array.`);
  }
  if (value.length > MAX_PUBLIC_FILES) {
    throw new Error(`${MANIFEST_RELATIVE_PATH} exceeds its public-file count limit.`);
  }

  const files = value.map((entry, index) => {
    if (typeof entry !== "string") {
      throw new Error(`${MANIFEST_RELATIVE_PATH} files[${index.toString()}] must be a string.`);
    }
    validateRelativePath(entry, `files[${index.toString()}]`);
    assertNoBlockedBrand(entry, `${entry} contains blocked branding in a public file path.`);
    if (isPrivatePublicationPath(entry)) {
      throw new Error(`${entry} is private and cannot enter the public export allowlist.`);
    }
    return entry;
  });
  assertSortedUniquePaths(files, "files");
  if (!files.includes(MANIFEST_RELATIVE_PATH)) {
    throw new Error(`${MANIFEST_RELATIVE_PATH} must include itself in files.`);
  }
  return files;
}

function parseBrandingCompatibility(value, files) {
  assertObject(value, "brandingCompatibility");
  const compatibilityPaths = Object.keys(value);
  if (!sameStringArray(compatibilityPaths, [...compatibilityPaths].sort())) {
    throw new Error("brandingCompatibility paths must be sorted.");
  }
  const brandingCompatibility = {};
  let brandingPolicyCount = 0;
  for (const relativePath of compatibilityPaths) {
    validateRelativePath(relativePath, "brandingCompatibility path");
    assertNoBlockedBrand(
      relativePath,
      `${relativePath} contains blocked branding in a brandingCompatibility path.`,
    );
    if (!files.includes(relativePath)) {
      throw new Error(`${relativePath} has a branding exception but is not in files.`);
    }
    const policies = value[relativePath];
    if (!Array.isArray(policies) || policies.length === 0) {
      throw new Error(`${relativePath} brandingCompatibility must be a non-empty array.`);
    }
    brandingPolicyCount += policies.length;
    if (brandingPolicyCount > MAX_BRANDING_POLICIES) {
      throw new Error("brandingCompatibility exceeds its policy count limit.");
    }
    const literals = [];
    brandingCompatibility[relativePath] = policies.map((policy, index) => {
      const label = `${relativePath} brandingCompatibility[${index.toString()}]`;
      assertObject(policy, label);
      assertExactKeys(policy, ["literal", "occurrences", "reason"], label);
      if (
        typeof policy.literal !== "string" ||
        policy.literal.length === 0 ||
        !blockedBrandPattern.test(policy.literal)
      ) {
        throw new Error(
          `${label} literal must name the frozen or rejected compatibility identifier explicitly.`,
        );
      }
      if (!approvedBrandingCompatibility.get(relativePath)?.has(policy.literal)) {
        throw new Error(`${label} literal is not an approved frozen compatibility identifier.`);
      }
      if (!Number.isSafeInteger(policy.occurrences) || policy.occurrences < 1) {
        throw new Error(`${label} occurrences must be a positive integer.`);
      }
      if (typeof policy.reason !== "string" || policy.reason.trim().length < 12) {
        throw new Error(`${label} reason must explain the compatibility requirement.`);
      }
      assertNoBlockedBrand(policy.reason, `${label} reason cannot repeat blocked branding.`);
      literals.push(policy.literal);
      return {
        literal: policy.literal,
        occurrences: policy.occurrences,
        reason: policy.reason,
      };
    });
    if (
      !sameStringArray(literals, [...literals].sort()) ||
      new Set(literals).size !== literals.length
    ) {
      throw new Error(`${relativePath} brandingCompatibility literals must be sorted and unique.`);
    }
  }
  return brandingCompatibility;
}

function parseReviewedDigests(value, files) {
  assertObject(value, "reviewedSha256");
  const expectedPaths = files.filter((entry) => entry !== MANIFEST_RELATIVE_PATH);
  const digestPaths = Object.keys(value);
  if (!sameStringArray(digestPaths, expectedPaths)) {
    throw new Error(
      "reviewedSha256 must contain every allowlisted file except the manifest, in sorted order.",
    );
  }
  const reviewedSha256 = {};
  for (const relativePath of digestPaths) {
    const digest = value[relativePath];
    if (typeof digest !== "string" || !/^[0-9a-f]{64}$/u.test(digest)) {
      throw new Error(`${relativePath} reviewedSha256 must be a lowercase SHA-256 digest.`);
    }
    reviewedSha256[relativePath] = digest;
  }
  return reviewedSha256;
}

function checkBranding(relativePath, content, policies) {
  let inspected = utf8(content, relativePath);
  for (const policy of policies) {
    const occurrences = countOccurrences(inspected, policy.literal);
    if (occurrences !== policy.occurrences) {
      throw new Error(
        `${relativePath} must contain ${policy.occurrences.toString()} exact occurrence(s) of its frozen compatibility literal; found ${occurrences.toString()}.`,
      );
    }
    inspected = inspected.split(policy.literal).join("");
  }
  const stale = blockedBrandPattern.exec(inspected);
  if (stale !== null) {
    const line = inspected.slice(0, stale.index).split("\n").length;
    throw new Error(
      `${relativePath}:${line.toString()} contains blocked human-facing product branding.`,
    );
  }
}

function assertNoBlockedBrand(value, message) {
  if (blockedBrandPattern.test(value)) {
    throw new Error(message);
  }
}

async function readRegularEntry(root, relativePath, maximumBytes) {
  validateRelativePath(relativePath, "public file");
  const absolutePath = path.join(root, ...relativePath.split("/"));
  let current = root;
  let listedMetadata;
  for (const [index, segment] of relativePath.split("/").entries()) {
    current = path.join(current, segment);
    const metadata = await lstat(current).catch((error) => {
      if (hasErrorCode(error, "ENOENT")) {
        throw new Error(`Allowlisted public file is missing: ${relativePath}.`);
      }
      throw error;
    });
    if (metadata.isSymbolicLink()) {
      throw new Error(`Allowlisted public path cannot contain a symlink: ${relativePath}.`);
    }
    if (index < relativePath.split("/").length - 1 && !metadata.isDirectory()) {
      throw new Error(`Allowlisted public path has a non-directory ancestor: ${relativePath}.`);
    }
    listedMetadata = metadata;
  }
  if (listedMetadata === undefined || !listedMetadata.isFile()) {
    throw new Error(`Allowlisted public path is not a regular file: ${relativePath}.`);
  }
  if (listedMetadata.size > maximumBytes) {
    throw new Error(
      `Allowlisted public file exceeds its release-review size limit: ${relativePath}.`,
    );
  }

  const noFollow = constants.O_NOFOLLOW ?? 0;
  const handle = await open(absolutePath, constants.O_RDONLY | noFollow);
  try {
    const openedMetadata = await handle.stat();
    if (
      !openedMetadata.isFile() ||
      !samePathAndOpenedFileSnapshot(listedMetadata, openedMetadata)
    ) {
      throw new Error(`Allowlisted public file changed during validation: ${relativePath}.`);
    }
    const content = await readBounded(handle, maximumBytes, relativePath);
    const [closedSnapshot, pathSnapshot] = await Promise.all([handle.stat(), lstat(absolutePath)]);
    if (
      !closedSnapshot.isFile() ||
      !pathSnapshot.isFile() ||
      !sameOpenedFileSnapshot(openedMetadata, closedSnapshot) ||
      !samePathAndOpenedFileSnapshot(pathSnapshot, openedMetadata) ||
      content.length !== openedMetadata.size
    ) {
      throw new Error(`Allowlisted public file changed during validation: ${relativePath}.`);
    }
    return {
      content,
      mode: openedMetadata.mode & 0o777,
    };
  } finally {
    await handle.close();
  }
}

async function prepareDestination(repositoryRoot, requestedDestination) {
  if (typeof requestedDestination !== "string" || requestedDestination.length === 0) {
    throw new Error("--export requires a destination directory.");
  }
  const destination = path.resolve(requestedDestination);
  if (isWithin(repositoryRoot, destination) || aliasKey(repositoryRoot) === aliasKey(destination)) {
    throw new Error("Public export destination must be outside the private source repository.");
  }

  await assertDestinationMissing(destination);

  const parent = path.dirname(destination);
  await assertNoSymlinkComponents(parent);
  const [parentMetadata, canonicalParent] = await Promise.all([lstat(parent), realpath(parent)]);
  if (!parentMetadata.isDirectory() || parentMetadata.isSymbolicLink()) {
    throw new Error("Public export destination parent must be a regular directory.");
  }
  await mkdir(destination, { mode: 0o700 });
  const [parentAfterCreation, canonicalParentAfterCreation, canonicalDestination] =
    await Promise.all([lstat(parent), realpath(parent), realpath(destination)]);
  if (
    !sameDirectoryIdentity(parentMetadata, parentAfterCreation) ||
    aliasKey(canonicalParent) !== aliasKey(canonicalParentAfterCreation) ||
    aliasKey(path.dirname(canonicalDestination)) !== aliasKey(canonicalParent)
  ) {
    throw new Error("Public export destination parent changed during creation.");
  }
  if (
    isWithin(repositoryRoot, canonicalDestination) ||
    aliasKey(repositoryRoot) === aliasKey(canonicalDestination)
  ) {
    throw new Error("Public export destination resolved inside the private source repository.");
  }
  const destinationMetadata = await lstat(canonicalDestination);
  if (!destinationMetadata.isDirectory() || destinationMetadata.isSymbolicLink()) {
    throw new Error("Public export destination must remain a regular directory.");
  }
  return {
    identity: directoryIdentity(destinationMetadata),
    root: canonicalDestination,
  };
}

async function assertDestinationMissing(destination) {
  let metadata;
  try {
    metadata = await lstat(destination);
  } catch (error) {
    if (!hasErrorCode(error, "ENOENT")) {
      throw error;
    }
  }
  if (metadata === undefined) {
    return;
  }
  if (metadata.isSymbolicLink()) {
    throw new Error("Public export destination cannot be a symlink.");
  }
  throw new Error(
    "Public export destination must not already exist; existing paths are never reused.",
  );
}

async function materializeDestinationParent(destination, relativePath) {
  await assertStableDirectory(
    destination.root,
    destination.identity,
    "Public export destination changed while creating parent directories.",
  );
  let parent = destination.root;
  const segments = relativePath.split("/").slice(0, -1);
  for (const segment of segments) {
    const next = path.join(parent, segment);
    try {
      await mkdir(next, { mode: 0o700 });
    } catch (error) {
      if (!hasErrorCode(error, "EEXIST")) {
        throw error;
      }
    }
    const metadata = await lstat(next);
    if (metadata.isSymbolicLink() || !metadata.isDirectory()) {
      throw new Error(`Public export parent cannot contain a symlink or file: ${relativePath}.`);
    }
    const canonical = await realpath(next);
    if (!isWithin(destination.root, canonical)) {
      throw new Error(`Public export parent escaped its destination: ${relativePath}.`);
    }
    parent = canonical;
  }
  const metadata = await lstat(parent);
  if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
    throw new Error(`Public export parent is not a stable directory: ${relativePath}.`);
  }
  return { identity: directoryIdentity(metadata), root: parent };
}

async function collectRegularFiles(root) {
  const files = [];
  async function visit(directory, relativeDirectory) {
    const entries = await readdir(directory, { withFileTypes: true });
    for (const entry of entries) {
      const relativePath =
        relativeDirectory.length === 0 ? entry.name : `${relativeDirectory}/${entry.name}`;
      validateRelativePath(relativePath, "exported file");
      const absolutePath = path.join(directory, entry.name);
      const metadata = await lstat(absolutePath);
      if (metadata.isSymbolicLink()) {
        throw new Error(`Public export contains a symlink: ${relativePath}.`);
      }
      if (metadata.isDirectory()) {
        await visit(absolutePath, relativePath);
      } else if (metadata.isFile()) {
        files.push(relativePath);
      } else {
        throw new Error(`Public export contains a non-regular file: ${relativePath}.`);
      }
    }
  }
  await visit(root, "");
  return files.sort();
}

async function canonicalDirectory(candidate, label) {
  const metadata = await lstat(candidate);
  if (metadata.isSymbolicLink() || !metadata.isDirectory()) {
    throw new Error(`${label} must be a regular directory.`);
  }
  return realpath(candidate);
}

async function assertNoSymlinkComponents(candidate) {
  const absolute = path.resolve(candidate);
  const root = path.parse(absolute).root;
  const segments = path.relative(root, absolute).split(path.sep).filter(Boolean);
  let current = root;
  for (const segment of segments) {
    current = path.join(current, segment);
    const metadata = await lstat(current);
    if (metadata.isSymbolicLink()) {
      throw new Error("Public export destination cannot traverse a symlink.");
    }
  }
}

function validateRelativePath(value, label) {
  if (
    value.length === 0 ||
    value.length > 4_096 ||
    value !== value.normalize("NFC") ||
    value.includes("\\") ||
    value.includes(":") ||
    path.posix.isAbsolute(value) ||
    path.win32.isAbsolute(value) ||
    path.posix.normalize(value) !== value
  ) {
    throw new Error(`${label} is not a normalized portable relative path: ${value}.`);
  }
  for (const segment of value.split("/")) {
    const deviceBase = segment.split(".")[0]?.toUpperCase();
    if (
      segment.length === 0 ||
      segment === "." ||
      segment === ".." ||
      segment.endsWith(".") ||
      segment.endsWith(" ") ||
      (deviceBase !== undefined && windowsDeviceNames.has(deviceBase)) ||
      hasControlCharacter(segment)
    ) {
      throw new Error(`${label} contains an unsafe path segment: ${value}.`);
    }
  }
}

function assertSortedUniquePaths(paths, label) {
  if (!sameStringArray(paths, [...paths].sort())) {
    throw new Error(`${label} must be sorted.`);
  }
  const aliases = new Set();
  for (const entry of paths) {
    const key = aliasKey(entry);
    if (aliases.has(key)) {
      throw new Error(`${label} contains a duplicate or portable path alias: ${entry}.`);
    }
    aliases.add(key);
  }
}

function isPrivatePublicationPath(relativePath) {
  const key = aliasKey(relativePath);
  return (
    privatePublicationPaths.has(key) ||
    privatePublicationPrefixes.some((prefix) => key.startsWith(prefix))
  );
}

function isWithin(root, candidate) {
  const relative = path.relative(root, candidate);
  return (
    relative !== "" &&
    relative !== ".." &&
    !relative.startsWith(`..${path.sep}`) &&
    !path.isAbsolute(relative)
  );
}

function aliasKey(value) {
  return value.normalize("NFC").toLowerCase();
}

function hasControlCharacter(value) {
  return [...value].some((character) => {
    const codePoint = character.codePointAt(0) ?? 0;
    return codePoint <= 0x1f || codePoint === 0x7f;
  });
}

function countOccurrences(value, literal) {
  let count = 0;
  let offset = 0;
  while (true) {
    const index = value.indexOf(literal, offset);
    if (index === -1) {
      return count;
    }
    count += 1;
    offset = index + literal.length;
  }
}

async function readBounded(handle, maximumBytes, relativePath) {
  const chunks = [];
  let totalBytes = 0;
  while (totalBytes <= maximumBytes) {
    const remaining = maximumBytes + 1 - totalBytes;
    const buffer = Buffer.allocUnsafe(Math.min(64 * 1_024, remaining));
    const { bytesRead } = await handle.read(buffer, 0, buffer.length, totalBytes);
    if (bytesRead === 0) {
      return Buffer.concat(chunks, totalBytes);
    }
    chunks.push(buffer.subarray(0, bytesRead));
    totalBytes += bytesRead;
  }
  throw new Error(
    `Allowlisted public file exceeds its release-review size limit: ${relativePath}.`,
  );
}

export function sameOpenedFileSnapshot(left, right) {
  return left.dev === right.dev && left.ino === right.ino && sameFileMetadata(left, right);
}

export function samePathAndOpenedFileSnapshot(
  pathSnapshot,
  openedSnapshot,
  platform = process.platform,
) {
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

function sameFileMetadata(left, right) {
  return (
    left.size === right.size && left.mtimeMs === right.mtimeMs && left.ctimeMs === right.ctimeMs
  );
}

function directoryIdentity(metadata) {
  return { dev: metadata.dev, ino: metadata.ino };
}

function sameDirectoryIdentity(left, right) {
  return (
    left.isDirectory() &&
    right.isDirectory() &&
    !left.isSymbolicLink() &&
    !right.isSymbolicLink() &&
    left.dev === right.dev &&
    left.ino === right.ino
  );
}

async function assertStableDirectory(candidate, identity, message) {
  const metadata = await lstat(candidate);
  if (
    !metadata.isDirectory() ||
    metadata.isSymbolicLink() ||
    metadata.dev !== identity.dev ||
    metadata.ino !== identity.ino ||
    aliasKey(await realpath(candidate)) !== aliasKey(candidate)
  ) {
    throw new Error(message);
  }
}

function sha256(content) {
  return createHash("sha256").update(content).digest("hex");
}

function utf8(content, relativePath) {
  try {
    return utf8Decoder.decode(content);
  } catch {
    throw new Error(`Allowlisted public file is not valid UTF-8: ${relativePath}.`);
  }
}

function assertObject(value, label) {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error(`${label} must be an object.`);
  }
}

function assertExactKeys(value, expected, label) {
  const actual = Object.keys(value).sort();
  const sortedExpected = [...expected].sort();
  if (!sameStringArray(actual, sortedExpected)) {
    throw new Error(`${label} has unknown or missing fields.`);
  }
}

function sameStringArray(left, right) {
  return left.length === right.length && left.every((entry, index) => entry === right[index]);
}

function formatPaths(paths) {
  return paths.length === 0 ? "none" : paths.join(", ");
}

function hasErrorCode(error, code) {
  return typeof error === "object" && error !== null && "code" in error && error.code === code;
}

async function main(argv) {
  if (argv.length === 1 && argv[0] === "--check") {
    const checked = await checkPublicSurface();
    process.stdout.write(
      `Public export allowlist validated: ${checked.manifest.files.length.toString()} regular files.\n`,
    );
    return;
  }
  if (argv.length === 2 && argv[0] === "--export") {
    const result = await exportPublicSurface(argv[1]);
    process.stdout.write(
      `Public export created at ${result.destination} with ${result.files.toString()} files.\n`,
    );
    return;
  }
  throw new Error("Usage: node scripts/public-export.mjs --check | --export <new-directory>");
}

if (path.resolve(process.argv[1] ?? "") === scriptPath) {
  main(process.argv.slice(2)).catch((error) => {
    const message = error instanceof Error ? error.message : "Unexpected public export failure.";
    process.stderr.write(`public export: ${message.slice(0, 1_000)}\n`);
    process.exitCode = 1;
  });
}
