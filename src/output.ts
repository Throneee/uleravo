import { randomUUID } from "node:crypto";
import type { Stats } from "node:fs";
import { link, lstat, open, realpath, unlink } from "node:fs/promises";
import path from "node:path";
import { sameOpenedFileSnapshot } from "./scanner/files.js";

interface SafeDirectorySnapshot {
  readonly canonicalPath: string;
  readonly metadata: Stats;
}

export async function assertOutputOutsideRoot(
  destination: string,
  canonicalRoot: string,
): Promise<void> {
  const resolved = path.resolve(destination);
  const parent = await captureSafeOutputParent(path.dirname(resolved));
  const canonicalDestination = path.join(parent.canonicalPath, path.basename(resolved));
  if (isWithin(canonicalRoot, canonicalDestination)) {
    throw new Error("Snapshot output must be outside the artifact root.");
  }
}

export async function writeNewFileAtomically(destination: string, content: string): Promise<void> {
  const resolved = path.resolve(destination);
  const parentPath = path.dirname(resolved);
  const parentBefore = await captureSafeOutputParent(parentPath);
  await requireAbsent(resolved, "Refusing to overwrite an existing output path.");

  const temporary = path.join(
    parentBefore.canonicalPath,
    `.${path.basename(resolved)}.${process.pid.toString()}.${randomUUID()}.tmp`,
  );
  let temporaryCreated = false;
  try {
    const handle = await open(temporary, "wx", 0o600);
    temporaryCreated = true;
    try {
      await handle.writeFile(content, { encoding: "utf8" });
      await handle.sync();
    } finally {
      await handle.close();
    }

    const temporaryMetadata = await lstat(temporary);
    if (!temporaryMetadata.isFile() || temporaryMetadata.isSymbolicLink()) {
      throw new Error("Atomic output temporary path is not a regular file.");
    }
    const parentBeforePublish = await captureSafeOutputParent(parentPath);
    if (!sameSafeDirectory(parentBefore, parentBeforePublish)) {
      throw new Error("Output parent changed before the report could be published.");
    }
    await requireAbsent(resolved, "Refusing to overwrite an output path created concurrently.");

    await link(temporary, resolved);
    const [publishedTemporaryMetadata, destinationMetadata, parentAfterPublish] = await Promise.all(
      [lstat(temporary), lstat(resolved), captureSafeOutputParent(parentPath)],
    );
    if (
      !destinationMetadata.isFile() ||
      destinationMetadata.isSymbolicLink() ||
      !sameOpenedFileSnapshot(publishedTemporaryMetadata, destinationMetadata) ||
      !sameSafeDirectory(parentBefore, parentAfterPublish)
    ) {
      throw new Error("Output path changed while the report was being published.");
    }

    await unlink(temporary);
    temporaryCreated = false;
  } finally {
    if (temporaryCreated && (await safeParentStillMatches(parentPath, parentBefore))) {
      await unlink(temporary).catch(() => undefined);
    }
  }
}

async function captureSafeOutputParent(parentPath: string): Promise<SafeDirectorySnapshot> {
  const resolvedParent = path.resolve(parentPath);
  const before = await lstat(resolvedParent);
  if (!before.isDirectory() || before.isSymbolicLink()) {
    throw new Error("Output parent must be an existing regular directory without links.");
  }
  const canonicalPath = await realpath(resolvedParent);
  if (normalizedAbsolutePath(canonicalPath) !== normalizedAbsolutePath(resolvedParent)) {
    throw new Error("Output parent must not traverse a symbolic link or junction.");
  }
  const after = await lstat(resolvedParent);
  if (!after.isDirectory() || after.isSymbolicLink() || !sameOpenedFileSnapshot(before, after)) {
    throw new Error("Output parent changed while it was being validated.");
  }
  return { canonicalPath, metadata: after };
}

async function safeParentStillMatches(
  parentPath: string,
  expected: SafeDirectorySnapshot,
): Promise<boolean> {
  try {
    return sameSafeDirectory(expected, await captureSafeOutputParent(parentPath));
  } catch {
    return false;
  }
}

function sameSafeDirectory(left: SafeDirectorySnapshot, right: SafeDirectorySnapshot): boolean {
  return (
    normalizedAbsolutePath(left.canonicalPath) === normalizedAbsolutePath(right.canonicalPath) &&
    left.metadata.dev === right.metadata.dev &&
    left.metadata.ino === right.metadata.ino
  );
}

async function requireAbsent(destination: string, message: string): Promise<void> {
  try {
    await lstat(destination);
  } catch (error) {
    if (hasErrorCode(error, "ENOENT")) {
      return;
    }
    throw error;
  }
  throw new Error(message);
}

function isWithin(root: string, candidate: string): boolean {
  const relative = path.relative(normalizedAbsolutePath(root), normalizedAbsolutePath(candidate));
  return (
    relative.length === 0 ||
    (relative !== ".." && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative))
  );
}

function normalizedAbsolutePath(value: string): string {
  const resolved = path.resolve(value);
  return process.platform === "win32" ? resolved.toLocaleLowerCase("en-US") : resolved;
}

function hasErrorCode(error: unknown, code: string): boolean {
  return (
    typeof error === "object" &&
    error !== null &&
    "code" in error &&
    (error as { readonly code?: unknown }).code === code
  );
}
