import type { Stats } from "node:fs";
import { lstat, realpath } from "node:fs/promises";
import path from "node:path";
import { sameOpenedFileSnapshot } from "./scanner/files.js";

const MAX_DIRECTORY_COMPONENTS = 256;

export interface SafeDirectorySnapshot {
  readonly canonicalPath: string;
  readonly metadata: Stats;
}

interface DirectoryPathComponent {
  readonly metadata: Stats;
  readonly path: string;
}

/**
 * Checks ancestors from the filesystem root before a caller inspects the leaf.
 * This rejects stable linked prefixes; path-based checks cannot atomically prevent
 * another process from replacing a checked ancestor before the next operation.
 */
export async function hasNonLinkedDirectoryAncestors(requestedPath: string): Promise<boolean> {
  try {
    return (await captureDirectoryPath(path.dirname(path.resolve(requestedPath)))) !== undefined;
  } catch {
    return false;
  }
}

/**
 * Canonicalizes a stable directory while rejecting linked path components.
 * Windows DOS 8.3 aliases are accepted only after the lexical path and its
 * canonical spelling are shown to identify the same unchanged directory.
 */
export async function captureSafeDirectory(
  requestedDirectory: string,
): Promise<SafeDirectorySnapshot | undefined> {
  const resolved = path.resolve(requestedDirectory);
  if (process.platform !== "win32") {
    return captureExactDirectory(resolved);
  }

  try {
    const pathBefore = await captureDirectoryPath(resolved);
    if (pathBefore === undefined) return undefined;

    const canonicalBefore = await realpath(resolved);
    const canonicalMetadata = await lstat(canonicalBefore);
    if (!canonicalMetadata.isDirectory() || canonicalMetadata.isSymbolicLink()) return undefined;

    const canonicalAfter = await realpath(resolved);
    const pathAfter = await captureDirectoryPath(resolved);
    if (
      pathAfter === undefined ||
      normalizedAbsolutePath(canonicalBefore) !== normalizedAbsolutePath(canonicalAfter) ||
      !sameDirectoryPath(pathBefore, pathAfter)
    ) {
      return undefined;
    }

    const requestedMetadata = pathAfter.at(-1)?.metadata;
    if (
      requestedMetadata === undefined ||
      !sameOpenedFileSnapshot(requestedMetadata, canonicalMetadata)
    ) {
      return undefined;
    }
    return { canonicalPath: canonicalAfter, metadata: requestedMetadata };
  } catch {
    return undefined;
  }
}

async function captureExactDirectory(resolved: string): Promise<SafeDirectorySnapshot | undefined> {
  try {
    const before = await lstat(resolved);
    if (!before.isDirectory() || before.isSymbolicLink()) return undefined;
    const canonicalPath = await realpath(resolved);
    if (normalizedAbsolutePath(canonicalPath) !== normalizedAbsolutePath(resolved))
      return undefined;
    const after = await lstat(resolved);
    if (!after.isDirectory() || after.isSymbolicLink() || !sameOpenedFileSnapshot(before, after)) {
      return undefined;
    }
    return { canonicalPath, metadata: after };
  } catch {
    return undefined;
  }
}

async function captureDirectoryPath(
  resolved: string,
): Promise<readonly DirectoryPathComponent[] | undefined> {
  const root = path.parse(resolved).root;
  const suffix = resolved.slice(root.length);
  const segments = suffix.length === 0 ? [] : suffix.split(path.sep);
  if (segments.length + 1 > MAX_DIRECTORY_COMPONENTS) return undefined;

  const components: DirectoryPathComponent[] = [];
  let current = root;
  for (const segment of ["", ...segments]) {
    if (segment.length > 0) current = path.join(current, segment);
    const metadata = await lstat(current);
    if (!metadata.isDirectory() || metadata.isSymbolicLink()) return undefined;
    components.push({ metadata, path: current });
  }
  return components;
}

function sameDirectoryPath(
  left: readonly DirectoryPathComponent[],
  right: readonly DirectoryPathComponent[],
): boolean {
  if (left.length !== right.length || left.length === 0) return false;
  return left.every((component, index) => {
    const counterpart = right[index];
    if (
      counterpart === undefined ||
      normalizedAbsolutePath(component.path) !== normalizedAbsolutePath(counterpart.path)
    ) {
      return false;
    }
    const isRootDirectory = index === left.length - 1;
    return isRootDirectory
      ? sameOpenedFileSnapshot(component.metadata, counterpart.metadata)
      : sameDirectoryIdentity(component.metadata, counterpart.metadata);
  });
}

function sameDirectoryIdentity(left: Stats, right: Stats): boolean {
  return left.ino !== 0 && right.ino !== 0 && left.dev === right.dev && left.ino === right.ino;
}

function normalizedAbsolutePath(value: string): string {
  const resolved = path.resolve(value);
  return process.platform === "win32" ? resolved.toLocaleLowerCase("en-US") : resolved;
}
