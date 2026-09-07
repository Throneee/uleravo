import type { Stats } from "node:fs";
import { constants } from "node:fs";
import { lstat, open, realpath } from "node:fs/promises";
import path from "node:path";

export async function checkDirectory(directory: string): Promise<string> {
  const absolute = path.resolve(directory);
  const root = path.parse(absolute).root;
  const segments = absolute.slice(root.length).split(path.sep).filter(Boolean);
  if (segments.length > 256) throw new Error("unsafe");
  let current = root;
  for (const segment of ["", ...segments]) {
    current = path.join(current, segment);
    const stat = await lstat(current);
    if (stat.isSymbolicLink() || !stat.isDirectory()) throw new Error("unsafe");
  }
  const canonical = await realpath(absolute);
  const normalize = (p: string) => (process.platform === "win32" ? p.toLowerCase() : p);
  if (normalize(canonical) !== normalize(absolute)) throw new Error("unsafe");
  return canonical;
}

export async function readConfig(file: string): Promise<string> {
  await checkDirectory(path.dirname(file));
  const metadata = await lstat(file);
  if (metadata.isSymbolicLink() || !metadata.isFile()) throw new Error("unsafe");
  const limit = 256 * 1024;
  if (metadata.size > limit) throw new Error("too_large");
  const handle = await open(file, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  try {
    const opened = await handle.stat();
    if (!opened.isFile() || !sameFile(metadata, opened)) throw new Error("unstable");
    const buffer = Buffer.alloc(limit + 1);
    let total = 0;
    while (total < buffer.length) {
      const { bytesRead } = await handle.read(buffer, total, buffer.length - total, total);
      if (!bytesRead) break;
      total += bytesRead;
    }
    if (total > limit) throw new Error("too_large");
    if (total !== metadata.size || !sameFile(metadata, await handle.stat()))
      throw new Error("unstable");
    await checkDirectory(path.dirname(file));
    const after = await lstat(file);
    if (after.isSymbolicLink() || !after.isFile() || !sameFile(metadata, after))
      throw new Error("unstable");
    return new TextDecoder("utf-8", { fatal: true }).decode(buffer.subarray(0, total));
  } finally {
    await handle.close();
  }
}

function sameFile(a: Stats, b: Stats): boolean {
  return (
    a.ino !== 0 &&
    a.ino === b.ino &&
    a.dev === b.dev &&
    a.size === b.size &&
    a.mtimeMs === b.mtimeMs &&
    a.ctimeMs === b.ctimeMs
  );
}
